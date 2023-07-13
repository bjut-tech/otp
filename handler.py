# Alibaba Cloud FC handler

from __future__ import annotations

import json
import os
import time
from http import HTTPStatus
from math import floor
from os.path import dirname, join
from typing import TYPE_CHECKING, Optional, Dict
from urllib.parse import parse_qsl

import jwt
import pyotp
import requests

if TYPE_CHECKING:
    from wsgiref.types import WSGIEnvironment, StartResponse


class Database:
    data: Optional[Dict[str, str]] = None

    def __init__(self):
        default_path = join(dirname(__file__), 'data', 'secrets.json')
        self.path = os.environ.get('DB_PATH', default_path)

    def __getitem__(self, item):
        if self.data is None:
            if not os.path.exists(self.path):
                self.data = {}
            else:
                with open(self.path, encoding='utf-8') as f:
                    try:
                        self.data = json.load(f)
                    except json.JSONDecodeError:
                        self.data = {}

        return self.data.get(item)


class HTTPException(Exception):

    def __init__(self, status: HTTPStatus, message: Optional[str] = None):
        super().__init__(message)

        self.status = status
        self.message = message


class HTTPHandler:

    def __init__(self, environ: WSGIEnvironment, start_response: StartResponse):
        self.database = Database()
        self.environ = environ
        self._start_response = start_response
        self.response_headers = [
            ('Access-Control-Allow-Origin', '*'),
            ('Access-Control-Allow-Methods', '*'),
            ('Access-Control-Allow-Headers', '*'),
            ('Access-Control-Max-Age', '86400')
        ]

    def handle(self) -> list:
        try:
            if self.environ['REQUEST_METHOD'] == 'GET':
                return self.handle_get()

            if self.environ['REQUEST_METHOD'] == 'POST':
                return self.handle_post()

            if self.environ['REQUEST_METHOD'] == 'OPTIONS':
                return self.handle_options()

            raise HTTPException(HTTPStatus.METHOD_NOT_ALLOWED)

        except HTTPException as e:
            self.start_response(e.status, [
                ('Content-Type', 'text/plain')
            ])

            if e.message is None:
                return [e.status.description.encode('utf-8')]

            return [e.message.encode('utf-8')]

    def handle_get(self) -> list:
        query = self._get_query()
        token = self._get_token()

        username = query.get('username')

        if username is None:
            raise HTTPException(HTTPStatus.BAD_REQUEST)

        if self.database[username] is None:
            raise HTTPException(HTTPStatus.NOT_FOUND)

        if token is None or not self.verify_token(username, token):
            raise HTTPException(HTTPStatus.UNAUTHORIZED)

        response = self.generate_response(username)
        del response['token']

        self.start_response(HTTPStatus.OK, [
            ('Content-Type', 'application/json')
        ])

        return [json.dumps(response).encode('utf-8')]

    def handle_post(self) -> list:
        query = self._get_query()
        body = self._parse_body()

        username = body.get('username', query.get('username'))
        password = body.get('password')

        if username is None or password is None:
            raise HTTPException(HTTPStatus.BAD_REQUEST)

        if self.database[username] is None:
            raise HTTPException(HTTPStatus.NOT_FOUND)

        response = requests.post('https://cas.bjut.edu.cn/v1/users', data={
            'username': username,
            'password': password
        }, headers={
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64)',
            'X-Forwarded-For': '127.0.0.1'
        }, verify=False)

        if response.status_code == 200:
            self.start_response(HTTPStatus.OK, [
                ('Content-Type', 'application/json')
            ])

            return [json.dumps(self.generate_response(username)).encode('utf-8')]

        if response.status_code == 401:
            raise HTTPException(HTTPStatus.UNAUTHORIZED)

        print('cas returned: ', response.status_code, response.text)
        raise HTTPException(HTTPStatus.INTERNAL_SERVER_ERROR)

    def handle_options(self) -> list:
        self.start_response(HTTPStatus.NO_CONTENT, [
            ('Allow', 'GET, POST, OPTIONS')
        ])

        return []

    def verify_token(self, username: str, token: str) -> bool:
        try:
            decoded_payload = jwt.decode(token, self.database[username], algorithms='HS256')
            if decoded_payload['username'] == username:
                return True
        except jwt.exceptions.DecodeError:
            pass

        return False

    def generate_response(self, username: str) -> dict:
        token = jwt.encode({
            'username': username
        }, self.database[username], algorithm='HS256')

        current_time = floor(time.time())
        interval = 60
        token_time = floor(current_time / interval) * interval
        remaining_time = interval - (current_time - token_time)

        totp = pyotp.TOTP(self.database[username], interval=interval)
        code = totp.at(current_time)

        return {
            'token': token,
            'code': code,
            'remaining_time': remaining_time
        }

    def start_response(self, status: HTTPStatus, headers: Optional[list] = None):
        if headers is None:
            headers = []

        for k, v in self.response_headers:
            for i, (k2, v2) in enumerate(headers):
                if k2.lower() == k.lower():
                    headers[i] = (k, v)
                    break
            else:
                headers.append((k, v))

        return self._start_response(f'{status.value} {status.phrase}', headers)

    def _get_query(self) -> dict:
        return dict(parse_qsl(self.environ['QUERY_STRING']))

    def _get_token(self) -> Optional[str]:
        authorization = self.environ.get('HTTP_AUTHORIZATION')

        if authorization and authorization.startswith('Bearer '):
            return authorization[7:]

        return authorization

    def _get_body(self) -> bytes:
        length = int(self.environ.get('CONTENT_LENGTH', '0'))
        return self.environ['wsgi.input'].read(length)

    def _parse_body(self) -> dict:
        body = self._get_body().decode('utf-8')

        if self.environ['CONTENT_TYPE'] == 'application/json':
            return json.loads(body)
        elif self.environ['CONTENT_TYPE'] == 'application/x-www-form-urlencoded':
            return dict(parse_qsl(body))
        else:
            raise HTTPException(HTTPStatus.UNSUPPORTED_MEDIA_TYPE)


def handler(environ: WSGIEnvironment, start_response: StartResponse) -> list:
    return HTTPHandler(environ, start_response).handle()
