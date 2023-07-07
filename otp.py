import base64
import sqlite3
import sys
import time
from math import floor
from os.path import join, dirname
from typing import List

import pyotp
import requests
from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad


def get_time_difference(server: str) -> float:
    if sys.version_info[:2] >= tuple(map(int, '3.11'.split('.'))):
        # not supported
        return 0

    t_before = time.time()
    response = requests.get(f'https://{server}/system-time', verify=False)
    response.raise_for_status()
    t_server = int(response.text)

    t_after = time.time()

    return floor(t_server - (t_after - t_before) / 2 - t_before)


def decode_secret(secret: bytes) -> str:
    key = b'arraynetworks920jSd8f*#9*d-#j0.H'
    iv = b'arraydevIVclick1'

    cipher = AES.new(key, AES.MODE_CBC, iv)
    secret = cipher.decrypt(secret)
    secret = unpad(secret, AES.block_size)
    return base64.b32encode(secret).decode().rstrip('=')


def read_servers() -> List[dict]:
    db_file = join(dirname(__file__), 'data', 'otp.db')
    db = sqlite3.connect(db_file)
    cursor = db.cursor()

    cursor.execute('SELECT * FROM servers')
    servers = cursor.fetchall()

    servers = [{
        'address': i[1],
        'secret': decode_secret(i[2]),
        'time_diff': get_time_difference(i[1]),
        'interval': int(i[4]),
    } for i in servers]

    db.close()
    return servers


def generate_otp(server: dict) -> str:
    totp = pyotp.TOTP(server['secret'], interval=server['interval'])
    return totp.at(floor(time.time() + server['time_diff']))


if __name__ == '__main__':
    for s in read_servers():
        print(s)
        print(generate_otp(s))
