import os
import sys
import json
from colorama import Fore, Style
import requests
import base64
from getpass import getpass
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad


class SITManager:
    def __init__(self):
        self.path = os.path.expanduser(os.path.join("~", ".sit"))
        self.pk_path = os.path.join(self.path, "sit_rsa.pem")
        self.pub_path = os.path.join(self.path, "sit_rsa.pub.pem")
        self.token = None
        self.private_key = None
        self.public_key = None
        self.encrypted_aes_key = None
        self.ciphertext = None

    def run(self):
        if not os.path.exists(self.path) or not (os.path.exists(self.pk_path) and os.path.exists(self.pub_path)):
            # Validate the user
            isValid, auth, self.token = self.get_token()

            # Auth validation callback
            if isValid and auth.status_code == 200:
                self.generate_keys()
                self.encrypt_token()
                self.save_keys()
            else:
                print(
                    f"{Fore.RED}Error:{Fore.WHITE} Invalid token or the user does not exist!{Style.RESET_ALL}"
                )
                sys.exit()
        else:
            self.load_keys()
            self.decrypt_token()

    def generate_keys(self):
        print(f"{Fore.WHITE}Generating keys...{Style.RESET_ALL}")
        # Generate RSA key pair
        rsa_key = RSA.generate(2048)
        self.private_key = rsa_key.export_key("PEM")
        self.public_key = rsa_key.publickey().export_key("PEM")

        # Generate AES key
        aes_key = get_random_bytes(32)  # 256-bit key
        cipher_aes = AES.new(aes_key, AES.MODE_CBC)
        self.encrypted_aes_key = self.encrypt_with_rsa_public_key(aes_key)
        self.ciphertext = cipher_aes.encrypt(pad(self.token.encode(), AES.block_size))

    def encrypt_token(self):
        try:
            print(f"{Fore.WHITE}Encrypting token...{Style.RESET_ALL}")
            decrypted_aes_key = self.decrypt_with_rsa_private_key(self.encrypted_aes_key)
            cipher_aes = AES.new(decrypted_aes_key, AES.MODE_CBC)
            self.ciphertext = cipher_aes.encrypt(pad(self.token.encode(), AES.block_size))
        except Exception as e:
            print(
                f"{Fore.RED}Error: {Fore.WHITE} {str(e)}! {Style.RESET_ALL}\n Please pull request the bug to the GitNinja repo with code: 500."
            )
            sys.exit()

    def save_keys(self):
        try:
            if not os.path.exists(self.path):
                os.makedirs(self.path)

            with open(self.pk_path, "wb") as f:
                username = self.get_info()
                if username is not None:
                    f.write(
                        self.private_key +
                        b"\n -" +
                        self.encrypted_aes_key +
                        b"\n -" +
                        self.ciphertext
                    )
                    print(
                        f'{Fore.GREEN}Token on "{self.pk_path}" created successfully! for {username}{Style.RESET_ALL}'
                    )

            with open(self.pub_path, "wb") as f:
                username = self.get_info()
                if username is not None:
                    f.write(self.public_key)
                    print(f'{Fore.GREEN}Token on "{self.pub_path}" created successfully!')
        except Exception as e:
            print(
                f"{Fore.RED}Error: {Fore.WHITE}{str(e)}{Style.RESET_ALL} \n Creating the 'token', please try again! or pull request this bug to GitNinja repo{Style.RESET_ALL}"
            )
            sys.exit()

    def load_keys(self):
        try:
            with open(self.pk_path, "rb") as f:
                content = f.read()
                split_content = content.split(b"\n -")
                self.private_key = b"".join(split_content[0:-2]).strip()
                self.encrypted_aes_key = split_content[-2].strip()
                self.ciphertext = split_content[-1].strip()
        except Exception as e:
            print(f"{Fore.RED}{str(e)}\n Error: {Style.RESET_ALL} Failed to load private key!")
            sys.exit()

    def decrypt_token(self):
        try:
            decrypted_aes_key = self.decrypt_with_rsa_private_key(self.encrypted_aes_key)
            cipher_aes = AES.new(decrypted_aes_key, AES.MODE_CBC)
            decrypted_token = unpad(cipher_aes.decrypt(self.ciphertext), AES.block_size).decode()
            print(f"Decrypted Token: {decrypted_token}")
        except Exception as e:
            print(f"{Fore.RED}{str(e)}\n Error: {Style.RESET_ALL} Decrypting done unsuccessfully!")
            sys.exit()

    def get_token(self):
        count = 0
        while count <= 2:
            token = getpass("Your personal access token >> ")

            if token is not None:
                isValid, auth = self.auth_validation(token)
            else:
                print("Please try again!")

            if isValid and auth.status_code == 200:
                return isValid, auth, token
            else:
                isValid = False
                auth = None
                token = None

                if count >= 2:
                    print("Error: 3 incorrect token attempts")
                    return isValid, auth, token

            assert count <= 2
            count += 1

    def get_info(self):
        headers = {"Authorization": f"token {self.token}"}
        url = "https://api.github.com/user"

        response = requests.get(url, headers=headers)

        if response.status_code == 200:
            user_data = response.json()
            username = user_data["login"]
            return username
        else:
            print("Failed to retrieve username. Status code:", response.status_code)

    def encrypt_with_rsa_public_key(self, data):
        public_key = RSA.import_key(self.public_key)
        cipher_rsa = PKCS1_OAEP.new(public_key)
        encrypted_data = cipher_rsa.encrypt(data)
        return encrypted_data

    def decrypt_with_rsa_private_key(self, data):
        private_key = RSA.import_key(self.private_key)
        cipher_rsa = PKCS1_OAEP.new(private_key)
        decrypted_data = cipher_rsa.decrypt(data)
        return decrypted_data

    def auth_validation(self, token):
        headers = {
            "Authorization": f"token {token}",
            "Accept": "application/vnd.github.v3+json",
        }

        response = requests.get("https://api.github.com/user", headers=headers)

        if response.status_code == 200:
            return True, response
        else:
            return False, response


if __name__ == "__main__":
    sit_manager = SITManager()
    sit_manager.run()
