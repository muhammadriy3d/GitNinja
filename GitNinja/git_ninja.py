import os
import sys
import json
from colorama import Fore, Style
import requests
import base64
from getpass import getpass
from Crypto.Cipher import AES
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad
import base64


class SITManager:
    def __init__(self):
        self.path = os.path.expanduser(os.path.join("~", ".sit"))
        self.pk_path = os.path.join(self.path, "sit_rsa.pem")
        self.pub_path = os.path.join(self.path, "sit_rsa.pub.pem")
        self.token_path = os.path.join(self.path, "encrypted_token.bin")
        self.token = None
        self.private_key = None
        self.public_key = None
        self.encrypted_aes_key = None
        self.nonce = None
        self.ciphertext = None
        self.tag = None

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
            isValid, auth, self.token = self.get_token()

            # Auth validation callback
            if isValid and auth.status_code == 200:
                self.user_choice_menu()
            else:
                print(
                    f"{Fore.RED}Error:{Fore.WHITE} Invalid token or the user does not exist!{Style.RESET_ALL}"
                )
                sys.exit()
            # self.load_keys()
            # self.decrypt_token()


    def generate_keys(self):
        print(f"{Fore.WHITE}Generating keys...{Style.RESET_ALL}")
        # Generate RSA key pair
        rsa_key = RSA.generate(2048)
        self.private_key = rsa_key.export_key("PEM")
        self.public_key = rsa_key.publickey().export_key("PEM")

    def encrypt_token(self):
        try:
            print(f"{Fore.WHITE}Encrypting token...{Style.RESET_ALL}")
            # Generate AES key and nonce for AES-GCM mode
            aes_key = get_random_bytes(32)  # 256-bit key
            self.nonce = get_random_bytes(12)  # 96-bit nonce

            # Encrypt token using AES-GCM
            cipher_aes = AES.new(aes_key, AES.MODE_GCM, nonce=self.nonce)
            self.ciphertext, self.tag = cipher_aes.encrypt_and_digest(pad(self.token.encode(), AES.block_size))

            # Encrypt AES key using RSA public key
            rsa_public_key = RSA.import_key(self.public_key)
            cipher_rsa = PKCS1_OAEP.new(rsa_public_key)
            self.encrypted_aes_key = cipher_rsa.encrypt(aes_key)
        except Exception as e:
            print(
                f"{Fore.RED}Error: {Fore.WHITE} {str(e)}! {Style.RESET_ALL}\n Please pull request the bug to the GitNinja repo with code: 500."
            )
            sys.exit()

    def decrypt_token(self):
        try:
            rsa_private_key = RSA.import_key(self.private_key)
            cipher_rsa = PKCS1_OAEP.new(rsa_private_key)
            decrypted_aes_key = cipher_rsa.decrypt(self.encrypted_aes_key)

            cipher_aes = AES.new(decrypted_aes_key, AES.MODE_GCM, nonce=self.nonce)

            # Decrypt and verify the data
            decrypted_token_bytes = cipher_aes.decrypt_and_verify(self.ciphertext, self.tag)

            # Decode the decrypted data
            decrypted_token_hex = decrypted_token_bytes.hex()  # Convert bytes to hexadecimal
            print(f"Decrypted Token (Hex): {decrypted_token_hex}")
            print(f"Decrypted Token (UTF-8): {decrypted_token_bytes.decode('utf-8', errors='replace')}")
        except Exception as e:
            print(f"{Fore.RED}{str(e)}\n Error: {Style.RESET_ALL} Decrypting done unsuccessfully!")
            sys.exit()
            
    def save_keys(self):
        try:
            if not os.path.exists(self.path):
                os.makedirs(self.path)

            with open(self.pk_path, "wb") as f:
                f.write(self.private_key)

            with open(self.pub_path, "wb") as f:
                f.write(self.public_key)

            self.save_encrypted_token()
        except Exception as e:
            print(
                f"{Fore.RED}Error: {Fore.WHITE}{str(e)}{Style.RESET_ALL} \n Creating the 'token', please try again! or pull request this bug to GitNinja repo{Style.RESET_ALL}"
            )
            sys.exit()

    def load_keys(self):
        try:
            with open(self.pk_path, "rb") as f:
                self.private_key = f.read()

            with open(self.pub_path, "rb") as f:
                self.public_key = f.read()

            with open(self.token_path, "rb") as f:
                content = f.read()
                self.encrypted_aes_key, self.nonce, self.ciphertext = content.split(b"\n", 2)
                self.encrypted_aes_key = base64.b64decode(self.encrypted_aes_key)
                self.nonce = base64.b64decode(self.nonce)
                self.ciphertext = base64.b64decode(self.ciphertext)
        except Exception as e:
            print(f"{Fore.RED}{str(e)}\n Error: {Style.RESET_ALL} Failed to load keys or encrypted token!")
            sys.exit()

    def save_encrypted_token(self):
        try:
            with open(self.token_path, "wb") as f:
                f.write(base64.b64encode(self.encrypted_aes_key))
                f.write(b"\n")
                f.write(base64.b64encode(self.nonce))
                f.write(b"\n")
                f.write(base64.b64encode(self.ciphertext))
                f.write(b"\n")
                f.write(base64.b64encode(self.tag))  # Store the tag alongside other parameters
        except Exception as e:
            print(
                f"{Fore.RED}Error: {Fore.WHITE}{str(e)}{Style.RESET_ALL} \n Saving the encrypted token failed! Please try again."
            )
            sys.exit()

    def load_encrypted_token(self):
        try:
            with open(self.token_path, "rb") as f:
                lines = f.read().split(b"\n")
                self.encrypted_aes_key = base64.b64decode(lines[0])
                self.nonce = base64.b64decode(lines[1])
                self.ciphertext = base64.b64decode(lines[2])
                self.tag = base64.b64decode(lines[3])  # Load the tag along with other parameters
        except Exception as e:
            print(
                f"{Fore.RED}Error: {Fore.WHITE}{str(e)}{Style.RESET_ALL} \n Loading the encrypted token failed! Please try again."
            )
            sys.exit()

    def fetch_user_data(self):
        username = self.get_info()
        if username is not None:
            print(f"Fetching data for user: {username}")
            # Your code to fetch and display user data goes here
            # Example: self.fetch_and_display_data(username)

    def create_repository(self):
        repo_name = input("Enter the name of the repository: ")
        # Your code to create the repository goes here
        # Example: self.create_new_repository(repo_name)

    def get_token(self):
        count = 0
        isValid = False
        auth = None  # Initialize auth to None outside the loop
        while count <= 2:
            token = getpass("Your personal access token >> ")  # Get user-provided token
            if token is not None:
                isValid, auth = self.auth_validation(token)
                if isValid and auth.status_code == 200:
                    return isValid, auth, token
                else:
                    isValid = False
                    auth = None
                    token = None

            print("Please try again!")

            if count >= 2:
                print("Error: 3 incorrect token attempts")
                break

            count += 1

        return isValid, auth, token

    

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

    def user_choice_menu(self):
        while True:
            print("Choose an option:")
            print("1. Fetch user data")
            print("2. Create a repository")
            print("3. Decrypt and show token")
            print("4. Exit")

            choice = input("Enter your choice (1/2/3/4): ")
            if choice == "1":
                self.fetch_user_data()
            elif choice == "2":
                self.create_repository()
            elif choice == "3":
                self.decrypt_and_show_token()
            elif choice == "4":
                print("Exiting.")
                sys.exit()
            else:
                print("Invalid choice. Please try again.")


if __name__ == "__main__":
    sit_manager = SITManager()
    sit_manager.run()
