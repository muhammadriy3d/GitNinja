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
from dotenv import load_dotenv

load_dotenv()


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
                self.run()
            else:
                print(
                    f"{Fore.RED}Error:{Fore.WHITE} Invalid token or the user does not exist!{Style.RESET_ALL}"
                )
                sys.exit()
        else:
            isValid, auth, self.token = self.get_token()

            # Auth validation callback
            if isValid and auth.status_code == 200:
                self.load_keys()
                # self.decrypt_token()
                self.user_choice_menu()
            else:
                print(
                    f"{Fore.RED}Error:{Fore.WHITE} Invalid token or the user does not exist!{Style.RESET_ALL}"
                )
                sys.exit()

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
            self.ciphertext, self.tag = cipher_aes.encrypt_and_digest(
                pad(self.token.encode(), AES.block_size))

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

            cipher_aes = AES.new(
                decrypted_aes_key, AES.MODE_GCM, nonce=self.nonce)

            # Decrypt and verify the data
            decrypted_token_bytes = cipher_aes.decrypt_and_verify(
                self.ciphertext, self.tag)

            # Decode the decrypted data
            decrypted_token_hex = decrypted_token_bytes.hex()  # Convert bytes to hexadecimal
            print(f"Decrypted Token (Hex): {decrypted_token_hex}")
            # print(
            # f"Decrypted Token (UTF-8): {decrypted_token_bytes.decode('utf-8', errors='replace')}")
            return decrypted_token_bytes.decode("utf-8", errors="replace")
        except Exception as e:
            print(
                f"{Fore.RED}{str(e)}\n Error: {Style.RESET_ALL} Decrypting done unsuccessfully!")
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
                content = f.read().split(b"\n")
                self.encrypted_aes_key = base64.b64decode(content[0])
                self.nonce = base64.b64decode(content[1])
                self.ciphertext = base64.b64decode(content[2])
                # Load the tag along with other parameters
                self.tag = base64.b64decode(content[3])
        except Exception as e:
            print(
                f"{Fore.RED}{str(e)}\n Error: {Style.RESET_ALL} Failed to load keys or encrypted token!")
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
                # Store the tag alongside other parameters
                f.write(base64.b64encode(self.tag))
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
                # Load the tag along with other parameters
                self.tag = base64.b64decode(lines[3])
        except Exception as e:
            print(
                f"{Fore.RED}Error: {Fore.WHITE}{str(e)}{Style.RESET_ALL} \n Loading the encrypted token failed! Please try again."
            )
            sys.exit()

    def fetch_user_data(self):
        username = self.get_info()
        if username is not None:
            print(f"{username}")
            # Your code to fetch and display user data goes here
            # Example: self.fetch_and_display_data(username)

    def create_repository(self):
        repo_name = input("Enter the name of the repository: ")
        repo_description = input("Enter a description for the repository: ")
        # Your code to create the repository goes here
        self.create_new_repository(repo_name, repo_description)

    def create_new_repository(self, repo_name, repo_description):
        if (self.token is None):
            self.token = self.decrypt_token().strip("\x08")
        owner = "muhammadriy3d"
        url = f"https://api.github.com/user/repos"
        private = input("Is this repo private? (True | False): ")
        headers = {
            "Authorization": f"token {self.token}",
            "Accept": "application/vnd.github+json",
            'X-GitHub-Api-Version': '2022-11-28'
        }
        data = {
            "name": repo_name,
            "homepage": "https://github.com",
            "description": repo_description,
            "private": private,
            "is_template": False,
        }

        response = requests.post(url, headers=headers, json=data)

        # Handle response
        if response.status_code == 201 or response.status_code == 200:
            print(f"Repository '{repo_name}' created successfully!")
            print(
                """
                Quick setup — if you’ve done this kind of thing before

                Get started by creating a new file or uploading an existing file. We recommend every repository include a README, LICENSE, and .gitignore.
                …or create a new repository on the command line

                echo "# test-git-ninja" >> README.md
                git init
                git add README.md
                git commit -m "first commit"
                git branch -M main
                git remote add origin https://github.com/muhammadriy3d/test-git-ninja.git
                git push -u origin main

                …or push an existing repository from the command line

                git remote add origin https://github.com/muhammadriy3d/test-git-ninja.git
                git branch -M main
                git push -u origin main
            """)
        else:
            print(f"Error: {response.status_code} - {response.json()}")

    def get_token(self):
        count = 0
        isValid = False
        auth = None  # Initialize auth to None outside the loop
        if not os.path.exists(self.path) or not (os.path.exists(self.pk_path) and os.path.exists(self.pub_path)):
            while count <= 2:
                # Get user-provided token
                print("Login:")
                token = getpass("GitNinja: Your personal access token >> ")
                self.token = token
                isValid, auth = self.validate_user(self.token)

                if (isValid and auth.status_code == 200):
                    return isValid, auth, token

                print("Please try again!")

                if count >= 2:
                    print("Error: 3 incorrect token attempts")
                    break

                count += 1
        else:
            self.load_keys()
            self.token = self.decrypt_token().strip("\x08")
            isValid, auth = self.validate_user(self.token)

        return isValid, auth, self.token

    def validate_user(self, token):
        if token is not None:
            isValid, auth = self.auth_validation(token)
            if isValid and auth.status_code == 200:
                return isValid, auth
            else:
                isValid = False
                auth = None
                token = None
        return isValid, auth

    def get_info(self):
        headers = {"Authorization": f"token {self.token}"}
        url = "https://api.github.com/user"

        response = requests.get(url, headers=headers)

        if response.status_code == 200:
            user_data = response.json()
            username = user_data["login"]
            return username
        else:
            print("Failed to retrieve username. Status code:",
                  response.status_code)

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

        response = requests.get(
            "https://api.github.com/user", headers=headers)

        if response.status_code == 200:
            return True, response
        else:
            return False, response

    def user_choice_menu(self):
        username = self.get_info()
        print(f"""
        GitNinja version 0.0.1
        Welcome {username} to your lab!
        please type 'help' for help.
        Press Ctrl+C to exit.
        """)
        while 1:
            # print(f"")
            # print("fetch Fetch user data")
            # print("fetch Create a repository")
            # print("fetch Decrypt and show token")
            # print("fetch Exit")

            prompt = input(f"{Fore.GREEN}GitNinja ~ {Fore.BLUE}{username} {Fore.RESET}>> ")
            if prompt == "help":
                self.help()
            elif prompt == "whoami":
                self.fetch_user_data()
            elif prompt == "create":
                self.create_repository()
            elif prompt == "decrypt_token":
                self.decrypt_and_show_token()
            elif prompt == "exit()":
                print("Exiting.")
                sys.exit()
            else:
                print(
                    f"{Fore.RED}Err: '{prompt}' is invalid. Please type help! for list of commands.")

    def help(self):
        print("""
            GitNinja version 0.0.1 made by muhammad riyad.
            COPYRIGHT (c) 2024 Muhammad Riyad, All rights reserved.

            whoami              - Tells you who is currently logged in.
            create              - Create new repo.
            decrypt_token       - for decrpyting your current saved token in ~/.sit/.
            exit()              - Exit the program.

            more will be avaliable in the near future.
        """)

    def decrypt_and_show_token(self):
        token = self.decrypt_token()  # Decrypt token when user chooses option 3
        print(f"Your personal access token (): {token}")


if __name__ == "__main__":
    sit_manager = SITManager()
    sit_manager.run()
