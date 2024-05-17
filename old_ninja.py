import os
import sys
import json
import requests

from getpass import getpass

from colorama import Fore, Back, Style

from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad


def main():
    path = os.path.expanduser(os.path.join("~", ".sit"))
    pk_path = os.path.join(path, "sit_pk.pem")
    pub_path = os.path.join(path, "sit_pub.pem")

    encrypted_aes_key = b''

    if not os.path.exists(path) or not (os.path.exists(pk_path) and os.path.exists(pub_path)):
        # Validate the user
        isValid, auth, token = getToken()

        # Auth validation callback
        if isValid and auth.status_code == 200:
            # Generating keys
            try:
                print(f"{Fore.WHITE}Generating keys...{Style.RESET_ALL}")

                pk = RSA.generate(4096)
                pub = pk.publickey()

                # Generate a random AES key
                aes_key = get_random_bytes(32)  # 256-bit key

                # Create an AES cipher with CBC mode
                cipher_aes = AES.new(aes_key, AES.MODE_CBC)

            except AttributeError as e:
                print(
                    f"{Fore.RED}Error:{Fore.WHITE} {str(e)} \n {Style.RESET_ALL} The error with the code itself! Please pull request the bug to the GitNinja repo with code: 100."
                )
                sys.exit()

            try:
                print(f"{Fore.WHITE}Encrypting token...{Style.RESET_ALL}")
                # Encrypt the AES key with the public key
                cipher_rsa = PKCS1_OAEP.new(pub)
                encrypted_aes_key = cipher_rsa.encrypt(aes_key)

                # Encrypt the plaintext with the AES cipher
                ciphertext = cipher_aes.encrypt(pad(token.encode(), AES.block_size))

            except Exception as e:
                print(
                    f"{Fore.RED}Error: {Fore.WHITE} {str(e)}! {Style.RESET_ALL}\n Please pull request the bug to the GitNinja repo with code: 500."
                )
                sys.exit()

            try:
                if not os.path.exists(path):
                    os.makedirs(path)

                print(f"{Fore.WHITE}Creating '~/.sit/sit_pk.pem' file...{Style.RESET_ALL}")

                # Save the private key to a file
                with open(pk_path, "wb") as f:
                    username = getInfo(token)
                    if username is not None:
                        f.write(
                            pk.export_key("PEM") +
                            b" " +
                            ciphertext +
                            b" " +
                            username.encode("utf-8")
                        )
                        print(
                            f'{Fore.GREEN}Token on "{pk_path}" created successfully! for {username}{Style.RESET_ALL}'
                        )
            except Exception as e:
                print(
                    f"{Fore.RED}Error: {Fore.WHITE}{str(e)}{Style.RESET_ALL} \n Creating the 'token', please try again! or pull request this bug to GitNinja repo{Style.RESET_ALL}"
                )
                sys.exit()

            # Save public key
            try:
                # Save the public key to a file
                with open(pub_path, "wb") as f:
                    username = getInfo(token)
                    if username is not None:
                        f.write(pub.export_key("PEM") + b" " + username.encode("utf-8"))
                        print(f'{Fore.GREEN}Token on "{pub_path}" created successfully!')
            except Exception as e:
                print(
                    f"{Fore.RED}Error: {Fore.WHITE}{str(e)}{Style.RESET_ALL} \n Creating the 'token', please try again! or pull request the bug to GitNinja repo{Style.RESET_ALL}"
                )
                sys.exit()
        else:
            print(f"{Fore.RED}Error:{Fore.WHITE} Invalid token or the user does not exist!{Style.RESET_ALL}")
            sys.exit()
    # If the .sit file does not exist in the $HOME
    else:
        # Read the private key from the file
        with open(pk_path, "rb") as f:
            content = f.read()
            private_key, encrypted_aes_key, username = content.split(b" ")
            private_key = RSA.import_key(private_key)
            print(f"{Fore.GREEN}< Fetching done!{Style.RESET_ALL}")

        # Decrypt the AES key with the private key
        decrypt_rsa = PKCS1_OAEP.new(private_key)
        decrypted_aes_key = decrypt_rsa.decrypt(encrypted_aes_key)

        # Split the content using the space separator
        split = content.decode().split(" ")

        pk = split[0].strip()
        encrypted_token = split[1].strip()
        username = split[2].strip()

        try:
            decrypted_token = rsa.decrypt(encrypted_token, pk)
        except Exception as e:
            print(
                f"{Fore.RED}{str(e)}\n Error: {Style.RESET_ALL} Decrypting done unsuccessfully!"
            )


def getToken():
    count = 0
    while count <= 2:
        token = getpass("Your personal access token >> ")

        if token is not None:
            isValid, auth = auth_validation(token)
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


def getInfo(token):
    headers = {"Authorization": f"token {token}"}
    url = "https://api.github.com/user"

    response = requests.get(url, headers=headers)

    if response.status_code == 200:
        user_data = response.json()
        username = user_data["login"]
        return username
    else:
        print("Failed to retrieve username. Status code:", response.status_code)


def auth_validation(token):
    headers = {
        "Authorization": f"token {token}",
        "Accept": "application/vnd.github.v3+json",
    }

    response = requests.get("https://api.github.com/user", headers=headers)

    if response.status_code == 200:
        return True, response
    else:
        return False, response


def create_repository(token):
    headers = {
        "Authorization": f"token {token}",
        "Accept": "application/vnd.github.v3+json",
    }

    repo_name = input("Enter new repo name >> ")
    init_readme = input(
        "Init README.md file automatically? ([Y] Yes, [N] No) default [Y] >> "
    ).lower() in ["y", "yes"]
    init_readme = True if init_readme else False

    data = {"name": repo_name, "auto_init": init_readme}

    url = "https://api.github.com/user/repos"

    response = requests.post(url, headers=headers, data=json.dumps(data))

    if response.status_code == 201:
        return response, repo_name
    else:
        return response, repo_name


def delete_repository(owner_name, repo_name, token):
    # Set up authentication headers
    headers = {
        "Authorization": f"Bearer {token}",
        "Accept": "application/vnd.github.v3+json",
    }

    owner_name = input("Enter your GitHub username >> ")
    repo_name = input("Enter your repository name >> ")

    url = f"https://api.github.com/repos/{owner_name}/{repo_name}"

    response = requests.delete(url, headers=headers)

    if response.status_code == 204:
        return response
    else:
        return response


if __name__ == "__main__":
    main()













# response, repo_name = create_repository(token)

#         if (isValid and (auth == 200)):
#             if token and repo_name != None:

#                 print(f"Created {repo_name}!")


#                 print(f'{Fore.GREEN}Repository {Style.RESET_ALL}"{repo_name}" {Fore.GREEN}created successfully!{Style.RESET_ALL}')
#                 break
#             else:
#         else:
#             print(f'{Fore.RED}Error creating repository: {Style.RESET_ALL}{response.json()["message"]}')
#         count += 1
#         if count >= 3: