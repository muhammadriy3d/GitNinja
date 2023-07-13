import os
import rsa
import json
import requests
from getpass import getpass
from colorama import Fore, Back, Style


def main():
    path = os.path.expanduser(os.path.join('~', '.sit'))
    pk_path = os.path.join(path, 'token')
    pub_path = os.path.join(path, 'token.pub')

    if os.path.exists(path):
        with open(pk_path, 'rb') as token:
            obj = token.read()
            print(f"{Fore.GREEN}< Fetching done!{Style.RESET_ALL}")

        content = obj.decode('UTF-8')

        # Split will loop through the file and split if '-' true then add each word to a list
        split = content.split(" ")

        pk = split[0].strip()
        encryptedToken = split[1].strip()

        try:
            token = rsa.decrypt(encryptedToken.decode(), pk)
        except:
            print(f"{Fore.RED}<< Error: {Style.RESET_ALL}Encrypting done unsucessfully!")
    else:
        count = 1
        while count <= 3:
            token = getpass("Your personal access token >> ")
            response = create_repository(token)

            if response.status_code == 201:
                if token != None:

                    try:
                        pk, pub = rsa.newkeys(512)
                        print("Generating keys...")
                    except:
                        print(f"{Fore.RED}Error: {Style.RESET_ALL}Generating keys failed!")

                    encryptedToken = ""
                    print("Encrypting token...")
                    try:
                        with open(pub_path, 'wb') as public:
                            encryptedToken = rsa.encrypt(token.encode(), pub)
                            public.write(pub +" "+ repo_name)
                            print(f'{Fore.GREEN}Token on {Style.RESET_ALL}"{pub_path}"{Fore.GREEN} created successfully!{Style.RESET_ALL}')
                    
                        with open(pk_path, 'wb') as private:
                            private.write(pk +" "+ encryptedToken)
                            print(f'{Fore.GREEN}Token on "{pk_path}" created successfully!')
                    except:
                        print(f"{Fore.RED}Error: Encrypting the key or creating the pub or pk, please try again!{Style.RESET_ALL}")

                    print(f'{Fore.GREEN}Repository {Style.RESET_ALL}"{repo_name}" {Fore.GREEN}created successfully!{Style.RESET_ALL}')

            else:
                print(f'{Fore.RED}Error creating repository: {Style.RESET_ALL}{response.json()["message"]}')

            count += 1


def create_repository(token):
    headers = {
        'Authorization': f'token {token}',
        'Accept': 'application/vnd.github.v3+json'
    }
    
    repo_name = input("Enter new repo name >> ")
    init_readme = input("Init README.md file automatically? ([Y] Yes, [N] No) >> ").lower() in ['y', 'yes']
    init_readme = True if init_readme else False

    data = {
        'name': repo_name,
        'auto_init': init_readme
    }

    url = 'https://api.github.com/user/repos'

    response = requests.post(url, headers=headers, data=json.dumps(data))

    if response.status_code == 201:
        return response
    else:
        return response


if __name__ == "__main__":
    main()