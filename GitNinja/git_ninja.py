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
            result, response, repo_name = create_repository(token)

            if result == 1:
                if token and repo_name != None:
                    print(f"Created {repo_name}!")
                    try:
                        pk, pub = rsa.newkeys(512)
                        print("Generating keys...")
                    except ValueError:
                        isDelete = input('Several warnings occured, do you want to delete the repo and start again? ([Y]es, [N]o) >> ').lower() in ['y', 'yes']
                        isDelete = True if isDelete else False
                        if (isDelete):
                            delete_repository()
                        else:
                            print(f"{Fore.RED}Error: {Style.RESET_ALL}Generating keys failed! quitting...")
                        break

                    encryptedToken = ""
                    print("Encrypting token...")
                    try:
                        encryptedToken = rsa.encrypt(token.encode(), pub)
                    except ValueError:
                        print(f"{Fore.RED}Error: Encrypting the key, please try again!{Style.RESET_ALL}")
                        break

                    try:
                        print(f"{Fore.WHITE}Creating 'token.pub' file...")
                        with open(pub_path, 'wb') as public:
                            public.write(pub +" "+ repo_name)
                            print(pub, repo_name)
                            print(f'{Fore.GREEN}Token on {Style.RESET_ALL}"{pub_path}"{Fore.GREEN} created successfully!{Style.RESET_ALL}')
                    except FileNotFoundError:
                        response = requests.post(url, headers=headers, data=json.dumps())
                        print(f"{Fore.RED}Error: Creating the 'token.pub', please try again!{Style.RESET_ALL}")
                        break

                    try:
                        print(f"{Fore.WHITE}Creating token file...")
                        with open(pk_path, 'wb') as private:
                            private.write(pk +" "+ encryptedToken)
                            print(f'{Fore.GREEN}Token on "{pk_path}" created successfully!')
                    except FileNotFoundError:
                        print(f"{Fore.RED}Error: Creating the 'token', please try again!{Style.RESET_ALL}")
                        break

                    print(f'{Fore.GREEN}Repository {Style.RESET_ALL}"{repo_name}" {Fore.GREEN}created successfully!{Style.RESET_ALL}')
                    break
                else: 
                    print(f"{Fore.RED}Invalid name or token!{Style.RESET_ALL}")
            else:
                print(f'{Fore.RED}Error creating repository: {Style.RESET_ALL}{response.json()["message"]}')
                break
            count += 1


def create_repository(token):
    headers = {
        'Authorization': f'token {token}',
        'Accept': 'application/vnd.github.v3+json'
    }
    
    repo_name = input("Enter new repo name >> ")
    init_readme = input("Init README.md file automatically? ([Y] Yes, [N] No) default [Y] >> ").lower() in ['y', 'yes']
    init_readme = True if init_readme else False

    data = {
        'name': repo_name,
        'auto_init': init_readme
    }

    url = 'https://api.github.com/user/repos'

    response = requests.post(url, headers=headers, data=json.dumps(data))

    if response.status_code == 201:
        result = 1
        return result, response, repo_name
    else:
        result = 0
        return result, response, repo_name


def delete_repository(owner_name, repo_name, token):
    
    # Set up authentication headers
    headers = {
        'Authorization': f'Bearer {token}',
        'Accept': 'application/vnd.github.v3+json'
    }

    owner_name = input("Enter your github username >> ")
    repo_name = input("Enter your repository name >> ")

    url = f"https://api.github.com/repos/{owner_name}/{repo_name}"

    response = requests.delete(url, headers=headers)

    if response.status_code == 204:
        return 1
    else:
        return 0

if __name__ == "__main__":
    main()