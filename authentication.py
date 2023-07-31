import sys
import getpass
import json
import base64
import requests
import urllib3

urllib3.disable_warnings()


IP = sys.argv[1]
PORT = "443"
URL = "https://" + IP + ":" + PORT + "/api/tokenservices"
USERNAME = sys.argv[2]
PASSWORD = getpass.getpass()


def get_x_auth_token(ip):
    token = None
    username = USERNAME
    password = PASSWORD
    credentials = f"{username}:{password}"
    encoded_credentials = base64.b64encode(credentials.encode('utf-8')).decode('utf-8')
    payload = {}
    headers = {
        "Content-Type": "application/json",
        "Authorization": "Basic " + encoded_credentials,
    }
    try:
        response = requests.post(
            url=URL, headers=headers, data=json.dumps(payload), verify=False, timeout=10
        )
        if response.status_code == 204:
            print("Successfully obtained session token.")
            token = response.headers["x-auth-token"]
            return token
        else:
            print(f"Error: {response.status_code}. Failed to obtain session token.")
            return None
    except requests.exceptions.RequestException as error:
        print(f"Error: {error}. Failed to obtain session token.")
        return None


def delete_x_auth_token(token):
    headers = Header
    url = URL + '/' + token
    requests.delete(url=url, headers=headers, verify=False, timeout=10)


Token = get_x_auth_token(IP)
Header = {"x-auth-token": Token, "Content-Type": "application/json"}
