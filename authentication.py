import configparser
import json
import base64
import requests
import urllib3

urllib3.disable_warnings()

class Authenticator:
    def __init__(self, file_path):
        self.file_path = file_path
        self.credentials = self._read_credentials()
        self.token = None

    def _read_credentials(self):
        config = configparser.ConfigParser()
        config.read(self.file_path)

        credentials = {}
        for section in config.sections():
            credentials[section] = {
                'ip_address': config.get(section, 'ip_address'),
                'port': config.getint(section, 'port'),
                'username': config.get(section, 'username'),
                'password': config.get(section, 'password'),
            }
        return credentials

    def _get_x_auth_token(self, ip_address, port, username, password):
        if self.token:
            return self.token

        base_url = f"https://{ip_address}:{port}/api/tokenservices"
        credentials = f"{username}:{password}"
        encoded_credentials = base64.b64encode(credentials.encode('utf-8')).decode('utf-8')
        payload = {}
        headers = {
            "Content-Type": "application/json",
            "Authorization": "Basic " + encoded_credentials,
        }

        try:
            response = requests.post(
                url=base_url, headers=headers, data=json.dumps(payload), verify=False, timeout=10
            )
            if response.status_code == 204:
                print("Successfully obtained session token.")
                self.token = response.headers["x-auth-token"]
                return self.token
            else:
                print(f"Error: {response.status_code}. Failed to obtain session token.")
                return None
        except requests.exceptions.RequestException as error:
            print(f"Error: {error}. Failed to obtain session token.")
            return None

    def get_x_auth_token(self, device_name):
        device_credentials = self.credentials.get(device_name, {})
        return self._get_x_auth_token(
            device_credentials.get('ip_address'),
            device_credentials.get('port'),
            device_credentials.get('username'),
            device_credentials.get('password'),
        )

    def get_auth_header(self, device_name):
        token = self.get_x_auth_token(device_name)
        if token:
            return token
        return None
