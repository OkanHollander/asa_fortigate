import json
import requests
import urllib3
import configparser
import base64
import logging

urllib3.disable_warnings()

class Cisco:
    def __init__(self, device_name, file_path):
        self.device_name = device_name
        self.file_path = file_path
        self.credentials = self._read_credentials()
        self.token = None
        self.session = requests.Session()
        self.session.verify = False
        self.session.headers.update({'Content-Type': 'application/json'})
        self.session.headers.update({'Accept': 'application/json'})
        self._login()

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
            print(response.text)  # Print the response text for debugging
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

    def _login(self):
        device_credentials = self.credentials.get(self.device_name, {})
        ip_address = device_credentials.get('ip_address')
        port = device_credentials.get('port')
        token = self._get_x_auth_token(ip_address, port, device_credentials.get('username'), device_credentials.get('password'))
        if token:
            self.session.headers.update({"x-auth-token": token})
        else:
            raise ValueError("Failed to login. Unable to obtain the session token.")

    def _is_valid_endpoint(self, endpoint):
        url = f"https://{self.credentials[self.device_name]['ip_address']}:{self.credentials[self.device_name]['port']}/api/{endpoint}"
        try:
            response = self.session.request("GET", url, verify=False, timeout=10)
            return response.status_code == 200
        except requests.exceptions.RequestException:
            return False

    def _make_api_request(self, method, end_point, data=None):
        if not self._is_valid_endpoint(end_point):
            raise ValueError(f"Endpoint '{end_point}' does not exist for device '{self.device_name}'")

        url = f"https://{self.credentials[self.device_name]['ip_address']}:{self.credentials[self.device_name]['port']}/api/{end_point}"

        try:
            response = self.session.request(method, url, json=data, verify=False, timeout=10)
            response.raise_for_status()
            return response.json()
        except requests.exceptions.RequestException as error:
            print(f"Error: {error}")
            return None

    def get_static_routes(self):
        endpoint = "routing/static"
        return self._make_api_request("GET", endpoint)
