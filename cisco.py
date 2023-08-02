import json
import configparser
import base64
import urllib3
import requests

urllib3.disable_warnings()

class Cisco:
    """
    A class to interact with Cisco devices through their REST API.

    This class provides methods to authenticate with the Cisco device,
    make API requests, and retrieve network objects and static routes.

    Parameters:
        device_name (str): The name of the device as defined in the configuration file.
        file_path (str): The path to the configuration file containing device credentials.

    Attributes:
        device_name (str): The name of the device as defined in the configuration file.
        file_path (str): The path to the configuration file containing device credentials.
        credentials (dict): A dictionary containing credentials for different devices.
        token (str): The session token obtained after successful login.
        session (requests.Session): A session object to maintain the connection to the device.
    """
    def __init__(self, device_name, file_path):
        """
        Initializes a Cisco instance with the provided device_name and configuration file path.

        :param device_name: The name of the device in the configuration file.
        :param file_path: The path to the configuration file (credentials.ini).
        """
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
        """
        Reads the credentials from the configuration file.

        :return: A dictionary of credentials.
        """
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
        """
        Obtains an X-Auth-Token from the Cisco device.

        :param ip_address: The IP address of the Cisco device.
        :param port: The port of the Cisco device.
        :param username: The username of the Cisco device.
        :param password: The password of the Cisco device.
        :return: An X-Auth-Token if successful, None otherwise.
        """
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
        """
        Logs into the Cisco device.
        """
        device_credentials = self.credentials.get(self.device_name, {})
        ip_address = device_credentials.get('ip_address')
        port = device_credentials.get('port')
        token = self._get_x_auth_token(ip_address, port, device_credentials.get('username'),
                                       device_credentials.get('password'))
        if token:
            self.session.headers.update({"x-auth-token": token})
        else:
            raise ValueError("Failed to login. Unable to obtain the session token.")

    def _is_valid_endpoint(self, endpoint):
        """
        Checks if the specified API endpoint is valid.

        :param endpoint: The API endpoint to check.

        :return: True if the endpoint is valid, False otherwise.
        """
        url = f"https://{self.credentials[self.device_name]['ip_address']}:{self.credentials[self.device_name]['port']}/api/{endpoint}"
        try:
            response = self.session.request("GET", url, verify=False, timeout=10)
            return response.status_code == 200
        except requests.exceptions.RequestException:
            return False

    def _api_request(self, method, url, params=None, data=None):
        """
        Makes an API request to the specified URL using the provided HTTP method.

        :param method: The HTTP method for the request (GET, POST, PUT, DELETE).
        :param url: The URL to make the API request to.
        :param params: The URL parameters for the request.
        :param data: The JSON data to be included in the request.

        :return: The JSON response if successful, None otherwise.
        """
        headers = {
            "Authorization": "Basic " + base64.b64encode(f"{self.credentials[self.device_name]['username']}:{self.credentials[self.device_name]['password']}".encode()).decode(),
        }

        try:
            response = self.session.request(method, url, params=params, json=data, headers=headers, verify=False, timeout=10)
            response.raise_for_status()
            return response.json()
        except requests.exceptions.RequestException as error:
            print(f"Error: {error}")
            return None

    def _get_paged_data(self, endpoint):
        """
        Retrieves paged data from the specified API endpoint.

        :param endpoint: The API endpoint to retrieve data from.

        :return: A list containing all data retrieved from the endpoint.
        """
        limit = 100
        offset = 0
        all_data = []

        while True:
            base_url = f"https://{self.credentials[self.device_name]['ip_address']}/api/{endpoint}"
            params = {"limit": limit, "offset": offset}

            data = self._api_request("GET", base_url, params=params)

            if not data:
                print(f"Failed to retrieve data from '{endpoint}'.")
                break

            if "items" in data:
                results = data["items"]
                all_data.extend(results)

                if len(all_data) == data["rangeInfo"]["total"]:
                    break

                offset += limit
            else:
                print(f"No 'items' found in the response from '{endpoint}'.")
                break

        return all_data

    def get_network_objects(self):
        """
        Retrieves all network objects from the device.

        :return: A list of all network objects.
        """
        endpoint = "objects/networkobjects"
        self._login()  # Make sure we are logged in before making the API request
        return self._get_paged_data(endpoint)

    def get_static_routes(self):
        """
        Retrieves all static routes from the device.

        :return: The JSON response containing static routes if successful, None otherwise.
        """
        endpoint = "routing/static"
        self._login()  # Make sure we are logged in before making the API request
        return self._get_paged_data(endpoint)
