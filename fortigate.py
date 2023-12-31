import logging
import ipaddress
import json
import os
import time
import configparser
from rich import print as rprint
import urllib3
import requests

urllib3.disable_warnings()

class Fortigate:
    """
    Class for Fortigate devices.
    """
    def __init__(self, device_name, file_path, vdom='root'):
        self.device_name = device_name
        self.credentials = self._read_credentials(file_path)
        self.vdom = vdom
        self.verify = False
        self.timeout = 10
        self.urlbase = f"http://{self.credentials[self.device_name]['ip_address']}:{self.credentials[self.device_name]['port']}/"
        self._setup_logging(logging.DEBUG)

    def _setup_logging(self, log_level=logging.DEBUG):
        """
        Set up logging configuration.

        :param log_level: The log level to be used (e.g., logging.DEBUG, logging.INFO, logging.ERROR, etc.).
        """
        # Create the 'Logs' directory if it doesn't exist
        logs_dir = os.path.join(os.getcwd(), 'Logs')
        if not os.path.exists(logs_dir):
            os.makedirs(logs_dir)

        # Create the subdirectory for the device's hostname (ip_address) if it doesn't exist
        credentials = self.credentials[self.device_name]
        device_dir = os.path.join(logs_dir, credentials['ip_address'])
        if not os.path.exists(device_dir):
            os.makedirs(device_dir)

        # Create the subdirectory for the current date if it doesn't exist
        date_dir = os.path.join(device_dir, time.strftime('%Y-%m-%d'))
        if not os.path.exists(date_dir):
            os.makedirs(date_dir)

        # Set up logging
        log_level_str = {
            logging.CRITICAL: 'CRITICAL',
            logging.ERROR: 'ERROR',
            logging.WARNING: 'WARNING',
            logging.INFO: 'INFO',
            logging.DEBUG: 'DEBUG'
        }.get(log_level, 'DEBUG')  # Default to DEBUG if an invalid log level is provided

        timestamp = time.strftime('%Y-%m-%d_%H-%M-%S')  # Use the same format as in the debug message
        log_file = os.path.join(date_dir, f"{log_level_str}.{timestamp}.log")
        logging.basicConfig(filename=log_file, level=log_level, format='%(asctime)s - %(levelname)s - %(message)s')

    def _read_credentials(self, file_path):
        """
        Reads the credentials from the configuration file.

        :return: A dictionary of credentials.
        """
        config = configparser.ConfigParser()
        config.read(file_path)

        credentials = {}
        for section in config.sections():
            credentials[section] = {
                'ip_address': config.get(section, 'ip_address'),
                'port': config.getint(section, 'port'),
                'username': config.get(section, 'username'),
                'password': config.get(section, 'password'),
                'api_key': config.get(section, 'api_key')
            }
        return credentials

    def login(self):
        """
        Log into the Fortigate with provided parameters
        
        "return: Open Session
        """
        session = requests.session()
        if not self.verify:
            urllib3.disable_warnings()
            urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
        
        credentials = self.credentials[self.device_name]
        session.headers.update({"Content-Type": "application/json",
                                "Accept": "application/json", 
                                "Authorization": f"Bearer {credentials['api_key']}"})
        login_check = session.get(f"{self.urlbase}api/v2/cmdb/system/vdom")
        login_check.raise_for_status()
        return session

    def logout(self, logout_session):
        """
        Log out of the device.
        
        "return: None
        """
        url = f"{self.urlbase}logout"
        logout_session.post(url, verify=self.verify, timeout=self.timeout)
        # logging.basicConfig(format='%(asctime)s %(message)s')
        # logging.warning('Logged out successfully')

    def does_exist(self, object_url):
        """
        Checks if an object exists on the device.
        
        "return: True if object exists, False otherwise
        """
        session = self.login()
        request = session.get(object_url, verify=self.verify, timeout=self.timeout, params='vdom=' + self.vdom)
        self.logout(session)
        if request.status_code == 200:
            return True
        return False

    def get(self, url):
        """
        Get an object from the device.

        :param url: The URL of the object to get.
        
        "return: Request result as a JSON object
        """
        session = self.login()
        request = session.get(url, verify=self.verify, timeout=self.timeout, params='vdom=' + self.vdom)
        self.logout(session)
        if request.status_code == 200:
            return request.json()['results']
        return request.status_code

    def put(self, url, data):
        """
        Perform PUT operation on provided URL

        :param url: Target of PUT operation
        :param data: JSON data. MUST be a correctly formatted string. e.g. "{'key': 'value'}"

        :return: HTTP status code returned from PUT operation
        """
        session = self.login()
        result = session.put(url, data=data, verify=self.verify, timeout=self.timeout, params='vdom='+self.vdom).status_code
        self.logout(session)
        return result

    def post(self, url, data):
        """
        Perform POST operation on provided URL

        :param url: Target of POST operation
        :param data: JSON data. MUST be a correctly formatted string. e.g. "{'key': 'value'}"

        :return: HTTP status code returned from POST operation
        """
        session = self.login()
        result = session.post(url, data=data, verify=self.verify, timeout=self.timeout, params='vdom='+self.vdom).status_code
        self.logout(session)
        return result

    def delete(self, url):
        """
        Perform DELETE operation on provided URL

        :param url: Target of DELETE operation

        :return: HTTP status code returned from DELETE operation
        """
        session = self.login()
        result = session.delete(url, verify=self.verify, timeout=self.timeout, params='vdom='+self.vdom).status_code
        self.logout(session)
        return result

    def get_firewall_address(self, specific=False, filters=False):
        """
        Get address object information from firewall

        :param specific: If provided, a specific object will be returned. If not, all objects will be returned.
        :param filters: If provided, the raw filter is appended to the API call.

        :return: JSON data for all objects in scope of request, nested in a list.
        """
        api_url = self.urlbase + "api/v2/cmdb/firewall/address/"
        if specific:
            api_url += specific
        elif filters:
            api_url += "?filter=" + filters
        results = self.get(api_url)
        return results

    def create_firewall_address(self, address, data):
        """
        Create firewall address record

        :param address: Address record to be created
        :param data: JSON Data with which to create the address record

        :return: HTTP Status Code
        """
        api_url = self.urlbase + "api/v2/cmdb/firewall/address/"
        # Check whether target object already exists
        if self.does_exist(api_url + address):
            rprint(f"[red][bold]{address} already exists[/bold]![/red]")
            return 424
        result = self.post(api_url, f"{data}")
        rprint(f"[blue]({result})[/blue]{address} created successfully!\t{data}")
        return result

    def read_file(self, filename):
        """
        Creates a JSON file from the provided filename.
        
        :param filename: The name of the file to read.
        
        "return: A JSON object
        """
        if not filename.endswith('.json'):
            print("Invalid file format. Only .json files are accepted.")

        try:
            with open(filename, 'r', encoding='utf-8') as file:
                raw_data = file.read()
                data_list = json.loads(raw_data)

            net_dict = {}
            for item in data_list:
                object_id = item.get("objectId")
                if object_id:
                    net_dict[object_id] = item

            return net_dict
        except ValueError as error:
            print("Error while processing the JSON file:", str(error))

    def is_ip_address(self, name):
        try:
            ipaddress.IPv4Address(name)
            return True
        except ipaddress.AddressValueError:
            return False

    def modify_name_for_ip_address(self, name):
        ip_parts = name.split("/")
        if len(ip_parts) == 2 and ip_parts[1].isdigit():
            # Network address with CIDR notation, modify to N-x.x.x.x_y
            ip_address = ip_parts[0]
            subnet_mask = ip_parts[1]
            modified_name = f"N-{ip_address}_{subnet_mask}"
        else:
            # Single host or invalid format, modify to H-x.x.x.x_32
            modified_name = f"H-{name}_32"

        return modified_name

    def process_address_objects(self, filename, name_param=None, BULK_DATA=False):
        """
        Processes the provided JSON file and creates firewall address objects.

        :param filename: The name of the JSON file to process.
        :param name_param: The name of the object to create.
        :param BULK_DATA: If set to True, the JSON data will be processed in bulk.
        """
        data = self.read_file(filename)

        kind_mapping = {
            "IPv4Network": ("subnet", ""),
            "IPv4Range": ("iprange", ""),
            "IPv4FQDN": ("fqdn", ""),
            "IPv4Address": ("subnet", "/32")
        }

        json_data = {}
        for value in data.values():
            name = value.get("name")
            host = value.get("host").get("value")
            kind = value.get("host").get("kind")
            type_value, subnet_suffix = kind_mapping.get(kind, (None, ""))

            # Modify the name for IP addresses
            if kind in ["IPv4Address", "IPv4Network"]:
                if self.is_ip_address(name):
                    name = self.modify_name_for_ip_address(name)

            # Special handling for IPv4FQDN and IPv4Range
            if kind == "IPv4FQDN":
                json_data[name] = {
                    "name": name,
                    "type": type_value,
                    "fqdn": host
                }
            elif kind == "IPv4Range":
                start_ip, end_ip = host.split('-')
                json_data[name] = {
                    "name": name,
                    "type": type_value,
                    "start-ip": start_ip.strip(),
                    "end-ip": end_ip.strip()
                }
            else:
                json_data[name] = {
                    "name": name,
                    "type": type_value,
                    "subnet": f"{host}{subnet_suffix}"
                }

        if name_param:
            # First, check if the name_param is an IP address and modify it if necessary
            if self.is_ip_address(name_param):
                name_param = self.modify_name_for_ip_address(name_param)

            # Then, try to find a modified name that matches the provided name_param
            if name_param in json_data:
                self.create_firewall_address(name_param, json_data[name_param])
            else:
                raise ValueError(f"Entry with name '{name_param}' not found in the JSON data.")
        elif BULK_DATA:
            for name, data in json_data.items():
                self.create_firewall_address(name, data)
        else:
            raise ValueError("You must either provide 'name_param' or set 'BULK_DATA' to True for bulk processing.")
        
if __name__ == "__main__":
    fortinet = Fortigate('Fortigate', 'credentials.ini')
    rprint(fortinet.get_firewall_address())