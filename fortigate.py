import logging
import os
import time
import configparser
import urllib3
import requests

urllib3.disable_warnings()
DEVICE = 'FortiGate'

class Fortigate:

    def __init__(self, file_path, timeout=10, vdom='root', port="443", verify=False):
        self.credentials = self._read_credentials(file_path)
        self.timeout = timeout
        self.vdom = vdom
        self.port = port
        self.verify = verify
        self.urlbase = f"http://{self.credentials[DEVICE]['ip_address']}:{self.credentials[DEVICE]['port']}/"
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
        credentials = self.credentials[DEVICE]
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
        
        credentials = self.credentials[DEVICE]
        url = f"{self.urlbase}logincheck"
        # Login
        session.post(url,
                     data=f"username={credentials['username']}&secretkey={credentials['password']}",
                     verify=self.verify,
                     timeout=self.timeout)
        # Get CSRF token from cookies and add to headers
        for cookie in session.cookies:
            if cookie.name == "ccsrftoken":
                csrftoken = cookie.value
                session.headers.update({"X-CSRFToken": csrftoken})
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
            return 424
        result = self.post(api_url, f"{data}")
        return result

if __name__ == "__main__":
    fortigate = Fortigate(file_path='credentials.ini')
    create_data = {'name': 'Test_Okan', 'type': 'subnet', 'subnet': '192.168.0.0 255.255.255.0'}
    fortigate.create_firewall_address("Test_Okan", create_data)

