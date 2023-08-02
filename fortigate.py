import logging
import configparser
import urllib3
import requests

urllib3.disable_warnings()
DEVICE = 'FortiGate'

class Fortigate:

    def __init__(self, file_path, timeout=10, vdom='root', port="80", verify=False):
        self.credentials = self._read_credentials(file_path)
        self.timeout = timeout
        self.vdom = vdom
        self.port = port
        self.verify = verify
        self.urlbase = f"http://{self.credentials[DEVICE]['ip_address']}:{self.port}/"

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
            }
        return credentials
    
    # Login / Logout
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
        print(url)
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
        
        login_check = session.get(f"{self.urlbase}api/v2/cmdb/system/vdom")
        login_check.raise_for_status()
        return session



if __name__ == "__main__":
    fortigate = Fortigate(file_path='credentials.ini')
    fortigate.login()