import configparser

def read_credentials(file_path):
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


FILE_PATH = "credentials.ini"
CREDENTIALS = read_credentials(FILE_PATH)

# Accessing credentials for ASA
asa_credentials = CREDENTIALS.get("ASA", {})
asa_ip_address = asa_credentials.get("ip_address")
asa_port = asa_credentials.get("port")
asa_username = asa_credentials.get("username")
asa_password = asa_credentials.get("password")


# Accessing credentials for FortiGate
fortigate_credentials = CREDENTIALS.get("FortiGate", {})
fortigate_ip_address = fortigate_credentials.get("ip_address")
fortigate_port = fortigate_credentials.get("port")
fortigate_username = fortigate_credentials.get("username")
fortigate_password = fortigate_credentials.get("password")
