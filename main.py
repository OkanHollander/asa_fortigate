# Cisco ASA restful API to obtain all address objects with the requests library
from authentication import Authenticator

FILE_PATH = "credentials.ini"

# Create the authenticator instance
authenticator = Authenticator(FILE_PATH)

# Accessing credentials for ASA
asa_header = authenticator.get_auth_header("ASA")


if __name__ == "__main__":
    print(asa_header)
    
