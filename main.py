# Cisco ASA restful API to obtain all address objects with the requests library
import cisco
import sys

FILE_PATH = "credentials.ini"
CISCO_DEVICE = "ASA"

# Accessing ASA
CISCO_DEVICE = cisco.Cisco(CISCO_DEVICE, FILE_PATH)

# sys args
ACL_NAME = sys.argv[1]

if __name__ == "__main__":

    CISCO_DEVICE.get_network_objects()
    CISCO_DEVICE.get_acl(ACL_NAME)
    CISCO_DEVICE.get_static_routes()
    
    CISCO_DEVICE.logout()
