# Cisco ASA restful API to obtain all address objects with the requests library
from rich import print as rprint
import cisco

FILE_PATH = "credentials.ini"
CISCO_DEVICE = "ASA"

# Accessing ASA
CISCO_DEVICE = cisco.Cisco(CISCO_DEVICE, FILE_PATH)

if __name__ == "__main__":
    # static_routes = CISCO_DEVICE.get_static_routes()
    # address_objects = CISCO_DEVICE.get_network_objects()
    acl = CISCO_DEVICE.get_acl("INSIDE")
    rprint(acl)
    CISCO_DEVICE.logout()
