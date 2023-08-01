# Cisco ASA restful API to obtain all address objects with the requests library
import cisco

FILE_PATH = "credentials.ini"
cisco_device = "ASA"

# Accessing ASA
cisco_device = cisco.Cisco(cisco_device, FILE_PATH)

if __name__ == "__main__":
    static_routes = cisco_device.get_static_routes()
    address_objects = cisco_device.get_network_objects()
    print(address_objects)
