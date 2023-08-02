# Cisco ASA restful API to obtain all address objects with the requests library
import argparse
import cisco

FILE_PATH = "credentials.ini"
CISCO_DEVICE = "ASA"

# Accessing ASA
CISCO_DEVICE = cisco.Cisco(CISCO_DEVICE, FILE_PATH)


def arg_parser():
    """
    Argument parser for the script
    :return: Argument parser"""
    parser = argparse.ArgumentParser()
    parser.add_argument('-a',
                        '--acl_argument',
                        help='Argument for ACL')
    parser.add_argument('-n',
                        '--network_objects',
                        action='store_true',
                        help='Execute network_objects without an argument')
    parser.add_argument('-s',
                        '--static_routes',
                        action='store_true',
                        help='Execute static_routes without any argument')
    args = parser.parse_args()

    if args.acl_argument:
        CISCO_DEVICE.get_acl(args.acl_argument)
    elif args.network_objects:
        CISCO_DEVICE.get_network_objects()
    elif args.static_routes:
        CISCO_DEVICE.get_static_routes()
    else:
        print("No valid argument provided. Use -a <argument_name>, -n, or -s.")
   
if __name__ == "__main__":
    #starting argument parser
    arg_parser()

    # Logout
    CISCO_DEVICE.logout()
