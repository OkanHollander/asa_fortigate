# Cisco ASA restful API to obtain all address objects with the requests library
import argparse
import cisco
import fortigate

CREDENTIALS = "credentials.ini"
FILE_PATH = "Files/test_file.json"
CISCO = "ASA"
FORTIGATE = "Fortigate"

# Accessing ASA
CISCO_DEVICE = cisco.Cisco(CISCO, CREDENTIALS)

# Accessing Fortigate
FORTIGATE_DEVICE = fortigate.Fortigate(FORTIGATE, CREDENTIALS)

class FirewallAction(argparse.Action):
    def __call__(self, parser, namespace, values, option_string=None):
        if values is not None:
            setattr(namespace, self.dest + '_name', values)
        setattr(namespace, self.dest + '_bulk', True)

def arg_parser():
    """
    Argument parser for the script
    :return: Argument parser"""
    parser = argparse.ArgumentParser()
    parser.add_argument('-ca',
                        '--cisco_acl_argument',
                        help='Argument for ACL')
    parser.add_argument('-cn',
                        '--cisco_network_objects',
                        action='store_true',
                        help='Execute network_objects without an argument')
    parser.add_argument('-cs',
                        '--cisco_static_routes',
                        action='store_true',
                        help='Execute static_routes without any argument')

    parser.add_argument('--name', type=str, help='Name of the entry to process individually.')
    parser.add_argument('--bulk', action='store_true', help='Enable bulk processing.')
    parser.add_argument('-fn', '--firewall_name', action=FirewallAction, nargs='?', const=True, help='Specify firewall name for subsequent processing')

    args = parser.parse_args()

    if args.cisco_acl_argument:
        CISCO_DEVICE.get_acl(args.acl_argument)
    elif args.cisco_network_objects:
        CISCO_DEVICE.get_network_objects()
    elif args.cisco_static_routes:
        CISCO_DEVICE.get_static_routes()
    elif args.firewall_name_name and args.name:
        # Process a single entry with the provided name
        FORTIGATE_DEVICE.process_address_objects(FILE_PATH, name_param=args.name)
    elif args.firewall_name_bulk:
        # Perform bulk processing for all entries in the JSON file
        FORTIGATE_DEVICE.process_address_objects(FILE_PATH, BULK_DATA=True)
    else:
        print("No valid argument provided. Use -a <argument_name>, -n, -s, -fn, or --bulk.")

if __name__ == "__main__":
    arg_parser()

    # Logout
    CISCO_DEVICE.logout()
