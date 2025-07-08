#! python
#
# FW Move Script
# Script to facilitate Firewall migration.
# - read parameter file from YAML
# - connect to devices
# - remove VLANs on one AAEP
# - add VLANs on another AAEP
# - clear ARP entries    
#
# Author: Alexander Pickar
#

import code  # allows to interact with the local variables in the script after it has run

import getpass
import json
import os
import re
# import requests
import urllib3
import pandas as pd
import numpy as np
from datetime import datetime
import sys
import argparse
import logging
import yaml
from concurrent.futures import ThreadPoolExecutor, as_completed


from src.cisco_api.apic import apic as BaseApic  # will enhance the APIC class with :set_aaep_epg method
from src.cisco_api.netdevice import netdevice as BaseNetdevice  # will enhance the Netdevice class with :clear_arp_interface method


class fw_apic(BaseApic):
    """
    Class to enhance the APIC class with :set_aaep_epg method.
    This class method is used to set the AAEP and EPG for a specific VLAN.
    """

    def set_aaep_epg(self, aaep_name: str, epg_dn: str,  action: str, debug_level: int = 0):
        """
        Add or remove an EPG reference to/from an AAEP (Application Network Profile).
        This method allows you to add or remove an EPG from an AAEP on the APIC.
        The action can be 'add' or 'remove'. If you want to query the EPG, use 'query'.

        Args:
            aaep_name (str): Name of the AAEP.
            epg_dn (str): Distinguished name of the EPG. (for example: 'uni/tn-CZDC_TDA/ap-tste/epg-VLAN2913_EPG')
            action (str): Action to perform, either 'add' or 'remove'.
        """
        action = action.lower().strip()
        epg_dn = epg_dn.strip()
        aaep_name = aaep_name.strip()

        # if action not in ['add', 'remove', 'query']:
        if action not in ['add', 'remove']:
            print(f"ERROR: Unknown action '{action}' for set_aaep_epg method")
            logging.error(f"ERROR: Unknown action '{action}' for set_aaep_epg method")
            return None

        if not epg_dn or not aaep_name:  # Check if EPG and AAEP names are provided
            print(f"ERROR: EPG name  '{epg_dn}' or AAEP name '{aaep_name}' is empty")
            logging.error(f"ERROR: EPG name  '{epg_dn}' or AAEP name '{aaep_name}' is empty")
            return None
        

        if action == 'add':
            vlan_match = re.search(r'epg-VLAN0*(\d+)_EPG', epg_dn)
            if vlan_match:
                vlan_id = int(vlan_match.group(1))
            else:
                print(f"ERROR: Could not extract VLAN ID from EPG DN '{epg_dn}'")
                logging.error(f"ERROR: Could not extract VLAN ID from EPG DN '{epg_dn}'")
                return None

            payload = f'{{"infraAttEntityP":\
                {{"attributes":{{"dn":"uni/infra/attentp-{aaep_name}",\
                    "name":"{aaep_name}"}},\
                        "children":\
                            [{{"infraGeneric":\
                                {{"attributes":{{"annotation":"","descr":"","name":"default","nameAlias":""}},\
                                    "children":\
                                        [{{"infraRsFuncToEpg":\
                                            {{"attributes":{{"encap":"vlan-{vlan_id}",\
                                                "tDn":"{epg_dn}"}}}}}}]}}}}]}}}}'


        elif action == 'remove':
            payload = f'{{"infraRsFuncToEpg":\
                {{"attributes": {{\
                    "dn": "uni/infra/attentp-{aaep_name}/gen-default/rsfuncToEpg-[{epg_dn}]",\
                    "tDn": "{epg_dn}",\
                    "status": "deleted"}},\
                "children": []}}\
                }}'


        # TODO: Implement query action if needed

        if debug_level > 1:
            print(f"    Sending payload: {payload}")
            logging.debug(f"    Sending payload: {payload}")
        
        payload_json = json.loads(payload)
        response = self.send_uni_payload(payload_json)

        return response

    def query_apic_vpc_aaep(self, aaep_name: str, vpc_policy: str, debug_level: int = 0):
        """
        Query the AAEP association for a given VPC policy group.
        Args:
            aaep_name (str): Name of the AAEP.
            vpc_policy (str): Name of the VPC policy group.
            debug_level (int): Debug level for logging.
        Returns:
            Response object from the requests library.
        """
        vpc_policy = vpc_policy.strip()
        aaep_name = aaep_name.strip()
        dn = f"uni/infra/funcprof/accbundle-{vpc_policy}/rsattEntP"
        # Construct the URL for the query
        url = f"/api/node/mo/{dn}.json"
        if debug_level > 1:
            print(f"    Querying AAEP association for VPC policy '{vpc_policy}' at '{url}'")
            logging.debug(f"    Querying AAEP association for VPC policy '{vpc_policy}' at '{url}'")
        response = self.get(url)
        return response


    def set_apic_vpc_aaep(self, aaep_name: str, vpc_policy: str, debug_level: int = 0):
        # TODO: Implement the method to change AAEP inside of a VPC policy
        """
        Sends a REST API payload to update the AAEP in a VPC policy group using the universal ACI URL.
        
        SAMPLE PAYLOAD:
        url: https://10.100.131.249/api/node/mo/uni/infra/funcprof/accbundle-DCLAB-A-LFA101:102_VPC112/rsattEntP.json
        payload{"infraRsAttEntP":{"attributes":{"tDn":"uni/infra/attentp-CZLAB_TRUNK-ALL_AAEP"},"children":[]}}

        url: https://10.100.131.249/api/node/mo/uni/infra/funcprof/accbundle-DCLAB-A-LFA101:102_VPC112/rsattEntP.json
        payload{"infraRsAttEntP":{"attributes":{"tDn":"uni/infra/attentp-CZDC_Static_AAEP"},"children":[]}}
        Parameters:
        - apic_ip (str): IP address or hostname of the APIC controller.
        - vpc_policy (str): Name of the VPC policy group.
        - aaep_name (str): Name of the AAEP to associate.

        Returns:
        - Response object from the requests library.
        """

        vpc_policy = vpc_policy.strip()
        aaep_name = aaep_name.strip()
        dn = f"uni/infra/funcprof/accbundle-{vpc_policy}"

        payload = {
            "infraAccBndlGrp": {
                "attributes": {
                    "dn": dn,
                    "name": vpc_policy,
                    "status": "modified"
                },
                "children": [
                    {
                        "infraRsAttEntP": {
                            "attributes": {
                                "tDn": f"uni/infra/attentp-{aaep_name}"
                            }
                        }
                    }
                ]
            }
        }


        if debug_level > 1:
            print(f"    Sending payload: {json.dumps(payload, indent=2)}")
            logging.debug(f"    Sending payload: {json.dumps(payload, indent=2)}")
        
        # payload_json = json.loads(payload)
        response = self.send_uni_payload(payload)

        return response


class netdevice(BaseNetdevice):
    """
    Class to enhance the Netdevice class with :clear_arp_interface method.
    This class method is used to clear ARP entries for a specific interface on a network device.
    Attributes:
        last_result (dict): Last result of the command executed.
        address (str): IP address of the network device.
        hostname (str): Hostname of the network device.
        is_connected (bool): Connection status of the network device.
        debug_level (int): Debug level for logging.
    Args:
        address (str): IP address of the network device.
        username (str): Username for device login.
        password (str): Password for device login.
        device_type (str): Type of the network device (e.g., 'cisco_ios').
        debug_level (int): Debug level for logging.
    """

    def clear_arp_interface(self, interface: str):
        """
        Clear ARP entries for a specific interface on the network device.

        Args:
            interface (str): The name of the interface for which to clear ARP entries.
        Returns:
            dict: A dictionary containing the IP address, hostname, and output of the command.
        """
        result = {}
        result['ip'] = self.address
        result['hostname'] = self.hostname
        command = f"clear arp interface {interface}"
        result['output'] = self.send(command)
        self.last_result = result
        if self.debug_level > 1:
            print(f"    Clear ARP for interface {interface} on device {self.address}")
            logging.debug(f"    Clear ARP for interface {interface} on device {self.address}")
        return result


def process_cli_arguments(parameter_file='vars/parameters.yml',\
                          output_dir='.',\
                          verbosity=0,\
                          max_workers=5,\
                          username = None,\
                          log_file = 'session_last.log'):
    
    """
    Process CLI arguments and return them to the main function.
    Args:
        parameter_file (str): Path to the parameter file in YAML format.
        output_dir (str): Directory where output files will be saved.
        verbosity (int): Verbosity level for logging.
        max_workers (int): Maximum number of workers for parallel execution.
        username (str): Username for device login.
        log_file (str): Log file name.
    """
    parser = argparse.ArgumentParser(
        description="""Get show command outputs from device_source specified by their IPs.
        """
    )

    parser.add_argument(
        "-f",
        "--parameter_file",
        help=f"Parameter file in YAML format. Default = {parameter_file}",
        type=str,
        default=parameter_file,
    )

    parser.add_argument(
        "-l",
        "--log_file",
        help=f"Log file. Default = {log_file}",
        type=str,
        default=log_file,
    )

    parser.add_argument(
        "-u",
        "--username",
        help=f"username",
        type=str,
        default=None,
    )

    parser.add_argument(
        "-p",
        "--password",
        help=f"password",
        type=str,
        default=None,
    )

    parser.add_argument(
        "-o",
        "--output_dir",
        help=f"Output directory. Default = {output_dir}",
        type=str,
        default=output_dir,
    )

    parser.add_argument(
        "-v", "--verbosity", help="increase output verbosity", action="count", default=verbosity
    )

    parser.add_argument(
        "-w",
        "--max_workers",
        help="Max workers count, default = 5",
        action="count",
        default=max_workers,
    )

    parser.add_argument(
        "-s",
        "--scope",
        help="""Scope determines what actions should be taken.
            scope can be a comma separated string and accepts following words:
            'aaep' - change AAEP bound to an Interface profile
            'epg' - (default) change EPG assignment within AAEP
            'arp' - clear arp interface relevant to EPG based on the embedded VLAN ID
            'all' - do all the above actions""",
        type=str,
        default = "epg")


    return parser.parse_args()


def get_credentials(raw_username=None, raw_password=None):
    """
    Gets login information from the user or command line arguments.
    If username and password are not provided, it prompts the user for them.
    Returns:
        tuple: (username, password)
    """
    print(f"- Processing credentials")
    logging.info(f"- Geting Credentials")

    # Read Credentials
    # username = args.username
    if raw_username:
        username = raw_username.strip()
        print(f"  Username: {username}")
    else:
        username = input("  Username: ").strip()

    if raw_password:
        password = raw_password

    else:
        if sys.stdin.isatty():
            password = getpass.getpass("  Password: ")
        else:
            password = sys.stdin.readline().rstrip()

    return username, password


def read_parameter_file(parameter_file):
    """
    Reads a parameter file in YAML format and returns a list of raw parameters.

    Args:
        parameter_file (str): Path to the device YAML file.
    Returns:
        list: List of raw devices with their IPs and roles.
    """
    if os.access(parameter_file, os.F_OK):
        with open(parameter_file, 'r') as f:
            parameters = yaml.safe_load(f)
        return parameters
    else:
        print(f"ERROR: Could not read parameter file {parameter_file}")
        logging.error(f"ERROR: Could not read parameter file {parameter_file}")
        return []


def processDeviceFile(device_source, default_username:str, default_password:str):
    """
    Processes a list of device_source and returns a list of netdevice objects.
    Args:
        device_source (list): List of device_source with their IPs and other details.   
    """
    netdevice_list = []
    for device in device_source:
        if 'ip' not in device:
            print(f"ERROR: Device {device} does not have an IP address")
            logging.error(f"ERROR: Device {device} does not have an IP address")
            continue
        ip = device['ip']
        username = device.get('username', default_username)
        if not username:
            print(f"ERROR: Device {ip} does not have a username")
            logging.error(f"ERROR: Device {ip} does not have a username")
            continue
        password = device.get('password', default_password)
        if not password:
            print(f"ERROR: Device {ip} does not have a password")
            logging.error(f"ERROR: Device {ip} does not have a password")
            continue
        if 'device_type' not in device:
            print(f"WARNING: Device {ip} does not have a device_type, using default 'cisco_ios'")
            logging.warning(f"WARNING: Device {ip} does not have a device_type, using default 'cisco_ios'")
        # Default device type is cisco_ios, but can be overridden by the device_source
        # If device_type is not specified, use 'cisco_ios' as default

        device_type = device.get('device_type', 'cisco_ios')
        new_device = netdevice(ip, username, password, device_type)
        new_device.base_interface = device.get('base_interface', None)  # Optional interface for ARP clearing
        netdevice_list.append(new_device)
    return netdevice_list


def modify_aaep(dc_apic, epg):
    """
    Modify the AAEP (Application Network Profile) for a given EPG entry.

    """
    result_success_list = []
    result_fail_list = []

    vlan_match = re.search(r'epg-VLAN0*(\d+)_EPG', epg['dn'])

    if vlan_match:
        vlan_id = int(vlan_match.group(1))
        print(f"- Processing EPG {epg['dn']} with VLAN ID {vlan_id}")
        logging.info(f"- Processing EPG {epg['dn']} with VLAN ID {vlan_id}")

        for aaep in epg['aaep_list']:
            print(f"  - {aaep['action'].upper()} EPG \'{epg['dn']}\' association to AAEP {aaep['name']}")
            logging.info(f"  - {aaep['action'].upper()} EPG \'{epg['dn']}\' association to AAEP {aaep['name']}")
            
            result = dc_apic.set_aaep_epg(aaep_name=aaep['name'], epg_dn=epg['dn'], action=aaep['action'], debug_level=debug_level)

            if debug_level > 1 or result.status_code != 200:
                print(f"    Result: {result.status_code} {result.reason}\n    {result.text}")
                logging.debug(f"    Result: {result.status_code} {result.reason} {result.text}")


        if result.status_code == 200:
            print(f"  - Successfully {aaep['action']}ed EPG {epg['dn']} in AAEP {aaep['name']}")
            logging.info(f"  - Successfully {aaep['action']}ed EPG {epg['dn']} in AAEP {aaep['name']}")
            result_success_list.append(aaep['name'])

        else:
            result_fail_list.append(aaep['name'])

    else:
        print(f"  ERROR: Could not extract VLAN ID from EPG DN {epg['dn']}'")
        logging.error(f"  ERROR: Could not extract VLAN ID from EPG DN {epg['dn']}")


    # print(f"- Finished processing EPG {epg['dn']}.")
    # logging.info(f"- Finished processing EPG {epg['dn']}.")

    return result_success_list, result_fail_list


def send_command_to_routers(netdevice_list, command, max_workers=5):
    """
    Sends a clear ARP command to a list of routers concurrently.

    Parameters:
    - router_list: List of network device objects with a `.send(command)` method.
    - clear_arp_base_interface (str): Base interface name.
    - vlan_id (str or int): VLAN ID to append to the interface.

    Returns:
    - Dictionary mapping router object (or name) to command result.
    """
    command = command.strip()
    if not command:
        print("ERROR: Command is empty. Please provide a valid command.")
        logging.error("ERROR: Command is empty. Please provide a valid command.")
        return {}
    results = {}

    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        future_to_router = {
            executor.submit(router.send, command): router for router in netdevice_list
        }

        for future in as_completed(future_to_router):
            router = future_to_router[future]
            try:
                result = future.result()
                results[router.address] = result
            except Exception as e:
                results[router.address] = f"Error: {e}"

    return results




def main():
    """
    Connect to the devices, shutdown VLANs on one side and enable on another side.
    - Define global variables and default values
    - Process command line arguments
    - Read input files: device, credentials
    - read parameter file from YAML
    - connect to devices
    - remove VLANs on one AAEP
    - add VLANs on another AAEP
    - clear ARP entries
    - Optional save config
    """
    global debug_level
    urllib3.disable_warnings()

    # Process command-line arguments
    args = process_cli_arguments()
    parameter_file = args.parameter_file
    output_dir = args.output_dir
    debug_level = args.verbosity
    max_workers = args.max_workers
    log_file = args.log_file
    scope_raw = args.scope
    scope = [scope_entry.strip().lower() for scope_entry in scope_raw.split(',')]


    # Setup logging
    logging.basicConfig(
        filename = log_file, 
        format = f"%(asctime)s \n%(levelname)s: %(message)s \n{'-' * 80}",
        datefmt='%x %X %Z',
        level = logging.INFO
    )
    logging.info(f"\n{'=' * 80}\nSTARTING a new logging session.")


    # Start executing
    print("=====================================================")
    print("  FW MOVE: configure infrastructure for Firewall migration    ")
    print(f"  Parameter file: { parameter_file }                   ")
    print(f"       Verbosity: { debug_level }                   ")
    print(f"       Scope: { scope }                   ")
    print("   STARTED at: ", datetime.now().strftime("%Y-%m-%d %H:%M:%S"))
    if 'test' in scope:
        print()
        print("  TEST MODE: No changes will be made to the devices.")
        logging.info("  TEST MODE: No changes will be made to the devices.")
        print()

    print("=====================================================")


    username, password = get_credentials(raw_username = args.username, raw_password = args.password)


    # Read device file
    print(f"- Reading parameter file: {parameter_file}")
    logging.info(f"- Reading parameter file: {parameter_file}")

    parameters_raw = read_parameter_file(parameter_file)

    if not parameters_raw:
        print(f"ERROR: Could not read parameter file {parameter_file}")
        logging.error(f"ERROR: Could not read parameter file {parameter_file}")
        sys.exit(1)
    if 'apic' not in parameters_raw or 'ip' not in parameters_raw['apic']:
        print(f"ERROR: Parameter file {parameter_file} does not contain APIC IP address")
        logging.error(f"ERROR: Parameter file {parameter_file} does not contain APIC IP address")
        sys.exit(1)
    if 'all' in scope or 'arp' in scope:
        if 'routers' not in parameters_raw or not parameters_raw['routers']:
            print(f"ERROR: Parameter file {parameter_file} does not contain routers")
            logging.error(f"ERROR: Parameter file {parameter_file} does not contain routers")
            sys.exit(1)
    if 'epg_list' not in parameters_raw or not parameters_raw['epg_list']:
        print(f"ERROR: Parameter file {parameter_file} does not contain EPG list")
        logging.error(f"ERROR: Parameter file {parameter_file} does not contain EPG list")
        sys.exit(1)

    print(f"- Parameter file {parameter_file} read successfully.")
    logging.info(f"- Parameter file {parameter_file} read successfully.")
    print(f"- APIC IP: {parameters_raw['apic']['ip']}")
    logging.info(f"- APIC IP: {parameters_raw['apic']['ip']}")
    print(f"- Routers: {parameters_raw['routers']}")
    logging.info(f"- Routers: {parameters_raw['routers']}")
    print(f"- EPG list: {parameters_raw['epg_list']}")
    logging.info(f"- EPG list: {parameters_raw['epg_list']}")
    # Check if output directory exists, if not create it
    if not os.path.exists(output_dir):
        print(f"Creating output directory: {output_dir}")
        logging.info(f"Creating output directory: {output_dir}")
        os.makedirs(output_dir, exist_ok=True)
    else:
        print(f"Output directory {output_dir} already exists.")
        logging.info(f"Output directory {output_dir} already exists.")

    # Check if log file exists, if not create it
    if not os.path.exists(log_file):
        print(f"Creating log file: {log_file}")
        logging.info(f"Creating log file: {log_file}")
    else:
        print(f"Log file {log_file} already exists.")
        logging.info(f"Log file {log_file} already exists.")

    if 'all' in scope or 'arp' in scope:
        # Prepare connection parameters for network devices
        routers = parameters_raw['routers']
        print(f"- Processing routers: {routers}")
        logging.info(f"- Processing routers: {routers}")
        netdevice_list = processDeviceFile(device_source = routers, default_username=username, default_password = password)
        if not netdevice_list:
            print(f"ERROR: Could not connect to any router in {routers}")
            logging.error(f"ERROR: Could not connect to any router in {routers}")
            sys.exit(1)
        else:
            print(f"- Ready to connect to {len(netdevice_list)} network devices.")
            logging.info(f"- Ready to connect to {len(netdevice_list)} network devices.")
        # now we have a list of netdevice objects in netdevice_list.


        # Connect to network devices
        for device in netdevice_list:
            print(f"  - Connecting to {device.address}",end='')
            logging.info(f"  - Connecting to {device.address}")
            device.connect()

            if device.is_connected:
                print(f": OK")
                logging.info(f"  - Connected successfully.")
            else:
                print(f"    - ERROR: Could not connect to {device.address}")
                logging.error(f"    - ERROR: Could not connect to {device.address}")
                sys.exit(1)

        if debug_level > 1:
            print(f"- Connected to network devices: {[device.address for device in netdevice_list]}")
            logging.debug(f"- Connected to network devices: {[device.address for device in netdevice_list]}")

        print(f"- Finished connecting to network devices.")
        logging.info(f"- Finished connecting to network devices.")


    # Prepare APIC connection
    if 'all' in scope or 'aaep' in scope or 'epg' in scope:
        # Prepare connection parameters for APIC
        if 'apic' not in parameters_raw or 'ip' not in parameters_raw['apic']:
            print(f"ERROR: Parameter file {parameter_file} does not contain APIC IP address")
            logging.error(f"ERROR: Parameter file {parameter_file} does not contain APIC IP address")
            sys.exit(1)
        # Connect to APIC
        apic_ip = parameters_raw['apic']['ip']
        print(f"- Connecting to APIC {apic_ip}.")
        logging.info(f"- Connecting to APIC {apic_ip}")
        os.environ.update({"no_proxy": apic_ip})
        dc_apic = fw_apic(apic_ip,username,password, debug_level=debug_level)


    # READY FOR MIGRATION - wait for user input
    print()
    print(" **** READY FOR MIGRATION ****")
    if 'test' in scope:
        print("     (TEST MODE)")
    print()
    user_input = input("Press Enter to continue or Ctrl+C to exit...\n\n")
    print()




    # MIGRATION STEP: Loop through VPCs and set AAEPs
    # For each VPC in the list, we will:
    # - Set the AAEP for the VPC policy
    #
    if 'all' in scope or 'aaep' in scope:
        print("  SWITCHOVER started at: ", datetime.now().strftime("%Y-%m-%d %H:%M:%S"))
        print()

        print('# MIGRATION STEP: Loop through VPCs and set AAEPs')
        logging.info('MIGRATION STEP: Loop through VPCs and set AAEPs')

        for vpc in parameters_raw['vpc_list']:

            # Query the current AAEP for the VPC
            querystring = f"mo/uni/infra/funcprof/accbundle-{vpc['name']}.json?query-target=subtree&target-subtree-class=infraRsAttEntP"
            response = dc_apic.query(querystring)
            if response.status_code != 200:
                print(f"ERROR sending {querystring}:")
                print(f"{response.status_code}: {response.text}")
            else:
                aaep_response = response.json()["imdata"][0]["infraRsAttEntP"]["attributes"]["tDn"]
                print(f"  INFO: Initial VPC {vpc['name']} contains AAEP {aaep_response}")
                logging.info(f"Initial VPC {vpc['name']} contains AAEP {aaep_response}")

            # Try to attach the AAEP to the VPC
            if 'test' in scope:
                print(f"  - TEST MODE: Would attach AAEP {vpc['aaep']} to VPC {vpc['name']}")
                logging.info(f"- TEST MODE: Would attach AAEP {vpc['aaep']} to VPC {vpc['name']}")
                continue

            else:
                print(f"  - Attaching AAEP {vpc['aaep']} to VPC {vpc['name']}")
                logging.info(f"- Attaching AAEP {vpc['aaep']} to VPC {vpc['name']}")
                result = dc_apic.set_apic_vpc_aaep(aaep_name=vpc['aaep'], vpc_policy=vpc['name'], debug_level=debug_level)

                if result.status_code == 200:
                    print(f"  - Successfully attached AAEP {vpc['aaep']} to VPC {vpc['name']}")
                    logging.info(f"  - Successfully attached AAEP {vpc['aaep']} to VPC {vpc['name']}")
                else:
                    print(f"  - ERROR: Could not set AAEP {vpc['aaep']} for VPC {vpc['name']}: {result.status_code} {result.reason}")
                    logging.error(f"  - ERROR: Could not set AAEP {vpc['aaep']} for VPC {vpc['name']}: {result.status_code} {result.reason}")


    # MIGRATION STEP: Loop through EPGs and process them.
    #
    # For each EPG in the list, we will:
    # - Extract the VLAN ID from the EPG DN
    # - For each AAEP in the EPG, we will:
    #   - Add or remove the EPG from the AAEP based on the action specified in the AAEP
    #   - Clear ARP entries on the routers for the VLAN subinterface associated with the EPG
    #
    if 'all' in scope or 'epg' in scope:

        print('\n# MIGRATION STEP: Modify EPG to AAEP associations\n')
        logging.info('MIGRATION STEP: Modify EPG to AAEP associations')

        aaep_name_list = []  # List containing all AAEP names
        for epg in parameters_raw['epg_list']:
            for aaep_entry in epg['aaep_list']:
                if aaep_entry['name'] not in aaep_name_list:
                    aaep_name_list.append(aaep_entry['name'])
                    querystring = f"mo/uni/infra/attentp-{aaep_entry['name']}/gen-default.json?query-target=children&target-subtree-class=infraRsFuncToEpg"
                    response = dc_apic.query(querystring)

                    if response.status_code != 200:
                        print(f"ERROR sending {querystring}:")
                        print(f"{response.status_code}: {response.text}")
                    else:
                        epg_response = response.json()['imdata']
                        print(f"  INFO: AAEP {aaep_entry['name']} contains these EPGs {len(epg_response)}:")
                        for epg_query_repsponse in epg_response:
                            print(f"  - {epg_query_repsponse['infraRsFuncToEpg']['attributes']['tDn']}")

        print()
        for epg in parameters_raw['epg_list']:
            # Attach the EPG to the AAEP
            vlan_match = re.search(r'epg-VLAN0*(\d+)_EPG', epg['dn'])
            if not vlan_match:
                print(f"ERROR: Could not extract VLAN ID from EPG DN {epg['dn']}")
                logging.error(f"ERROR: Could not extract VLAN ID from EPG DN {epg['dn']}")
                continue
            vlan_id = int(vlan_match.group(1))

            if 'test' in scope:
                print(f"  - TEST MODE: Would process EPG {epg['dn']} with VLAN ID {vlan_id}")
                logging.info(f"  - TEST MODE: Would process EPG {epg['dn']} with VLAN ID {vlan_id}")
                continue

            else:
                print(f"  - Processing EPG {epg['dn']} with VLAN ID {vlan_id}")
                logging.info(f"  - Processing EPG {epg['dn']} with VLAN ID {vlan_id}")
                aaep_success_list, aaep_fail_list = modify_aaep(dc_apic, epg)
                if aaep_success_list:
                    print(f"   SUCCESS: Setting AAEPs for {epg['dn']}: {aaep_success_list}")
                    logging.info(f"  SUCCESS: Problems setting AAEPs for {epg['dn']}: {aaep_success_list}")

                if aaep_fail_list:
                    print(f"ERROR: Problems setting AAEPs for {epg['dn']}: {aaep_fail_list}")
                    logging.error(f"ERROR: Problems setting AAEPs for {epg['dn']}: {aaep_fail_list}")
                    continue


            # MIGRATION STEP: clear ARP entries on the routers for the VLAN subinterface associated with the EPG
            if 'all' in scope or 'arp' in scope:
                
                command = f"clear arp interface {epg['clear_arp_base_interface']}" + f"{vlan_id}"

                print(f"- Clearing ARP entries for VLAN {vlan_id} on routers: {', '.join([device.address for device in netdevice_list])}")
                logging.info(f"- Clearing ARP entries for VLAN {vlan_id} on routers: {', '.join([device.address for device in netdevice_list])}")
                if 'test' in scope:
                    command = '!' + command  # Prefix the command with '!' to indicate test mode
                    print(f"  TEST mode only - sending {command}")
                if debug_level > 1:
                    print(f"  - Command: {command}")
                    logging.debug(f"  - Command: {command}")
                
                net_result_list = send_command_to_routers(netdevice_list=netdevice_list, command=command, max_workers=max_workers)


                if debug_level > 0:
                    print(f"- ARP clearing results:")
                    logging.debug(f"- ARP clearing results:")
                    for device, result in net_result_list.items():
                        print(f"  NET Device {command} result summary:")
                        print(f"   - {device}:\n {result}")
                        logging.debug(f"   - {device}:\n {result}")
                
            else:
                print(f"- Skipping ARP clearing for VLAN {vlan_id}.")


            print(f"- Finished processing EPG {epg['dn']}.")
            print()
            logging.info(f"- Finished processing EPG {epg['dn']}.")




    # Stop executing
    print("=====================================================")
    print("  FINISHED at: ", datetime.now().strftime("%Y-%m-%d %H:%M:%S"))
    print("=====================================================")




    return locals()  # Return all local variables for debugging purposes
    # sys.exit(0)
 
if __name__ == "__main__":
    # main()

    local_vars = main()
    # code.interact(local=local_vars)
    
