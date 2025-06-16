import json
import re
# import urllib3
from netmiko import ConnectHandler

# Settings
# urllib3.disable_warnings()
# pd.set_option("display.max_rows", None, "display.max_columns", None)

class netdevice:
    '''
    This class serves to connect to Cisco NXOS (default) or IOS devices using Netmiko.
    
    '''
    def __init__(self, address, username, password, hostname=None, last_result = None, device_type='cisco_ios', logdir = '.', debug_level=0):
        _addr_port=address.split(':',1)
        if len(_addr_port) == 1:
            self.address = _addr_port[0]
            self.port = 22 # Use SSH default port if not specified in IP address.

        elif len(_addr_port) == 2:
            self.address = _addr_port[0]
            self.port = int(_addr_port[1])
            
        else:
            print(f'ERROR - Could not parse address and port from {address} ')
            self.address = address
            self.port = 22 
        self.username = username
        self.password = password
        self.hostname = hostname
        self.last_result = last_result
        self.device_type = device_type
        self.logdir = logdir
        #
        self.debug_level = debug_level
        
        if self.debug_level >1:
            print (f'Init device {self.address}:{self.port}')       
        if self.debug_level >0:
            print(f'Created a new device with ip {self.address} - type {self.device_type}')
        
            
    def connect(self):
        '''
        Connects to the device using Netmiko
        '''
        device = {
            'device_type': self.device_type,
            'host': self.address,
            'username': self.username,
            'password': self.password,
            'port': self.port,
            'session_log': f"{self.logdir}/netmiko-log_{self.address}.log"
        }
        if self.debug_level > 1:
            print('Connecting to device {}'.format(self.address))
        self.net_session = ConnectHandler(**device)
        try:
            prompt = self.net_session.find_prompt()
            hostname = re.sub(r"[#>].*$",'',prompt)
            self.hostname = hostname
            self.is_connected = True
            self.last_result = f'Connected to {self.address} as {self.username} ({self.hostname})'

        except Exception as con_exception:
            print(f"ERROR: Failed to connect to {self.host}:")
            print(f"{con_exception}")
            self.is_connected = False
            self.last_result = None
            sys.exit()
            
        if self.debug_level > 0:
            print(f'Connected to device {self.hostname} ({self.address})')
        return self
          
    def send(self,command):
        '''
        Send non-config commands to device using Netmiko
        '''
        if self.debug_level >1:
            print (f'Received command "{command}"')
        if self.net_session:
            result = self.net_session.send_command(command)
            self.last_result = result
        else:
            print('Connect to the device using commannd "device.connect()" first.')
            result = None
        return result
    
        
    def logout(self):
        '''
        Logout from the device
        '''
        if self.net_session:
            result = self.net_session.disconnect()
            if self.debug_level > 0:
                print (f'Disconnecting from {self.address} done.')
        else:
            print('Not connected.')
            result = None
        return result
     
    
    def configure(self, config_set):
        '''
        Send configuration command set (a list object) to device using Netmiko
        '''
        if self.debug_level > 0:
            print (f'Configuring device {self.address}.\n commands {config_set}')
        result = self.net_session.send_config_set(config_set)
        self.last_result = result
        if self.debug_level > 1:
            print(result)
        return result
    
    
    def save(self):
        '''
        Save config on the device
        '''
        if self.debug_level > 0:
            print (f'Saving config on device {self.address}.')
        result = self.net_session.save_config()
        if self.debug_level > 1:
            print(result)
        return result
    
    
