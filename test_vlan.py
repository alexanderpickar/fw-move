#! python

# This is for tests helping by move_vlan.py development
#


import concurrent.futures as cf
import argparse
import time
from netmiko import ConnectHandler
import datetime
import os
import re
import sys
import yaml


file = './vars/move_vlans2.yml'
fullfile = os.path.join(os.path.curdir,os.path.normpath(file))
filename = os.path.abspath(fullfile)
print('')
print(f"Opening file {filename}.")

try:
    with open(filename,'r') as f:
        params = yaml.load(f, Loader=yaml.FullLoader)
except Exception as e:
    print(f"ERROR: Could not read device move file {filename} ")
    print(e)
print(f"Got these device parameters:\n{params['devices']}\n")

mydevices = {}
for device in params['devices']:
    print(f"Found device {device}")
    device_ip = device['ip']
    if device_ip not in mydevices: # initialize a new device
        mydevices[device_ip] = {}
        mydevices[device_ip]['interfaces_add'] = []
        mydevices[device_ip]['interfaces_remove'] = []
        mydevices[device_ip]['clear_mac'] = False
    #
    if 'interfaces_add' in device.keys(): 
        if not isinstance(device['interfaces_add'], list): device['interfaces_add'] = [device['interfaces_add']]
        mydevices[device_ip]['interfaces_add'] += device['interfaces_add']
        mydevices[device_ip]['interfaces_add'] = list(dict.fromkeys(mydevices[device_ip]['interfaces_add']))

    if 'interfaces_remove' in device.keys(): 
        if not isinstance(device['interfaces_remove'], list): device['interfaces_remove'] = [device['interfaces_remove']]
        mydevices[device_ip]['interfaces_remove'] += device['interfaces_remove']
        mydevices[device_ip]['interfaces_remove'] = list(dict.fromkeys(mydevices[device_ip]['interfaces_remove']))
    
    if 'clear_mac' in device.keys():
        mydevices[device_ip]['clear_mac'] = device['clear_mac'] # Last value counts !


print(f'My devices:')
for dev_ip,parameters in mydevices.items():
    print(f"Device {dev_ip}:")
    for key,value in parameters.items():
        print(f"- {key}: {value}")
# for my_ip,details in mydevices.items():
#     print(f"{my_ip} - {details}")