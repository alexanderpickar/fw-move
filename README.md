# fw-move
CSOB firewall move script

- init connection to network devices (usually core routers)
- inint connection to the APIC controller

- change AAEP on VPC interface
- add/remove EPG inside of an AAEP
- clear arp of the corresponding interface on the core routers


parameters are taken from a YAML file.


SAMPLE parameters.yaml file:

---
# This is a FW Move parameters file.
#
# We need following parameters:
# - APIC IP address
# - L3 switch list
# - list of EPGS and AAEPs for migration
# - each EPG should have:
#   - EPG DN
#   - IOS base interface
#   - list of AAEPs to add
#   - list of AAEPs to remove
# - list of routers for clearing ARP entries from the base interface

routers:
  - ip: 10.178.128.2
  - ip: 10.178.128.3
  - ip: 10.178.128.4
  

apic:
  ip: 10.178.130.130

vpc_list:
# VPC list containting VPC names and AAEP names to be set.
  - name: APICKAR_VPC001_VPC
    # aaep: CZDC_Empty_AAEP
    aaep: CZDC_TELCO_FW-OLD_AAEP
  - name: APICKAR_VPC002_VPC
    # aaep: CZDC_Empty_AAEP
    aaep: CZDC_TELCO_FW-OLD_AAEP

epg_list:
  - dn: uni/tn-CZDC_TDA/ap-tste/epg-VLAN2913_EPG
    clear_arp_base_interface: vlan 
    # Base interface = network device interface.
    # we will clear arp on {base_interface}.{vlan_id}
    # example full interface is Hu1/0/5.2913


    aaep_list:
    - name: CZDC_TELCO_FW-OLD_AAEP
      action: remove
    - name: CZDC_TELCO_DCFW-PROD_AAEP
      action: add

