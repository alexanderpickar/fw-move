import requests
import json


# Disable warnings
class apic:
    '''
    This class serves to connect to Cisco APIC controller using REST API.
    Methods:
    - login: login to APIC
    - refresh: refresh APIC login
    - send_xml_payload: send XML payload to APIC
    - send_uni_payload: send JSON payload to APIC
    - query: send query to APIC
    - backup: create a local backup on the APIC
    - endpoint_query: query endpoint by IP address
    - endpoint_query_ip: query endpoint by IP address
    - endpoint_query_mac: query endpoint by MAC address
    - set_bd_routing: enable or disable unicast routing on ACI bridge domain
    - query_bd_routing: query unicast routing status on ACI bridge domain
'''
    def __init__(self, address, username, password, debug_level=0):
        self.address = address
        self.username = username
        self.password = password
        self.debug_level = debug_level
        self.last_post_result = None
        self.last_query = None
        self.last_query_result = None
        self.last_payload = None
        self.last_endpoint = None
        self.token = self.login(address, username, password)

    def login(self, address, username, password):
        """
        Login into APIC using REST API, return token to be used in subsequent operations.
        :param apic_ip: APIC IP address
        :param username: Username to log into APIC
        :param password: Password to log into APIC
        :return: Token to be used in following REST calls
                 using cookie 'APIC-Cookie'.
        """
        headers = {"Cache-Control": "no-cache"}
        url = "https://{}/api/aaaLogin.json".format(address)
        payload_login = (f'{{"aaaUser":{{"attributes":{{"name": "{username}", "pwd": "{password}"}} }} }}')
        if self.debug_level > 1:
            print(f"DEBUG: Sending login request\n\
        - Username: {username}, pwd: {len(password)*'*'}\n")
        response = requests.request(
            "POST", url, data=payload_login, headers=headers, verify=False
        )
        jresponse = json.loads(response.text)
        if response.status_code == 200:
            self.token = jresponse["imdata"][0]["aaaLogin"]["attributes"]["token"]
            if self.debug_level > 0:
                print(
                    f"Logged to apic {self.address} \
                        with status {response.status_code}"
                )
            if self.debug_level > 1:
                print("Received token {0}".format(self.token))
        else:
            print(
                'Failed with message "{}"'.format(
                    jresponse["imdata"][0]["error"]["attributes"]["text"]
                )
            )
            self.token = None
        return self.token

    def refresh(self):
        #         https://apic-ip-address/api/aaaLogin.json
        cookies = {}
        cookies["APIC-Cookie"] = self.token
        headers = {"Cache-Control": "no-cache"}
        url = f"https://{self.address}/api/aaaRefresh.json"
        #
        query_response = requests.request(
            "GET", url, headers=headers, verify=False, cookies=cookies
        )
        if self.debug_level > 2:
            print(f"Sending APIC login refresh:\n{url}")
        if self.debug_level > 1:
            print(
                f"GET Login refresh result:\n\
                    {json.dumps(json.loads(query_response.text), indent=2)}"
            )
        #
        # self.last_query_result = query_response
        return query_response

    def send_xml_payload(self, payload, debug_level=1):
        """
        Takes XML payload  together with a valid token and sends it to APIC.
        :param payload: payload in XML format
        :param token: A valid APIC authentication token
        :param apic_ip: APIC IP address
        :return: relevant POST response
        """
        self.last_payload = payload
        cookies = {}
        cookies["APIC-Cookie"] = self.token
        url = f"https://{self.address}/api/mo/uni.xml"
        headers = {"Cache-Control": "no-cache"}
        if self.debug_level > 1:
            print(f"Sending payload to APIC {self.address}")
            print(f"{payload}")
        post_response = requests.request(
            "POST", url, data=payload, headers=headers,
            verify=False, cookies=cookies
        )
        if self.debug_level > 1:
            print(f"POST Result:\n{post_response.text}")

        self.last_post_result = post_response
        return post_response

    def send_uni_payload(self, payload_json, debug_level=1):
        """
        Takes payload in JSON format together with a valid token
        and sends it to APIC.
        :param payload_json: ACI configuration in JSON format
        :param token: A valid APIC authentication token
        :param apic_ip: APIC IP address
        :return: relevant POST response
        """
        self.last_payload = payload_json
        cookies = {}
        cookies["APIC-Cookie"] = self.token
        url = f"https://{self.address}/api/node/mo/uni.json"
        headers = {"Cache-Control": "no-cache"}
        payload = json.dumps(payload_json)
        if self.debug_level > 1:
            print(f"Sending payload to APIC {self.address}")
            print(f"{payload}")
        post_response = requests.request(
            "POST", url, data=payload, headers=headers,
            verify=False, cookies=cookies
        )
        if self.debug_level > 1:
            print(f"POST Result:\n{post_response.text}")

        self.last_post_result = post_response
        return post_response

    def query(self, querystring, debug_level=1):
        """
        Sends query to the APIC url "https://{{URL}}//api/node/{{querystring}}"
        """
        querystring = querystring.strip()
        cookies = {}
        cookies["APIC-Cookie"] = self.token
        url = f"https://{self.address}/api/node/{querystring}"
        self.last_query = url
        headers = {"Cache-Control": "no-cache"}
        query_response = requests.request(
            "GET", url, headers=headers, verify=False, cookies=cookies
        )
        if self.debug_level > 2:
            print(f"Sending query:\n{url}")
        if self.debug_level > 1:
            print(f"GET Result:\n{query_response.text}")
        #
        self.last_query_result = query_response
        return query_response

    def backup(self, description="python_triggered_backup"):
        """
        Creates a local backup on the APIC.
        """
        # SAMPLE REST CALL:
        # url: https://10.178.128.88/api/node/mo/uni/fabric/configexp-defaultOneTime.json
        # payload"{\"configExportP\":{\"attributes\":{\"dn\":\"uni/fabric/configexp-defaultOneTime\",\"name\":\"defaultOneTime\",\"snapshot\":\"true\",\"targetDn\":\"\",\"adminSt\":\"triggered\",\"rn\":\"configexp-defaultOneTime\",\"status\":\"created,modified\",\"descr\":\"DESCRIPTION\"},\"children\":[]}}"
        #
        if self.token:
            payload = f'{{"configExportP":{{"attributes":\
            {{"dn":"uni/fabric/configexp-defaultOneTime",\
            "name":"defaultOneTime","snapshot":"true","targetDn":"",\
            "adminSt":"triggered","rn":"configexp-defaultOneTime",\
            "status":"created,modified","descr":"{description}"}},\
            "children":[]}}}}'
            #
            payload_json = json.loads(payload)
            if self.debug_level > 1:
                print(f"Backup payload:\n{payload}")
            if self.debug_level > 0:
                print(f"Backing up APIC {self.address}....")
                response = self.send_uni_payload(payload_json, debug_level=2)
            if self.debug_level > 0:
                print(f"Response received:\n{response.text}")
        else:
            print(f"Could not backup. Authentication token is missing.\n\
            Please try to authenticate on {self.address} first.")
            response = None
        # TODO: send payload to APIC
        #
        return response

    def endpoint_query_ip(self, endpoint_ip, debug_level=0):
        # SAMPLE REST CALL:
        # https://{{URL}}/api/node/class/fvCEp.json?\
        # query-target-filter=and(eq(fvCEp.ip,"172.29.85.10"))

        endpoint_ip = endpoint_ip.strip()
        cookies = {}
        cookies["APIC-Cookie"] = self.token
        url = f'https://{self.address}/api/node/class/fvCEp.json?query-target-filter=and(eq(fvCEp.ip,"{endpoint_ip}"))'
        headers = {"Cache-Control": "no-cache"}
        query_response = requests.request(
            "GET", url, headers=headers, verify=False, cookies=cookies
        )
        if self.debug_level > 2:
            print(f"Sending query:\n{url}")
        if self.debug_level > 1:
            print(f"GET Result:\n{query_response.text}")
        #
        self.last_query_result = query_response
        self.last_endpoint = query_response
        return query_response

    def endpoint_query_mac(self, endpoint_mac, debug_level=0):
        # SAMPLE REST CALL:
        # https://{{URL}}/api/node/class/fvCEp.json?\
        # query-target-filter=and(eq(fvCEp.ip,"172.29.85.10"))

        endpoint_mac = endpoint_mac.strip()
        cookies = {}
        cookies["APIC-Cookie"] = self.token
        url = f'https://{self.address}/api/node/class/fvCEp.json?query-target-filter=and(eq(fvCEp.mac,"{endpoint_mac}"))'
        headers = {"Cache-Control": "no-cache"}
        query_response = requests.request(
            "GET", url, headers=headers, verify=False, cookies=cookies
        )
        if self.debug_level > 2:
            print(f"Sending query:\n{url}")
        if self.debug_level > 1:
            print(f"GET Result:\n{query_response.text}")
        #
        self.last_query_result = query_response
        self.last_endpoint = query_response
        return query_response

    def set_bd_routing(self, tenant, bridge_domain, status):
        """
        Enables or disables unicast routing on ACI tenant bridge domain.
        :param tenant: an existing tenant name
        :param bridge_domain: an existing bridge domain name
        :param status: status of unicast routing
            ("true" - enable routing, "false": - disable routing)
        :return: relevant POST response
        """
        # normalize inputs
        tenant = tenant.strip()
        bridge_domain = bridge_domain.strip()
        if isinstance(status, str):
            status = status.lower()

        # check status values
        if status in [True, "true", "present", "enabled", "enable", "yes"]:
            status = "true"
        elif status in [False, "false", "absent", "disabled", "disable", "no"]:
            status = "false"
        else:
            raise ValueError(
                f"WARNING - could not recognise status value '{status}'. "
                "set status to 'true' or 'false'."
            )

        # send payload
        payload = f'{{"fvBD":{{"attributes":{{"dn":"uni/tn-{tenant}/BD-{bridge_domain}","unicastRoute":"{status}"}}}}}}'
        payload_json = json.loads(payload)
        response = self.send_uni_payload(payload_json)

        return response

    def query_bd_routing(self, tenant, bridge_domain):
        """
        Sends Query about unicast routing to ACI tenant bridge domain.
        :param tenant: an existing tenant name
        :param bridge_domain: an existing bridge domain name

        :return: True if routing is enabled, False if routing is disabled
        """
        # normalize inputs
        tenant = tenant.strip()
        bridge_domain = bridge_domain.strip()

        queryString = f'mo/uni/tn-{tenant}/BD-{bridge_domain}.json'
        response = self.query(queryString)
        response_json = json.loads(response.text)
        unicastRoute = response_json['imdata'][0]['fvBD']['attributes']['unicastRoute']
        if unicastRoute == 'yes':
            return True
        else:
            return False
