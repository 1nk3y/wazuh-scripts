#!/var/ossec/framework/python/bin/python3
import os
import sys
import json
import time
import requests
from socket import socket, AF_UNIX, SOCK_DGRAM

# Exit error codes
ERR_NO_REQUEST_MODULE = 1
ERR_BAD_ARGUMENTS = 2
ERR_BAD_MD5_SUM = 3
ERR_NO_RESPONSE_VT = 4
ERR_SOCKET_OPERATION = 5
ERR_FILE_NOT_FOUND = 6
ERR_INVALID_JSON = 7

# Constants
ALERT_INDEX = 1
APIKEY_INDEX = 2

# Global variables
DEBUG_ENABLED = True
PWD = os.path.dirname(os.path.dirname(os.path.realpath(__file__)))
SOCKET_ADDR = f"{PWD}/queue/sockets/queue"
LOG_FILE = f"{PWD}/logs/integrations.log"
NOW = time.strftime("%a %b %d %H:%M:%S %Z %Y")
API_KEY = sys.argv[2]
URL = sys.argv[3]

def main(args):
    # Read incoming alert
    incoming_alert = args[1]

    # Load wazuh alert
    wazuh_alert = get_json_alert(incoming_alert)

    process_args(args, wazuh_alert)

# Core function creates a message with valid fields
def process_args(args, wazuh_alert):
    alert_file_location = args[ALERT_INDEX]
    apikey = args[APIKEY_INDEX]

    json_alert = get_json_alert(alert_file_location)

    msg = request_misp_info(json_alert, apikey)

    if not msg:
        debug("# Error: Empty message")
        raise Exception

    send_msg(msg, json_alert)

# Write messages to LOG_FILE if DEBUG_ENABLED = True
def debug(debug_message):
    if DEBUG_ENABLED:
        debug_message = f"{NOW}: {debug_message}"
        print(debug_message)

        with open(LOG_FILE, "a") as file:
            file.write(debug_message + '\n')

# Query MISP and build alert object 
def request_misp_info(alert, apikey):
    alert_output = {"misp": {}, "integration": "misp"}

    if "syscheck" not in alert or "md5_after" not in alert["syscheck"]:
        debug("# No syscheck block or md5 checksum present in the alert")
        return None

    misp_response_data = query_api(alert["syscheck"]["md5_after"], apikey)

    alert_output["misp"]["event_id"] = misp_response_data["response"]["Attribute"][0]["event_id"]
    alert_output["misp"]["category"] = misp_response_data["response"]["Attribute"][0]["category"]
    alert_output["misp"]["value"] = misp_response_data["response"]["Attribute"][0]["value"]
    alert_output["misp"]["type"] = misp_response_data["response"]["Attribute"][0]["type"]
    alert_output["misp"]["event_id"] = misp_response_data["response"]["Attribute"][0]["Event"]["id"]
    alert_output["misp"]["event_info"] = misp_response_data["response"]["Attribute"][0]["Event"]["info"]

    return alert_output

# Build API query
def query_api(hash, apikey):
    params = f"value:{hash}"
    headers = {"Accept": "application/json", "Content-Type": "application/json", "Authorization": f"{apikey}"}
    hookurl = URL
    query_url = '/'.join([hookurl, params])

    response = requests.get(query_url, headers=headers, verify=False)

    if response.status_code == 200:
        json_response = response.json()
        misp_response_data = json_response
        return misp_response_data
    else:
        alert_output = {"misp": {}, "integration": "misp"}

        if response.status_code == 204:
            alert_output["misp"]["error"] = response.status_code
            alert_output["misp"]["description"] = "Error: Public API request rate limit reached"
            alert_output["misp"]["integration"] = "MISP"
            send_msg(alert_output)
            raise Exception("# Error: MISP Public API request rate limit reached")
        elif response.status_code == 403:
            alert_output["misp"]["error"] = response.status_code
            alert_output["misp"]["description"] = "Error: Check credentials"
            alert_output["misp"]["integration"] = "MISP"
            send_msg(alert_output)
            raise Exception("# Error: MISP credentials, required privileges error")
        else:
            alert_output["misp"]["error"] = response.status_code
            alert_output["misp"]["description"] = "Error: API request fail"
            alert_output["misp"]["integration"] = "MISP"
            send_msg(alert_output)
            raise Exception("# Error: MISP credentials, required privileges error")

# Send MISP alert to wazuh-manager
def send_msg(msg, json_alert):
    agent_id = json_alert["agent"]["id"]
    agent_name = json_alert["agent"]["name"]
    agent_ip = json_alert["agent"]["ip"]

    if agent_id == "000":
        string = '1:misp:{0}'.format(json.dumps(msg))
    else:
        string = f'1:[{agent_id}] ({agent_name}) {agent_ip}->misp:{json.dumps(msg)}'

    try:
        sock = socket(AF_UNIX, SOCK_DGRAM)
        sock.connect(SOCKET_ADDR)
        sock.send(string.encode())
        sock.close()
        debug(string)
    except FileNotFoundError:
        debug("# Error: Unable to open socket connection at %s" % SOCKET_ADDR)
        sys.exit(ERR_SOCKET_OPERATION)

# Load json alert from sys.argv[1]
def get_json_alert(file_location):
    try:
        with open(file_location) as alert_file:
            return json.load(alert_file)
    except FileNotFoundError:
        debug("# JSON file for alert %s doesn't exist" % file_location)
        sys.exit(ERR_FILE_NOT_FOUND)
    except json.decoder.JSONDecodeError as e:
        debug("Failed getting JSON alert. Error: %s" % e)
        sys.exit(ERR_INVALID_JSON)

# Execute main()
if __name__ == "__main__":
    main(sys.argv)
