#!/var/ossec/framework/python/bin/python3
import os
import sys
import json
import time
import requests
from socket import socket, AF_UNIX, SOCK_DGRAM

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
    with open(incoming_alert) as alert_file:
        wazuh_alert = json.load(alert_file)

    # Request AbuseIPDB info
    aipdb_request = request_abuseipdb_info(wazuh_alert, API_KEY)

    # If match found in AbuseIPDB,
    if aipdb_request:
        aipdb_response = json.loads(aipdb_request)
        # Create alert
        create_alert(aipdb_response, wazuh_alert)

# Write messages to LOG_FILE if DEBUG_ENABLED = True
def debug(debug_message):
    if DEBUG_ENABLED:
        debug_message = f"{NOW}: {debug_message}\n"
        print(debug_message)

        with open(LOG_FILE, "a") as file:
            file.write(debug_message)

# Extract "srcip" to include in API query
def request_abuseipdb_info(wazuh_alert, apikey):
    srcip = wazuh_alert["data"]["srcip"]
    abuseipdb_response = query_api(srcip, apikey)
    return abuseipdb_response

# Construct API query
def query_api(srcip, apikey):
    querystring = {'ipAddress': srcip, 'maxAgeInDays': '90'}
    headers = {'Accept': 'application/json', 'Key': apikey}
    response = requests.get(URL, headers=headers, params=querystring)
    return response.text

# Create alert containing response from AbuseIPdb
def create_alert(abuseipdb_response, wazuh_alert):
    alert_output = {"abuseipdb": {}}

    if check_total_reports(abuseipdb_response):
        data = abuseipdb_response["data"]
        alert_output["abuseipdb"].update({
            "total_reports": data.get("totalReports"),
            "abuse_confidence_score": data.get("abuseConfidenceScore"),
            "country_code": data.get("countryCode"),
            "usage_type": data.get("usageType"),
            "isp": data.get("isp"),
            "domain": data.get("domain"),
            "last_reported_at": data.get("lastReportedAt"),
        })
        # Include integration source and info from wazuh alert
        alert_output["integration"] = "AbuseIPDB"
        alert_output["abuseipdb"]["source"] = {
            "alert_id": wazuh_alert["id"],
            "rule": wazuh_alert["rule"]["id"],
            "description": wazuh_alert["rule"]["description"],
            "full_log": wazuh_alert["full_log"],
            "srcip": wazuh_alert["data"]["srcip"],
        }
        # Send alert data
        send_event(alert_output, wazuh_alert)
    else:
        debug("Error creating alert.")

# Ensure "totalReports" is not 0
def check_total_reports(abuseipdb_response):
    return abuseipdb_response.get("data", {}).get("totalReports", 0) != 0

# Send AbuseIPdb alert to wazuh-manager
def send_event(abuseipdb_response, wazuh_alert, agent=None):
    # If agent ID is 000 or missing
    agent_id = wazuh_alert["agent"]["id"]
    agent_name = wazuh_alert["agent"]["name"]
    agent_ip = wazuh_alert["agent"].get("ip", "any")

    if agent_id == "000":
        # Send alert
        string = f'1:abuseipdb:{json.dumps(abuseipdb_response)}'
    else:
        # Send alert with agent id, name, and ip
        string = f'1:[{agent_id}] ({agent_name}) {agent_ip}->abuseipdb:{json.dumps(abuseipdb_response)}'

    # Write alert data to integrations log
    with open(LOG_FILE, 'a') as file:
        file.write(string)

    # Open socket and send data
    sock = socket(AF_UNIX, SOCK_DGRAM)
    sock.connect(SOCKET_ADDR)
    sock.send(string.encode())
    sock.close()

# Execute main()
if __name__ == "__main__":
    main(sys.argv)