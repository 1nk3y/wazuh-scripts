# AbuseIPDB Integration for Wazuh

Custom integration script that will identify a non-private IP address and check AbuseIPDB fo

## Description

An in-depth paragraph about your project and overview of use.

### Dependencies

Requires an API key from abuseipdb.com

### Installing

1. Add "custom-adbuseipdb.py" to "/var/ossec/integrations/"
2. Change permissions and ownership on "custom-abuseipdb.py" 
```
cd /var/ossec/integrations
chmod 750 custom-abuseipdb.py
chown root:wazuh custom-abuseipdb.py
```
3. Add the integration block in "ossec.conf" to the Wazuh Manager global configuration with API key.
4. Create a new rule on the Wazuh Manager: Management > Rules
 - The example rule "110001-abuseipdb.xml" will trigger on "Rule ID: 2502 - User missed the password more than one time"
5. Restart Wazuh Manager
```
sudo systemctl restart wazuh-manager
```