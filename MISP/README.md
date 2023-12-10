# MISP Integration for Wazuh

## Description

Custom integration script that queries MISP for matches and generates an alert in Wazuh if there's a match. Currently MD5 hashes only.

MISP - Malware Information Sharing Platform
https://www.misp-project.org/

### Dependencies

Requires an API key from your MISP instance.

### Installing

1. Add "custom-misp.py" to "/var/ossec/integrations/"
2. Change permissions and ownership on "custom-misp.py" 
```
cd /var/ossec/integrations
chmod 750 custom-misp.py
chown root:wazuh custom-misp.py
```
3. Add the integration block in "ossec.conf" to the Wazuh Manager global configuration with API key.
4. Create a new rule on the Wazuh Manager: Management > Rules
 - The example rule "110050-misp.xml" will trigger on "syscheck" events.
5. Restart Wazuh Manager
```
sudo systemctl restart wazuh-manager
```

### Development
Furture iterations to include lookups for:
- IP Adressess
- Domains
- Filenames
- Text