# Crowdsec x Wazuh

This is a translation of the [original article](https://www.aukfood.fr/wazuh-x-crowdsec/) published in French on Aukfood's Blog.

Discover today the integration of CrowdSec with Wazuh.

This integration aims to centralize CrowdSec alerts into a SIEM. In our example, I will use Wazuh to demonstrate the power of open-source.

### Prerequisites
- Crowdsec >= v1.6.3
- Wazuh >= v4.9.0

### CrowdSec Configuration
Let's start by creating the wazuh.yaml file, a file that will contain the notification for sending CrowdSec alerts to the temporary file crowdsec_alerts.json. Choosing a JSON file allows for better interpretation by Wazuh, which eliminates the need to create a decoder.
