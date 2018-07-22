"""
Python Dynamic DNS script for Gandi LiveDNS
"""

import configparser
import ipaddress
import json
import logging
import os
import sys

import requests
from systemd.journal import JournalHandler

LOGGER = logging.getLogger("gandi_ddns")
CONFIG_FILE = "config.txt"
SCRIPT_DIR = os.path.dirname(os.path.realpath(__file__))
JOURNAL_HANDLER = JournalHandler()

# Could be any service that just gives us a simple raw ASCII IP address (not HTML etc)
EXTERNAL_IP_URL = "https://api.ipify.org"


def get_ip():
    """
    Retuns the external ip address of the machine.
    """
    try:
        resp = requests.get(EXTERNAL_IP_URL, timeout=3)
    except Exception:
        LOGGER.critical("Failed to retrieve external IP.", exc_info=True)
        sys.exit(2)
    if resp.status_code != 200:
        LOGGER.critical(
            "Failed to retrieve external IP. Invalid status code in response.",
            extra={"STATUS_CODE": resp.status_code},
            exc_info=True,
        )
        sys.exit(2)

    ip_addr = resp.text.rstrip()  # strip \n and any trailing whitespace
    if not ipaddress.IPv4Address(ip_addr):  # check if valid IPv4 address
        sys.exit(2)

    return ip_addr


def update_record(url, headers, payload):
    """
    Updates a record
    """
    resp = requests.put(url, headers=headers, json=payload)
    if resp.status_code != 201:
        LOGGER.critical(
            "Record update failed",
            extra={"STATUS_CODE": resp.status_code, "RESPONSE_TEXT": resp.text},
        )
        sys.exit(2)
    LOGGER.info("DNS record updated.")
    return resp


def main():
    """
    Main entry point.
    """
    path = CONFIG_FILE
    if not path.startswith("/"):
        path = os.path.join(SCRIPT_DIR, path)

    config = configparser.ConfigParser()
    config.read(path)

    if not config:
        sys.exit("Please fill in the 'config.txt' file.")

    for section in config.sections():
        # LOGGER.info("%s - section %s" % (str(datetime.now()), section))

        apikey = config.get(section, "apikey")
        headers = {"Content-Type": "application/json", "X-Api-Key": apikey}

        # Set URL
        url = "%sdomains/%s/records/%s/A" % (
            config.get(section, "api"),
            config.get(section, "domain"),
            config.get(section, "a_name"),
        )
        LOGGER.debug("API Endpoint", extra={"URL": url})

        # Discover External IP
        external_ip = get_ip()
        LOGGER.debug("Got external IP", extra={"EXTERNAL_IP": external_ip})

        # Check current record
        record = requests.get(url, headers=headers)

        if record.status_code == 200:
            dns_value = json.loads(record.text)["rrset_values"][0]
            LOGGER.info("Current DNS record", extra={"RECORD_VALUE": dns_value})
            if dns_value == external_ip:
                LOGGER.info("No change in IP address.")
                continue
        else:
            LOGGER.warning("No existing record.")

        payload = {
            "rrset_ttl": config.get(section, "ttl"),
            "rrset_values": [external_ip],
        }
        update_record(url, headers, payload)


if __name__ == "__main__":
    main()
