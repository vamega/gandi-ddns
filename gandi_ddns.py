#!/usr/bin/env python
"""
Python Dynamic DNS script for Gandi LiveDNS
"""

import ipaddress
import json
import logging
import os
import sys

import requests
import yaml
import structlog
from systemd.journal import JournalHandler

LOGGER = logging.getLogger("gandi_ddns")
CONFIG_FILE = "config.yaml"
SCRIPT_DIR = os.path.dirname(os.path.realpath(__file__))


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
        LOGGER.critical(
            "IP Address service response could not be identified as an IP address.",
            extra={"STATUS_CODE": resp.status_code, "RESPONSE": resp.text},
            exc_info=True,
        )
        # TODO: Raise error instead of exiting here.
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


def configure_logging():
    """
    """
    # JOURNAL_HANDLER = JournalHandler()
    # JOURNAL_HANDLER.setFormatter(logging.Formatter("%(message)s"))
    # LOGGER.addHandler(JOURNAL_HANDLER)
    # LOGGER.setLevel(logging.DEBUG)

    timestamper = structlog.processors.TimeStamper(fmt="%Y-%m-%d %H:%M:%S")
    pre_chain = [
        structlog.stdlib.filter_by_level,
        structlog.stdlib.add_log_level,
        structlog.stdlib.add_logger_name,
        structlog.stdlib.PositionalArgumentsFormatter(),
        structlog.processors.StackInfoRenderer(),
        structlog.processors.format_exc_info,
        structlog.processors.UnicodeDecoder(),
        structlog.stdlib.render_to_log_kwargs,
        timestamper,
    ]

    logging.config.dictConfig({
            "version": 1,
            "disable_existing_loggers": False,
            "formatters": {
                "plain": {
                    "()": structlog.stdlib.ProcessorFormatter,
                    "processor": structlog.dev.ConsoleRenderer(colors=False),
                    "foreign_pre_chain": pre_chain,
                },
                "colored": {
                    "()": structlog.stdlib.ProcessorFormatter,
                    "processor": structlog.dev.ConsoleRenderer(colors=True),
                    "foreign_pre_chain": pre_chain,
                },
            },
            "handlers": {
                "default": {
                    "level": "DEBUG",
                    "class": "logging.StreamHandler",
                    "formatter": "colored",
                },
                "file": {
                    "level": "DEBUG",
                    "class": "logging.handlers.WatchedFileHandler",
                    "filename": "test.log",
                    "formatter": "plain",
                },
            },
            "loggers": {
                "": {
                    "handlers": ["default", "file"],
                    "level": "DEBUG",
                    "propagate": True,
                },
            }
    })

    structlog.configure(
        processors=shared_processors + [
            structlog.stdlib.ProcessorFormatter.wrap_for_formatter,
        ],
        logger_factory=structlog.stdlib.LoggerFactory(),
        cache_logger_on_first_use=True,
    )

    formatter = structlog.stdlib.ProcessorFormatter(
        processor=structlog.dev.ConsoleRenderer(),
        foreign_pre_chain=shared_processors,
    )


def main():
    """
    Main entry point.
    """
    path = CONFIG_FILE
    if not path.startswith("/"):
        path = os.path.join(SCRIPT_DIR, path)

    with open(path, "r") as config_file:
        config = yaml.safe_load(config_file)

    if not config:
        sys.exit("Please fill in the 'config.txt' file.")

    config_defaults = config["defaults"]
    defaults = {
        "api": config_defaults["api"],
        "apikey": config_defaults["apikey"],
        "ttl": config_defaults["ttl"],
    }

    for domain_key, domain_config in config["domains"].items():
        # LOGGER.info("%s - section %s" % (str(datetime.now()), section))

        overlaid_config = defaults.copy()
        overlaid_config.update(domain_config)

        headers = {
            "Content-Type": "application/json",
            "X-Api-Key": overlaid_config["apikey"],
        }

        # Set URL
        url = "%sdomains/%s/records/%s/A" % (
            overlaid_config["api"],
            overlaid_config["domain"],
            overlaid_config["a_name"],
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

        payload = {"rrset_ttl": overlaid_config["ttl"], "rrset_values": [external_ip]}
        update_record(url, headers, payload)


if __name__ == "__main__":
    main()
