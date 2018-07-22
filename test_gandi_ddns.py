import requests

import gandi_ddns as script


def test_get_ip():
    assert script.get_ip() == requests.get("http://ipecho.net/plain?").text
