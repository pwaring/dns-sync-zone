# External modules
import requests


class APIError(Exception):
    """Class for exceptions"""

    def __init__(self, command, message):
        self.command = command
        self.message = message


class MythicAPI(object):
    """Class abstracting Mythic Beasts' Primary DNS API"""

    def __init__(self, domain, password):
        self.valid = True
        self.payload = {
            "domain": domain,
            "password": password,
            "command": None,
        }
        self.uri = "https://dnsapi.mythic-beasts.com/"
        response = self.call("LIST")
        if response.text.startswith("ERR "):
            error = response.text[4:].strip()
            self.valid = False
            raise APIError("LIST", error)
        else:
            self._list = response

    def check_valid(self, command=""):
        if not self.valid:
            raise APIError(command, "Operation on invalid API access")

    def list(self):
        self.check_valid()
        return self._list

    def call(self, commands):
        self.check_valid()
        self.payload["command"] = commands
        return requests.post(self.uri, data=self.payload)
