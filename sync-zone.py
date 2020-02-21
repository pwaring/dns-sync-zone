# Standard library modules
import argparse
import json
import sys

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
            "domain": args.zone,
            "password": credentials[args.zone],
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


def skip_zone_record(zone_record):
    """Whether a zone record should be skipped or not.

    Records are skipped if they are empty or start with
    a # (indicating a comment).

    :param zone_record: Full zone record, including the command (e.g. ADD).
    :returns: True if the record should be skipped, false otherwise.
    """
    zone_record = zone_record.strip()

    return not zone_record or zone_record[:1] == "#"


def validate_zone_record(zone_record):
    """Validate a zone record.

    This validation is not exhaustive and may allow some invalid
    records through (false positive) or reject valid records (false
    negative). It is mainly intended to catch common errors, although
    in time it will be expanded.

    :param zone_record: Full zone record, including the command (e.g. ADD).
    :returns: True if the record appears valid, false otherwise.
    """
    valid_commands = ["ADD", "DELETE", "REPLACE"]

    # Only a subset of all valid types are supported
    valid_types_basic = ["A", "CNAME", "AAAA", "ANAME"]
    valid_types_extra = ["MX", "TXT"]

    if skip_zone_record(zone_record):
        return True
    else:
        # Looks like an actual record
        zone_record = zone_record.strip()
        zone_record_parts = zone_record.split()

        if len(zone_record_parts) >= 5:
            # First four fields are the same for all records
            record_command = zone_record_parts[0]
            record_hostname = zone_record_parts[1]
            record_ttl = zone_record_parts[2]
            record_type = zone_record_parts[3]

            # Command, TTL and type are required for all records
            if (
                record_command in valid_commands
                and record_ttl.isdigit()
                and (
                    record_type in valid_types_basic
                    or record_type in valid_types_extra
                )
            ):
                if len(zone_record_parts) == 5:
                    # Looks like a standard record type
                    record_data = zone_record_parts[4]

                    if (
                        record_type in valid_types_basic
                        or record_type == "TXT"
                    ):
                        return True
                elif len(zone_record_parts) == 6 and record_type == "MX":
                    record_priority = zone_record_parts[4]
                    record_data = zone_record_parts[5]

                    if record_priority.isdigit():
                        return True
                elif len(zone_record_parts) >= 5 and record_type == "TXT":
                    record_data = zone_record_parts[4:]
                    return True

    return False


parser = argparse.ArgumentParser()
parser.add_argument(
    "-n",
    "--dry-run",
    help="dry run: check commands but do not perform any actions",
    action="store_false",
    dest="perform_sync",
)
parser.add_argument(
    "--credentials-file", help="path to credentials file", required=True
)
parser.add_argument(
    "--zone", help="name of zone (e.g. example.org)", required=True
)
parser.add_argument("--zone-file", help="path to zone file", required=True)
args = parser.parse_args()

with open(args.zone_file) as f:
    zone_records = f.read()

# Validate all new zone records
for zone_record in zone_records.splitlines():
    if not validate_zone_record(zone_record):
        print("The following record failed validation:")
        print(zone_record)
        sys.exit(1)

with open(args.credentials_file) as f:
    credentials = json.load(f)

try:
    api = MythicAPI(args.zone, credentials[args.zone])
except APIError as err:
    print("* Error: {}".format(err.message))
    sys.exit(2)

# Get all the existing records
list_response = api.list()
list_records = list_response.text.splitlines()

# Create DELETE [record] commands for all existing records returned by LIST,
# except NS records
delete_records = []

for list_record in list_records:
    record_parts = list_record.split()
    record_type = record_parts[2]

    # Do not delete NS or SOA records as this may break the zone
    if record_type != "NS" and record_type != "SOA":
        delete_records.append(list_record)

delete_commands = []

for delete_record in delete_records:
    delete_commands.append("DELETE " + delete_record)

# Send all the DELETE and new zone entries in one transaction
sync_commands = delete_commands
for zone_record in zone_records.splitlines():
    if not skip_zone_record(zone_record):
        sync_commands.append(" ".join(zone_record.split()))

for cmd in sync_commands:
    print(cmd)

if args.perform_sync:
    sync_response = api.call(sync_commands)
    print(sync_response.text)
else:
    print("* Dry run: no action taken")
