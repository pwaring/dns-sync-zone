# Standard library modules
import argparse
import json
import sys

# Local modules
from mythic import MythicAPI
import rfcparser
import zone_validate


class APIError(Exception):
    """Class for exceptions"""

    def __init__(self, command, message):
        self.command = command
        self.message = message


parser = argparse.ArgumentParser()
parser.add_argument(
    "-n",
    "--dry-run",
    help="dry run: check commands but do not perform any actions",
    action="store_false",
    dest="perform_sync",
)
parser.add_argument(
    "-q",
    "--quiet",
    help="don't print anything except for errors",
    action="store_true",
    dest="quiet",
)
parser.add_argument(
    "--include-dangerous-records",
    help="allow modification of all dangerous records",
    action="store_true",
    dest="include_dangerous",
)
parser.add_argument(
    "--strict", help="perform stricter checking", action="store_true"
)
parser.add_argument(
    "--credentials-file", help="path to credentials file", required=True
)
parser.add_argument(
    "--zone", help="name of zone (e.g. example.org)", required=True
)
parser.add_argument("--zone-file", help="path to zone file")
parser.add_argument("--rfc-file", help="path to bind-style zone file")
args = parser.parse_args()

if args.zone_file:
    with open(args.zone_file) as f:
        zone_records = f.read().splitlines()
elif args.rfc_file:
    try:
        with open(args.rfc_file) as f:
            zone = rfcparser.RFCParser(f)
        zone_records = zone.records(
            "ADD", include_dangerous=args.include_dangerous
        )
        if args.zone != zone.domain():
            print("Zonefile origin domain is not for specified zone")
            print(args.zone, "!=", zone.domain())
            sys.exit(1)
    except rfcparser.RFCParserError as err:
        if err.line:
            print(f"Error: {err.message} in {err.line}")
        else:
            print(f"Error: {err.message}")
        sys.exit(1)
else:
    print("No zone file provided.")
    sys.exit(1)

# Validate all new zone records
for zone_record in zone_records:
    if not zone_validate.validate_zone_record(zone_record, args.strict):
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
except KeyError as err:
    print("* Error: {} not in credentials".format(err.args[0]))
    sys.exit(2)

# Get all the existing records
list_response = api.list()
# rstrip needed as Mythic adds a trailing space to the LIST responses
list_records = [l.rstrip() for l in list_response.text.splitlines()]

# Create DELETE [record] commands for all existing records returned by LIST,
# except NS and SOA records
delete_records = []

origins = ["@", args.zone + "."]
for list_record in list_records:
    record_parts = list_record.split()
    record_type = record_parts[2]

    dangerous = False

    if record_type == "SOA":
        # Deleting SOA records may break the zone
        dangerous = True
    elif record_type == "NS" and record_parts[0] in origins:
        # Deleting origin NS records may break the zone
        dangerous = True

    if dangerous and args.include_dangerous:
        print("* Warning: deleting dangerous record:")
        print(list_record)

    if not dangerous or args.include_dangerous:
        delete_records.append(list_record)

delete_commands = []

for delete_record in delete_records:
    delete_commands.append("DELETE " + delete_record)

# Send all the DELETE and new zone entries in one transaction
sync_commands = []
sync_commands.extend(delete_commands)
for zone_record in zone_records:
    if not zone_validate.skip_zone_record(zone_record):
        sync_commands.append(" ".join(zone_record.split()))

if not args.quiet:
    for cmd in sync_commands:
        print(cmd)

if args.perform_sync:
    sync_response = api.call(sync_commands)
    if sync_response.status_code == 200:
        if not args.quiet:
            print(sync_response.text)
        responses = sync_response.text.splitlines()
        # This assumes the API replies in same order as requested
        error = False
        for a, b in zip(sync_commands, responses):
            if a != b:
                print('* Mismatch: "{}" -> "{}"'.format(a, b))
                error = True
        if error:
            sys.exit(1)
    else:
        print("* Error:", sync_response.code, sync_response.reason)
        print(sync_response.text)
        sys.exit(1)
else:
    print("* Dry run: no action taken")
