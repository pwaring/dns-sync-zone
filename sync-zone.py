# Standard library modules
import argparse
import json

# External modules
import requests

parser = argparse.ArgumentParser()
parser.add_argument('--credentials-file', help='path to credentials file', required=True)
parser.add_argument('--zone', help='name of zone (e.g. example.org)', required=True)
parser.add_argument('--zone-file', help='path to zone file', required=True)
args = parser.parse_args()

with open(args.credentials_file) as f:
    credentials = json.load(f)

with open(args.zone_file) as f:
    zone_records = f.read()

base_payload = {
  'domain': args.zone,
  'password': credentials[args.zone],
  'command': ''
}

api_uri = 'https://dnsapi.mythic-beasts.com/'

# Get all the existing records
list_payload = base_payload
list_payload['command'] = 'LIST'

list_response = requests.post(api_uri, data = list_payload)
list_records = list_response.text.splitlines()

# Create DELETE [record] commands for all existing records returned by LIST,
# except NS records
delete_records = []

for list_record in list_records:
    record_parts = list_record.split()

    if record_parts[2] != 'NS':
        delete_records.append(list_record)

delete_commands = []

for delete_record in delete_records:
    delete_commands.append('DELETE ' + delete_record)

# Send all the DELETE and new zone entries in one transaction
sync_commands = delete_commands
for zone_record in zone_records.splitlines():
    sync_commands.append(zone_record)

print(sync_commands)

sync_payload = base_payload
sync_payload['command'] = sync_commands
sync_response = requests.post(api_uri, data = sync_payload)

print(sync_response.text)
