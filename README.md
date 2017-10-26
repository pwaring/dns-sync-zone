# dns-sync-zone

Python script for syncing zone data with Mythic Beasts primary DNS API service.

This script operates by fetching all the existing zone records, deleting any
which already exist and then adding those specified in a file. This effectively
syncronises the nameserver zone with the one in the file.

## Usage

For help, run `./sync-zone.py -h`, which will print all the options.

Running via `pipenv`:

```
pipenv run python3 -- ./sync-zone.py --credentials-file credentials.json --zone example.org --zone-file zones/example.org
```

You must pass `--` to `pipenv` otherwise it will consume all the arguments
intended for `sync-zone.py`.

## Dependencies

 * Python 3.x (development is done in 3.6.x). Python 2 is intentionally not supported.
 * [Requests](https://requests.readthedocs.io)

## Limitations

This script assumes that you are using the 'Mythic Beasts nameservers only'
template and that the SOA and NS records for the zone already exist. The script
will not allow you to upload new SOA and NS records, nor will it remove any
existing SOA and NS records.

Only a subset of record types are supported at present because the author does
not need the others.
