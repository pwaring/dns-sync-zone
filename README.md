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

## Contributions

Contributions are welcome using the following mechanisms:

 * Bug fixes: Fork the repository, make your changes and then open a pull request.
 * New features: Open an issue with the rough details of the proposed new feature.

This script is intended to be very specific and have a limited use case. If you
are thinking about adding new functionality, please open an issue first outlining
the changes you are proposing so that you don't spend a lot of time developing
a feature which may never be merged.

If you want to substantially expand on this script, you are welcome and
encouraged to fork the repository.

## Licence

This software is available under the MIT licence, details of which can be found
in the `LICENSE` file.
