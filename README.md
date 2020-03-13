# dns-sync-zone

Python script for syncing zone data with Mythic Beasts primary DNS API service.

**Disclaimer:** Although this script accesses an API provided by Mythic Beasts,
the owner of this repository is not affiliated with them and this software is
not endorsed by Mythic Beasts Ltd.

This script operates by fetching all the existing zone records, deleting them
and then adding those specified in a file. This effectively synchronises the
nameserver zone with the one in the file. Both the deletions and additions are
performed in a single transaction.

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

## Unit tests and coverage

Unit tests can be run using:

```
python3 -m unittest
```

For a coverage report, install the `coverage` module
(eg. `python3-coverage` in Debian, or `pip3 install coverage`) and
run:

```
python3-coverage run -m unittest
python3-coverage html
```

The command is `coverage` if installed using pip.  HTML output is in
the `htmlcov` directory.

Running via pipenv:

```
pipenv install --dev
pipenv run coverage run -m unittest
pipenv run coverage html
```

## Limitations

This script assumes that you are using the 'Mythic Beasts nameservers only'
template and that the SOA and NS records for the zone already exist. The script
will not allow you to upload new SOA and NS records, nor will it remove any
existing SOA and NS records.

## Support

If you are having trouble using the script, or have run across a bug, please open
an issue on GitHub. This support route is free and provided in the author's
spare time.

Paid support is available directly from the author. Please email them at
paul@phpdeveloper.org.uk for details.

## Contributions

Contributions are welcome using the following mechanisms:

 * Bug fixes: Fork the repository, make your changes and then open a pull request.
 * New features: Open an issue with the rough details of the proposed new feature.

New features are welcome, but opening an issue first allows for discussion and
avoids multiple people working on the same feature.

## Licence

This software is available under the MIT licence, details of which can be found
in the `LICENSE` file.
