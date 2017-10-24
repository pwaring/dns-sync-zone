# dns-sync-zone

Python script for syncing zone data with Mythic Beasts primary DNS API service.

This script operates by fetching all the existing zone records, deleting any
which already exist and then adding those specified in a file. This effectively
syncronises the nameserver zone with the one in the file.

Running via `pipenv`:

```
pipenv run python3 -- ./sync-zone.py --credentials-file credentials.json --zone example.org --zone-file zones/example.org
```

You must pass `--` to `pipenv` otherwise it will consume all the arguments
intended for `sync-zone.py`.

## Dependencies

 * Python 3.x (development is done in 3.6.x). Python 2 is not and will not be supported.
 * [Requests](https://requests.readthedocs.io)
