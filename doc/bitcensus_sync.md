## bitcensus sync

Syncs repo dbs

### Synopsis

Syncs repo dbs

```
bitcensus sync [flags]
```

### Options

```
  -c, --checksum              hashes files regardless of file size and modtime heuristic
  -n, --dry-run               do not modify the db and dry run the operation
  -h, --help                  help for sync
      --prune                 removes deleted files from the db
  -r, --repo string           repo name (empty means all)
      --state-db-dir string   state db directory (default is $XDG_DATA_HOME/bitcensus)
  -u, --update                updates files in db even if checksum differs
```

### Options inherited from parent commands

```
      --config string      config file (default is $XDG_CONFIG_HOME/bitcensus.json)
      --log-json           output json logs
      --log-level string   log level (default "info")
```

### SEE ALSO

* [bitcensus](bitcensus.md)	 - A file system census utility

