## bitcensus sync

Syncs repo dbs

### Synopsis

Syncs repo dbs

```
bitcensus sync [flags]
```

### Options

```
  -n, --dry-run               do not modify the db and dry run the operation
  -f, --force                 hashes files regardless of file size and modtime heuristic
  -h, --help                  help for sync
  -r, --repo string           repo name (empty means all)
      --rm                    removes deleted files from the db
      --state-db-dir string   state db directory (default is $XDG_DATA_HOME/bitcensus)
```

### Options inherited from parent commands

```
      --config string      config file (default is $XDG_CONFIG_HOME/bitcensus.json)
      --log-json           output json logs
      --log-level string   log level (default "info")
```

### SEE ALSO

* [bitcensus](bitcensus.md)	 - A file system census utility
