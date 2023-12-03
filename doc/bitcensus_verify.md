## bitcensus verify

Verifies files

### Synopsis

Verifies files

```
bitcensus verify [flags]
```

### Options

```
  -b, --before string         age of files to verify ("now" will verify all) (default "168h")
  -f, --force                 hashes files regardless of file size and modtime heuristic
  -h, --help                  help for verify
  -r, --repo string           repo name (empty means all)
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

