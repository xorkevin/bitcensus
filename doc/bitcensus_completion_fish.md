## bitcensus completion fish

Generate the autocompletion script for fish

### Synopsis

Generate the autocompletion script for the fish shell.

To load completions in your current shell session:

	bitcensus completion fish | source

To load completions for every new session, execute once:

	bitcensus completion fish > ~/.config/fish/completions/bitcensus.fish

You will need to start a new shell for this setup to take effect.


```
bitcensus completion fish [flags]
```

### Options

```
  -h, --help              help for fish
      --no-descriptions   disable completion descriptions
```

### Options inherited from parent commands

```
      --config string      config file (default is $XDG_CONFIG_HOME/bitcensus.json)
      --log-json           output json logs
      --log-level string   log level (default "info")
```

### SEE ALSO

* [bitcensus completion](bitcensus_completion.md)	 - Generate the autocompletion script for the specified shell

