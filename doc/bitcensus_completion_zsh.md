## bitcensus completion zsh

Generate the autocompletion script for zsh

### Synopsis

Generate the autocompletion script for the zsh shell.

If shell completion is not already enabled in your environment you will need
to enable it.  You can execute the following once:

	echo "autoload -U compinit; compinit" >> ~/.zshrc

To load completions in your current shell session:

	source <(bitcensus completion zsh)

To load completions for every new session, execute once:

#### Linux:

	bitcensus completion zsh > "${fpath[1]}/_bitcensus"

#### macOS:

	bitcensus completion zsh > $(brew --prefix)/share/zsh/site-functions/_bitcensus

You will need to start a new shell for this setup to take effect.


```
bitcensus completion zsh [flags]
```

### Options

```
  -h, --help              help for zsh
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

