## bitcensus completion bash

Generate the autocompletion script for bash

### Synopsis

Generate the autocompletion script for the bash shell.

This script depends on the 'bash-completion' package.
If it is not installed already, you can install it via your OS's package manager.

To load completions in your current shell session:

	source <(bitcensus completion bash)

To load completions for every new session, execute once:

#### Linux:

	bitcensus completion bash > /etc/bash_completion.d/bitcensus

#### macOS:

	bitcensus completion bash > $(brew --prefix)/etc/bash_completion.d/bitcensus

You will need to start a new shell for this setup to take effect.


```
bitcensus completion bash
```

### Options

```
  -h, --help              help for bash
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

