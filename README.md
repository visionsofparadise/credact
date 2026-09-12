# credact

Inject credentials into a child process and redact them from its output.

## Install

Download from the [latest release](https://github.com/visionsofparadise/credact/releases/latest).

## Usage

```sh
credact [--no-output-scan] VAR [...] -- COMMAND [ARG ...]
```

- `--no-output-scan` disables output redaction. (Optional)
- `VAR` either:
   - `KEY` environment variable key
   - `KEY=keepassxc://entry/field` resolves a field from KeePassXC with Browser Integration enabled and assigns to an environment variable.
- `--` delimits the sources from the command.
- `COMMAND` is the program to run, resolved from `PATH`.
- `ARG` is passed to the command unaltered.

A single command:

```sh
credact GH_TOKEN=keepassxc://github/token -- gh repo list
```

Many commands, through a shell:

```sh
credact API_TOKEN=keepassxc://service/password -- bash -c 'curl -H "Authorization: Bearer $API_TOKEN" https://example.com && deploy'
```

```sh
credact --help
credact --version
```

## Licence

MIT
