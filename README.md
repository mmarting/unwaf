
# Unwaf

Unwaf is a Go tool designed to help identify potential WAF bypass using passive techniques, such as: DNS history and SPF records.

## Installation

To install Unwaf, use the `go install` command:

```sh
go install github.com/mmarting/unwaf@latest
```

## Usage

Use -h to display the help for the tool:

```sh
unwaf -h
```

Unwaf requires a domain (-d) as the only mandatory parameter. The tool admits the following options:

## Options

    -d, --domain:       The domain to check (required).
    -s, --source:       The source HTML file to compare (optional).
    -c, --config:       The config file path (optional, default: $HOME/.wafbypass.conf).
    -h, --help:         Display help information.

## Examples

Check a domain:

```sh
unwaf --domain example.com
```

Check a domain with a manually provided HTML file:

```sh
unwaf --domain example.com --source original.html
```

Check a domain with a config file:

```sh
unwaf --domain example.com --config /path/to/config
```

## Author

**Martín Martín**

[LinkedIn](https://www.linkedin.com/in/martinmarting/)

[Twitter/X](https://x.com/mmrecon)

## License

`unwaf` is distributed under GPL v3 License.
