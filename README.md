
# Unwaf

Unwaf is a Go tool designed to help identify WAF bypasses using passive techniques, such as: SPF records and DNS history. By default, Unwaf will check SPF records. 

If you want it to check DNS history records, setup ViewDNS and/or SecurityTrails in Unwaf config file ($HOME/.unwaf.conf). The tool will create an example config file after first execution.

Unwaf is automating the steps I explained on this LinkedIn Post: [Passive WAF bypassing](https://www.linkedin.com/posts/martinmarting_bugbounty-bugbountytips-pentesting-activity-7217385665729093632-oZEP)

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

Check a domain with a custom location for the config file:

```sh
unwaf --domain example.com --config /path/to/config
```

## Author

**Martín Martín**

[LinkedIn](https://www.linkedin.com/in/martinmarting/)

[Twitter/X](https://x.com/mmrecon)

## License

`unwaf` is distributed under GPL v3 License.
