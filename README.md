# PF Redact

`pf-redact.py` redacts sensitive values from pfSense configuration backups before they are shared for troubleshooting, review, or support.

The script works with plain `config.xml` files and gzip-compressed `config.xml.gz` backups. It uses only the Python standard library.

## Requirements

- Python 3
- A pfSense backup exported as `.xml` or `.xml.gz`

## Quick Start

Redact a plain XML backup:

```sh
python3 pf-redact.py config.xml
```

This writes:

```text
config.redacted.xml
```

Redact a gzip-compressed backup:

```sh
python3 pf-redact.py config.xml.gz
```

This writes:

```text
config.redacted.xml.gz
```

Redact IP addresses and hostnames as well:

```sh
python3 pf-redact.py --redact-ips --redact-hostnames config.xml
```

Write to a specific output path:

```sh
python3 pf-redact.py config.xml redacted.xml
```

Overwrite the input file and keep a backup copy:

```sh
python3 pf-redact.py --in-place config.xml
```

The backup is written beside the original file with a `.bak` suffix.

## Usage

```text
usage: pf-redact.py [-h] [--redact-ips] [--redact-hostnames] [--in-place]
                    input [output]
```

Arguments:

- `input`: pfSense backup/config file, either `.xml` or `.xml.gz`.
- `output`: optional redacted output file. If omitted, the script writes `input.redacted.xml` or `input.redacted.xml.gz`.

Options:

- `--redact-ips`: redact IPv4 and IPv6 addresses found in XML text nodes.
- `--redact-hostnames`: redact hostnames and fully qualified domain names found in XML text nodes.
- `--in-place`: overwrite the input file after creating a `.bak` backup.

## What Gets Redacted

By default, the script redacts values whose XML tag or attribute names look sensitive, including common names such as:

- `password`, `passwd`, `pass`
- `secret`, `sharedsecret`, `pre-shared-key`, `psk`
- `token`, `apikey`, `api_key`
- `key`, `privatekey`, `privkey`
- `passwordhash`, `md5-hash`, `bcrypt-hash`
- `community`, `radius_secret`, `bindpw`, `ddns_password`
- `wireguard_privatekey`, `openvpn_tlskey`, `tlskey`

It also redacts:

- PEM blocks such as certificates and private keys.
- Long base64-looking values.
- Long hex-looking values.

Redacted values are replaced with markers such as:

```text
[REDACTED:password;len=12]
[REDACTED:PEM]
[REDACTED:blob;len=256]
```

The `len=` value is the stripped length of the original value. It is intended to help with review while avoiding exposure of the original content.

## Important Caveats

This tool is a helper, not a guarantee. Always inspect the redacted output before sharing it.

Known gaps and limitations:

- Redaction is heuristic. Sensitive values stored under unusual XML tag names may not be detected.
- `--redact-ips` and `--redact-hostnames` apply to XML text and tail text. They do not redact IP addresses or hostnames inside attributes unless the attribute name itself looks sensitive.
- XML is reserialized with `xml.etree.ElementTree`, so formatting, comments, CDATA sections, and some namespace prefix details may not be preserved exactly.
- If XML parsing fails, the fallback regex path redacts PEM blocks, very long base64-looking blobs, and optional IP/hostname values. It does not provide the same tag-aware redaction as the normal XML parser path.
- When the input is gzip-compressed, output is gzip-compressed too. With an explicit output name, a `.xml.gz` input will still produce gzip data even if the output filename does not end in `.gz`.

Because of these limitations, treat the generated file as a sanitized sharing copy rather than a backup intended for restore.

## Suggested Verification

After running the script, search the redacted output for values you expect to be removed:

```sh
rg -n "password|secret|token|community|private|key|example.com|192\\.0\\.2\\." config.redacted.xml
```

For gzip output, decompress to a temporary file first or inspect it with tools that can read gzip-compressed content.

## Examples

Redact secrets only:

```sh
python3 pf-redact.py config.xml
```

Redact secrets, IP addresses, and hostnames:

```sh
python3 pf-redact.py --redact-ips --redact-hostnames config.xml
```

Redact a compressed pfSense backup:

```sh
python3 pf-redact.py config.xml.gz config.redacted.xml.gz
```

Overwrite a local copy after creating `config.xml.bak`:

```sh
python3 pf-redact.py --in-place config.xml
```

