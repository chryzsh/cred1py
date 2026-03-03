## Overview

This is a tool used to exploit CRED-1 over a SOCKS5 connection (with UDP support).

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

Then we can invoke Cred1py with:

```
python ./main.py <target> <src_ip> <socks_host> <socks_port>
```

Or using the explicit `attack` subcommand:

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

To help visualise the components referenced in the arguments:

![](./images/attack-overview.png)

Note: Due to the way that SOCKS5 works, the C2 server will need to be accessible on all ports to Cred1py as a second ephemeral port is opened as part of the relaying of UDP traffic. Easiest method is usually to just run Cred1py on the C2 server and target `localhost`.. but you do you!

## How CRED-1 Attack Works

CRED-1 can be broken down into the following steps:

1. Send a DHCP Request for the PXE image over UDP 4011
2. SCCM responds with image path and crypto keys to decrypt the referenced variables file

At this stage, two files are downloaded over TFTP, for example:

1. `2024.09.03.23.35.22.0001.{FEF9DEEE-4C4A-43EF-92BF-2DD23F3CE837}.boot.var`
2. `2024.09.03.23.35.22.07.{FEF9DEEE-4C4A-43EF-92BF-2DD23F3CE837}.boot.bcd`

Next CRED-1 takes the crypto keys returned in the DHCP response, and takes one of two paths depending on whether a PXE password is configured:

1. **No PXE password set** — The DHCP response includes a crypto key (encrypted key material). A key derivation function is run on this material to produce an AES key, which is used to decrypt the variables file directly. No cracking needed.

2. **PXE password is set** — The DHCP response does NOT include a crypto key (only the file path). A hashcat hash is extracted from the variables file header so the password can be cracked offline.

Once the key has been recovered (or derived), the variable file can be decrypted and the contents can be used to retrieve Network Access Account username/password.

Further information on this attack can be found in [Misconfiguration Manager](https://github.com/subat0mik/Misconfiguration-Manager/blob/main/attack-techniques/CRED/CRED-1/cred-1_description.md).

## How Cred1Py Works

Cred1Py attempts to perform this flow over a SOCKS5 connection, due to UDP support being provided as part of the SOCKS5 specification and included in products such as Cobalt Strike.

There are a few differences to the Cred1py implementation to tools like PxeThiefy as SOCKS5 limits our ability to retrieve TFTP files (we can't determine the source port used during the data transfer and therefore can't download more than a handful of bytes).

This means that the requirements for Cred1Py are:

1. An implant executing with SOCKS5 enabled
2. Ability to make a SMB connection to a distribution server (this replaces the TFTP component of PxeThiefy)

Once the requirements are met, Cred1Py:

1. Sends a DHCP Request for the PXE image and crypto key
2. Retrieves the crypto keying material
3. Downloads the variables file over TFTP
4. If no PXE password is set, derives the decryption key and decrypts the variables file automatically
5. If a PXE password is set, outputs a hashcat hash for cracking

### No PXE password set (crypto key in DHCP response)

When no PXE password is configured, the DHCP response includes encrypted key material. Cred1Py derives the AES decryption key and decrypts the variables file automatically, printing the task sequence variables.

If the TFTP download fails (common over SOCKS5), Cred1Py will still output the derived key and the SMB path so you can download and decrypt manually:

```
download \\sccmserver.lab.local\REMINST\SMSTemp\BootFileName.boot.var
python3 main.py decrypt /tmp/BootFileName.boot.var <derived_key_hex>
```

### PXE password is set (no crypto key in DHCP response)

When a PXE password is configured, the DHCP response does NOT include crypto key material. Cred1Py extracts a hashcat hash from the variables file header. Crack it, then re-run with the `-p` flag:

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

