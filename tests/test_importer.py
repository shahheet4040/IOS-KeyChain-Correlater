import base64
import json
from pathlib import Path
import plistlib
import pytest

from correlator.importer import (
    import_keychain,
    parse_cellebrite_xml,
    parse_csv_keychain,
    parse_frida_keychain_dump,
    parse_plist_keychain,
)


def test_frida_keychain_dump_parsing(tmp_path):
    raw_data = [
        {
            "service": "org.whispersystems.signal",
            "account": "GRDBDatabaseCipherKeySpec",
            "access_group": "group.org.whispersystems.signal",
            "kSecValueData": "dGVzdF9zaWduYWxfa2V5XzQ4X2J5dGVzX2xvbmc=",
        },
        {
            "svce": "com.example.app",
            "acct": "user1",
            "agrp": "group.example",
            "data": "0x0102030405060708",
        }
    ]
    p = tmp_path / "frida_dump.json"
    p.write_text(json.dumps(raw_data), encoding="utf-8")

    items, fmt = import_keychain(p)
    assert fmt == "Frida / JSON Dump"
    assert len(items) == 2
    assert items[0]["service"] == "org.whispersystems.signal"
    assert items[0]["value_b64"] == "dGVzdF9zaWduYWxfa2V5XzQ4X2J5dGVzX2xvbmc="
    assert items[1]["service"] == "com.example.app"
    assert items[1]["value_b64"] == base64.b64encode(bytes.fromhex("0102030405060708")).decode()


def test_plist_keychain_parsing(tmp_path):
    plist_dict = {
        "genp": [
            {
                "svce": "net.whatsapp.WhatsApp",
                "acct": "ChatCipherKey",
                "agrp": "group.net.whatsapp.shared",
                "v_Data": b"32_byte_secret_key_whatsapp_test",
            }
        ]
    }
    p = tmp_path / "keychain.plist"
    with open(p, "wb") as f:
        plistlib.dump(plist_dict, f)

    items, fmt = import_keychain(p)
    assert "Plist" in fmt
    assert len(items) == 1
    assert items[0]["service"] == "net.whatsapp.WhatsApp"
    assert items[0]["value_b64"] == base64.b64encode(b"32_byte_secret_key_whatsapp_test").decode()


def test_cellebrite_xml_parsing(tmp_path):
    xml_content = """<?xml version="1.0" encoding="utf-8"?>
    <UFEDExport>
        <KeychainRecord service="org.example.app_b.cipher" account="cipher_key" access_group="group.b" value="0xdeadbeef12345678" />
        <Item>
            <Service>com.signal.app</Service>
            <Account>Key</Account>
            <Group>group.signal</Group>
            <Value>c2VjcmV0</Value>
        </Item>
    </UFEDExport>
    """
    p = tmp_path / "cellebrite.xml"
    p.write_text(xml_content, encoding="utf-8")

    items, fmt = import_keychain(p)
    assert "Cellebrite" in fmt
    assert len(items) == 2
    assert items[0]["service"] == "org.example.app_b.cipher"
    assert items[1]["service"] == "com.signal.app"
    assert items[1]["value_b64"] == "c2VjcmV0"


def test_csv_keychain_parsing(tmp_path):
    csv_content = """Service,Account,Access_Group,Value
org.telegram.messenger,passcode,group.telegram,0102030405060708090a
org.signal,db_key,group.signal,c2lnbmFsX2tleQ==
"""
    p = tmp_path / "elcomsoft.csv"
    p.write_text(csv_content, encoding="utf-8")

    out_json = tmp_path / "normalized.json"
    items, fmt = import_keychain(p, output_json=out_json)
    assert "CSV" in fmt
    assert len(items) == 2
    assert out_json.exists()
    assert items[0]["service"] == "org.telegram.messenger"
    assert items[1]["value_b64"] == "c2lnbmFsX2tleQ=="
