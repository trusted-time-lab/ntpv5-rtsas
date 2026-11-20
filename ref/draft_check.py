# -*- coding: utf-8 -*-
"""
draft01_check.py — run the draft §11 test vectors against the implementation (strict verification)

Approach: read the draft file, use regex to extract the "hand-written" test vector output values
in §11 (e / Root signature / RTSIS / RATSI-PKF / RTSAA fingerprint), then derive them from the
fixed keys + timestamps using algo, asserting each "value written in the file == code-derived value".

Zero failures means the draft §11 test vectors are correct and reproducible byte-for-byte, not
transcription errors.

Run: python draft01_check.py "<draft path>"
"""

import re
import sys
from pathlib import Path

from algo import sm2_e, sm2_sign, ed25519_sign, idh


def load(path):
    return Path(path).read_text(encoding="utf-8")


def extract(pattern, text, name):
    """Extract matching group(1) from text; raise on no match."""
    m = re.search(pattern, text)
    if not m:
        raise ValueError(f"not found {name} (regex {pattern})")
    return m.group(1)


def main(draft_path):
    text = load(draft_path)
    passed = 0
    failed = 0

    def check(name, actual_bytes, expected_hex):
        nonlocal passed, failed
        ok = actual_bytes.hex() == expected_hex.lower()
        if ok:
            passed += 1
            print(f"  ✅ {name}")
        else:
            failed += 1
            print(f"  ❌ {name}\n      file says: {expected_hex}\n      code says: {actual_bytes.hex()}")

    print("=== extract test vectors from draft §11, compare with code-derived values ===\n")

    # ---- fixed inputs (standard test keys, from RFC §10.0, hardcoded) ----
    SK_ROOT = "0000000000000000000000000000000000000000000000000000000000000001"
    SK_TS   = "0000000000000000000000000000000000000000000000000000000000000002"
    K_CALIB = "000000000000000000000000000000000000000000000000000000000000000A"
    K_TRUST = "000000000000000000000000000000000000000000000000000000000000000B"
    PK_ROOT = "32c4ae2c1f1981195f9904466a39c9948fe30bbff2660be1715a4589334c74c7bc3736a2f4f6779c59bdcee36b692153d0a9877cc62a474002df32e52139f0a0"
    PK_TS   = "56cefd60d7c87c000d58ef57fa73ba4d9c0dfa08c08a7331495c2e1da3f2bd5231b7e7e6cc8189f668535ce0f8eaf1bd6de84c182f6c8e716f780d3a970a23c3"
    # Ed25519 raw public key (§11.3)
    PK_TS_ED = "7422b9887598068e32c4448a949adb290d0f4e35b9e01b0ee5f1a1e600fe2674"
    # timestamps
    TS_SIGNED = "EBE6168000000000"
    TS_FROM   = "EBE6168000000000"
    TS_UNTIL  = "EBE6249000000000"
    TS_PT     = "EBE618D880000000"

    # ---- extract output values from draft ----
    # §11.1 SM2 RTSAA
    e1_hex     = extract(r"Za_root.*?0x([0-9a-fA-F]{64})", text, "§11.1 e")
    sig1_hex   = extract(r"root_signature = 0x([0-9a-fA-F]{128})", text, "§11.1 root_signature")
    fp1_hex    = extract(r"RTSAA fingerprint = SM3.*?0x([0-9a-fA-F]{64})", text, "§11.1 fingerprint")
    # §11.2 SM2 RTSIS
    pkf_sm2_hex = extract(r"RATSI-PKF = SM3\(pk_ts\).*?0x([0-9a-fA-F]{64})", text, "§11.2 RATSI-PKF")
    e2_hex     = extract(r"Za_ts.*?0x([0-9a-fA-F]{64})", text, "§11.2 e")
    rtsis_hex  = extract(r"RTSIS = 0x([0-9a-fA-F]{128})", text, "§11.2 RTSIS")
    # §11.3 Ed25519 RTSAA
    pkf_ed_hex = extract(r"RATSI-PKF = SHA-256.*?0x([0-9a-fA-F]{64})", text, "§11.3 RATSI-PKF")
    sig_ed_hex = re.findall(r"root_signature = 0x([0-9a-fA-F]{128})", text)[1]  # the second one = §11.3 Ed25519
    fp_ed_hex  = extract(r"RTSAA fingerprint = SHA-256.*?0x([0-9a-fA-F]{64})", text, "§11.3 fingerprint")

    # ---- derive ----
    # §11.1 SM2 RTSAA (algorithm_id = 0x03)
    alg_sm2 = bytes.fromhex("0300000000000000")
    calib_sm2 = (b"RTSAS-Calib-v1" + alg_sm2 + bytes.fromhex(PK_TS)
                 + (100).to_bytes(8, "big")
                 + bytes.fromhex(TS_SIGNED) + bytes.fromhex(TS_FROM) + bytes.fromhex(TS_UNTIL))
    e1 = sm2_e(PK_ROOT, calib_sm2)
    sig1 = sm2_sign(SK_ROOT, PK_ROOT, calib_sm2, K_CALIB)
    rtsaa_sm2 = alg_sm2 + bytes.fromhex(PK_TS) + (100).to_bytes(8, "big") \
                + bytes.fromhex(TS_SIGNED) + bytes.fromhex(TS_FROM) + bytes.fromhex(TS_UNTIL) + sig1
    fp1 = idh(0x03, rtsaa_sm2)

    print("[§11.1 SM2 RTSAA]")
    check("e", e1, e1_hex)
    check("root_signature", sig1, sig1_hex)
    check("RTSAA fingerprint", fp1, fp1_hex)

    # §11.2 SM2 RTSIS
    pkf_sm2 = idh(0x03, bytes.fromhex(PK_TS))
    trust_sm2 = (b"RTSAS-Trust-v1" + bytes.fromhex("0100000000000000")
                 + pkf_sm2 + fp1 + bytes.fromhex(TS_PT))
    e2 = sm2_e(PK_TS, trust_sm2)
    rtsis = sm2_sign(SK_TS, PK_TS, trust_sm2, K_TRUST)

    print("\n[§11.2 SM2 RTSIS]")
    check("RATSI-PKF", pkf_sm2, pkf_sm2_hex)
    check("e", e2, e2_hex)
    check("RTSIS", rtsis, rtsis_hex)

    # §11.3 Ed25519 RTSAA (algorithm_id = 0x01)
    alg_ed = bytes.fromhex("0100000000000000")
    pk_ed_field = bytes.fromhex(PK_TS_ED) + bytes(32)  # 32B raw + 32B zero padding
    calib_ed = (b"RTSAS-Calib-v1" + alg_ed + pk_ed_field
                + (100).to_bytes(8, "big")
                + bytes.fromhex(TS_SIGNED) + bytes.fromhex(TS_FROM) + bytes.fromhex(TS_UNTIL))
    pkf_ed = idh(0x01, bytes.fromhex(PK_TS_ED))
    sig_ed = ed25519_sign(bytes.fromhex(SK_ROOT), calib_ed)  # seed_root = 1
    rtsaa_ed = alg_ed + pk_ed_field + (100).to_bytes(8, "big") \
               + bytes.fromhex(TS_SIGNED) + bytes.fromhex(TS_FROM) + bytes.fromhex(TS_UNTIL) + sig_ed
    fp_ed = idh(0x01, rtsaa_ed)

    print("\n[§11.3 Ed25519 RTSAA]")
    check("RATSI-PKF", pkf_ed, pkf_ed_hex)
    check("root_signature", sig_ed, sig_ed_hex)
    check("RTSAA fingerprint", fp_ed, fp_ed_hex)

    print(f"\n===== Result: {passed} passed / {failed} failed =====")
    if failed == 0:
        print("✅ draft §11 test vectors are correct and reproducible byte-for-byte")
    else:
        print("❌ transcription errors exist, draft §11 needs fixing")
    return failed


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("usage: python draft01_check.py <draft file path>")
        sys.exit(1)
    sys.exit(main(sys.argv[1]))
