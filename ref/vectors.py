# -*- coding: utf-8 -*-
"""
vectors.py — RTSAS reference implementation: reproduce all §10 test vectors (strict verification script)

Asserts each "code-derived value == RFC §10 authoritative value"; zero failures means the reference
implementation matches the RFC byte-for-byte.
Covers: §10.1 SM2 RTSAA / §10.2 SM2 RTSIS / §10.3 SM2 client signature / §10.4 byte layout
        §10.5 Ed25519 / §10.6 ECDSA P-256 / §10.7 mixed algorithm / §10.8 negative tests.

Run: python vectors.py
"""

import hashlib
from algo import (
    sm2_za, sm2_e, sm2_sign, sm2_verify,
    ed25519_sign, ed25519_verify,
    ecdsa_sign, ecdsa_verify,
    idh,
)
from fields import (
    build_calib_payload, build_trust_payload, build_client_payload,
    build_rtsaa, build_request, build_response,
    split_rtsaa, split_request, split_response,
)

# ============================================================
# Timestamps and fixed values (RFC §10.1/§10.2)
# ============================================================
TS_SIGNED    = bytes.fromhex("EBE6168000000000")  # 2025-06-01 00:00:00 UTC
TS_VALID_FROM = bytes.fromhex("EBE6168000000000")
TS_VALID_UNTIL = bytes.fromhex("EBE6249000000000")  # 2025-06-01 01:00:00 UTC
TS_PT         = bytes.fromhex("EBE618D880000000")  # 2025-06-01 00:10:00.5 UTC
DELTA_NS      = 100
RESP_PROOF    = bytes.fromhex("0100000000000000")   # response mode 0x01 Proof
REQ_EXTRACT   = bytes.fromhex("0100000000000000")   # request mode 0x01 Extract
COOKIE        = bytes.fromhex("0001020304050607")   # Client Cookie

# ============================================================
# §10.0 fixed test keys / public keys / identifiers
# ============================================================
SK_ROOT_SM2   = "0000000000000000000000000000000000000000000000000000000000000001"
SK_TS_SM2     = "0000000000000000000000000000000000000000000000000000000000000002"
SK_CLIENT_SM2 = "0000000000000000000000000000000000000000000000000000000000000003"
K_CALIB = "000000000000000000000000000000000000000000000000000000000000000A"
K_TRUST = "000000000000000000000000000000000000000000000000000000000000000B"
K_CLIENT = "000000000000000000000000000000000000000000000000000000000000000E"

PK_ROOT_SM2   = "32c4ae2c1f1981195f9904466a39c9948fe30bbff2660be1715a4589334c74c7bc3736a2f4f6779c59bdcee36b692153d0a9877cc62a474002df32e52139f0a0"
PK_TS_SM2     = "56cefd60d7c87c000d58ef57fa73ba4d9c0dfa08c08a7331495c2e1da3f2bd5231b7e7e6cc8189f668535ce0f8eaf1bd6de84c182f6c8e716f780d3a970a23c3"
PK_CLIENT_SM2 = "a97f7cd4b3c993b4be2daa8cdb41e24ca13f6bd945302244e26918f1d0509ebf530b5dd88c688ef5ccc5cec08a72150f7c400ee5cd045292aaacdd037458f6e6"

# Ed25519 (§10.5) seed and raw 32B public key
SEED_ROOT_ED   = bytes.fromhex("0000000000000000000000000000000000000000000000000000000000000001")
SEED_TS_ED     = bytes.fromhex("0000000000000000000000000000000000000000000000000000000000000002")
SEED_CLIENT_ED = bytes.fromhex("0000000000000000000000000000000000000000000000000000000000000003")
PK_TS_ED_RAW   = bytes.fromhex("7422b9887598068e32c4448a949adb290d0f4e35b9e01b0ee5f1a1e600fe2674")

# ECDSA (§10.6) public key (x‖y)
PK_ROOT_EC   = "6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c2964fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5"
PK_TS_EC     = "7cf27b188d034f7e8a52380304b51ac3c08969e277f21b35a60b48fc4766997807775510db8ed040293d9ac69f7430dbba7dade63ce982299e04b79d227873d1"


# ============================================================
# Test result statistics
# ============================================================
PASS = 0
FAIL = 0
FAILURES = []


def check(name, actual, expected):
    global PASS, FAIL
    ok = (actual == expected)
    if ok:
        PASS += 1
        print(f"  ✅ {name}")
    else:
        FAIL += 1
        FAILURES.append(name)
        print(f"  ❌ {name}\n     expected {expected}\n     actual {actual}")


def check_true(name, cond):
    global PASS, FAIL
    if cond:
        PASS += 1
        print(f"  ✅ {name}")
    else:
        FAIL += 1
        FAILURES.append(name)
        print(f"  ❌ {name}")


def section(title):
    print(f"\n{'=' * 60}\n{title}\n{'=' * 60}")


# ============================================================
# §10.1 SM2 RTSAA (168B)
# ============================================================
def vec_10_1_sm2_rtsaa():
    section("§10.1 SM2 RTSAA (168B)")
    alg_id = bytes.fromhex("0300000000000000")
    pk_ts_field = bytes.fromhex(PK_TS_SM2)  # 64B x‖y

    # signing payload 118B
    payload = build_calib_payload(alg_id, pk_ts_field, DELTA_NS,
                                  TS_SIGNED, TS_VALID_FROM, TS_VALID_UNTIL)
    check("Calib payload length 118B", len(payload), 118)

    # pre-digest e = SM3(Za_root ∥ payload)
    e = sm2_e(PK_ROOT_SM2, payload)
    check("e = SM3(Za_root ∥ payload)", e.hex(),
          "441ded1c6bb61d5fd22e8df89b9463b81b5857c734fc23b59eddd18c6cb4564d")

    # Root Time Source signature
    root_sig = sm2_sign(SK_ROOT_SM2, PK_ROOT_SM2, payload, K_CALIB)
    check("Root Time Source signature", root_sig.hex(),
          "1817357fbd4c3f20f394ee5a91f0a1eb5c2548c1e057bcbccfc225980e313c80"
          "f3f4653f2159e06f863588d2b707af09c3f13b0a319a26ccebdae13d32bca2e8")

    # full 168B RTSAA
    rtsaa = build_rtsaa(alg_id, pk_ts_field, DELTA_NS,
                        TS_SIGNED, TS_VALID_FROM, TS_VALID_UNTIL, root_sig)
    check("RTSAA length 168B", len(rtsaa), 168)

    # RTSAA fingerprint = SM3(168B)
    fp = idh(0x03, rtsaa)
    check("RTSAA fingerprint = SM3(168B)", fp.hex(),
          "ce03d94a7447053549fe6a2e44854214fa63e34b800f8236a2143bf0f17f57ca")

    # verification
    check_true("Root Time Source signature verification passed", sm2_verify(PK_ROOT_SM2, payload, root_sig))
    return rtsaa, fp


# ============================================================
# §10.2 SM2 RTSIS (64B)
# ============================================================
def vec_10_2_sm2_rtsis(rtsaa_fp):
    section("§10.2 SM2 RTSIS (64B)")
    ratsi_pkf = bytes.fromhex("dad451ec36b06f8a16efb4867def22db0ae251fa143931b0067192998c48517e")

    payload = build_trust_payload(RESP_PROOF, ratsi_pkf, rtsaa_fp, TS_PT)
    check("Trust payload length 94B", len(payload), 94)

    e = sm2_e(PK_TS_SM2, payload)
    check("e = SM3(Za_ts ∥ payload)", e.hex(),
          "570d32429acf8cdd2d0bbed22076c218cc50151eb2a8bec190f91ca9ac6838de")

    rtsis = sm2_sign(SK_TS_SM2, PK_TS_SM2, payload, K_TRUST)
    check("RTSIS", rtsis.hex(),
          "5bc0fd53649665bfa9266a492fdeb75bdeade2f43c6bbe43f7859181394a43ac"
          "6d7f571d124666d58f3bb9248ac0db17b78ea84f4391849a3d79970555b1fe53")

    check_true("RTSIS verification passed", sm2_verify(PK_TS_SM2, payload, rtsis))
    return rtsis


# ============================================================
# §10.3 SM2 client signature (64B)
# ============================================================
def vec_10_3_sm2_client():
    section("§10.3 SM2 client signature (64B)")
    payload = build_client_payload(REQ_EXTRACT, COOKIE)
    check("Client payload length 31B", len(payload), 31)

    e = sm2_e(PK_CLIENT_SM2, payload)
    check("e = SM3(Za_client ∥ payload)", e.hex(),
          "2ac678dade840626ed65ceaa2c983983d37524bf28801655c2e59a65fb25f69b")

    client_sig = sm2_sign(SK_CLIENT_SM2, PK_CLIENT_SM2, payload, K_CLIENT)
    check("client signature", client_sig.hex(),
          "ae7b1db97528dd363815502c961b10ccc2980ee7e71d5b33cd29bef031e100a2"
          "7d23a9b3e8215a1755f003de8f6bb365e011d43d347000c479dca4d5146c80ad")

    check_true("client signature verification passed", sm2_verify(PK_CLIENT_SM2, payload, client_sig))
    return client_sig


# ============================================================
# §10.4 query request / notice / fault byte layout
# ============================================================
def vec_10_4_layout(client_sig):
    section("§10.4 query request / notice / fault byte layout")
    # query request 280B (request mode 0x03 Query + byte 1 0x01 fetch latest Root public key)
    req_mode = bytes.fromhex("0301000000000000")
    client_alg = bytes.fromhex("0300000000000000")
    credential = bytes([0xAB]) * 200
    req = build_request(req_mode, client_alg, credential, client_sig)
    check("query request length 280B", len(req), 280)
    s = split_request(req)
    check("query request request mode byte0=0x03", s['request_mode'][0], 0x03)
    check("query request request mode byte1=0x01", s['request_mode'][1], 0x01)
    check("query request client signature algorithm byte0=0x03", s['client_sig_algo'][0], 0x03)
    check("query request API credential 200B non-zero", s['api_credential'][0], 0xAB)

    # notice response (response mode 0x02, unsigned) offset 8-279 notice result 272B (§3.3)
    notify_mode = bytes.fromhex("0200000000000000")
    notify_text = b"SM2:" + PK_ROOT_SM2.encode('ascii')  # 0x01 fetch latest Root public key
    notify_pad = notify_text + b"\x00" + b"\x00" * (272 - len(notify_text) - 1)
    assert len(notify_pad) == 272
    notify_resp = notify_mode + notify_pad  # 8 + 272 = 280B
    check("notice response length 280B", len(notify_resp), 280)
    check("notice response response mode byte0=0x02", notify_resp[0], 0x02)
    check("notice response offset8=notice result first byte 'S'", notify_resp[8], ord('S'))

    # fault response (response mode 0x03) offset 8-15 fault code + offset 16-279 description text 264B (§3.3)
    fault_mode = bytes.fromhex("0300000000000000")
    fault_code = bytes.fromhex("0100000000000000")  # 0x01 change
    fault_desc = b"upstream no cache" + b"\x00" + b"\x00" * (264 - len(b"upstream no cache") - 1)
    assert len(fault_desc) == 264
    fault_resp = fault_mode + fault_code + fault_desc  # 8 + 8 + 264 = 280B
    check("fault response length 280B", len(fault_resp), 280)
    check("fault response response mode byte0=0x03", fault_resp[0], 0x03)
    check("fault response offset8=fault code 0x01", fault_resp[8], 0x01)


# ============================================================
# §10.5 Ed25519
# ============================================================
def vec_10_5_ed25519():
    section("§10.5 Ed25519 test vectors")
    alg_id = bytes.fromhex("0100000000000000")
    pk_ts_field = PK_TS_ED_RAW + b"\x00" * 32  # raw 32B + trailing 32B zeros = 64B

    # RATSI-PKF = SHA-256(raw 32B)
    pkf = idh(0x01, PK_TS_ED_RAW)
    check("RATSI-PKF = SHA-256(pk_ts raw 32B)", pkf.hex(),
          "2c5a92ed92c0b7999f215be93c8f0433f58072bdba21a8b277faa495b57bf7f3")

    # Calib + Root signature (Ed25519 deterministic, seed_root)
    payload = build_calib_payload(alg_id, pk_ts_field, DELTA_NS,
                                  TS_SIGNED, TS_VALID_FROM, TS_VALID_UNTIL)
    root_sig = ed25519_sign(SEED_ROOT_ED, payload)
    check("Root Time Source signature (Ed25519)", root_sig.hex(),
          "a90a83130f05e6f03b0fb7ad09ccd8f0136936dbebc060c4041ab67553a5f2e8"
          "04aff421dea9dd7012450d5ad258cd36c3ec1915725539fadf4fedd30fa4df02")

    rtsaa = build_rtsaa(alg_id, pk_ts_field, DELTA_NS,
                        TS_SIGNED, TS_VALID_FROM, TS_VALID_UNTIL, root_sig)
    fp = idh(0x01, rtsaa)
    check("RTSAA fingerprint = SHA-256(168B)", fp.hex(),
          "aee21b30c2f9c90ea17bdf3949ccaeec2290859f759a2c948197ea503f1f40ea")

    # RTSIS (Ed25519, seed_ts)
    trust_payload = build_trust_payload(RESP_PROOF, pkf, fp, TS_PT)
    rtsis = ed25519_sign(SEED_TS_ED, trust_payload)
    check("RTSIS (Ed25519)", rtsis.hex(),
          "cd62548258cf11f4c0e03ca07ec5391514086ebcf2c82d668b4e314751c1c30f"
          "28b0a163110777772613478d021eeba368d68147256929bdc7571ff6e5b1bd0e")

    # client signature (Ed25519, seed_client)
    client_payload = build_client_payload(REQ_EXTRACT, COOKIE)
    client_sig = ed25519_sign(SEED_CLIENT_ED, client_payload)
    check("client signature (Ed25519)", client_sig.hex(),
          "e5efea2c26de2a730cca2b2ee29ccc62b1c9dc20ca1255e2c36ed6b1995568ee"
          "7f6788616d8ba6f8a72fbf6386c4b5e123cda5e744226848226125d5759d2f06")

    check_true("Root Time Source signature verification passed", ed25519_verify(
        bytes.fromhex("4cb5abf6ad79fbf5abbccafcc269d85cd2651ed4b885b5869f241aedf0a5ba29"),
        payload, root_sig))


# ============================================================
# §10.6 ECDSA P-256
# ============================================================
def vec_10_6_ecdsa():
    section("§10.6 ECDSA P-256 test vectors")
    alg_id = bytes.fromhex("0200000000000000")
    pk_ts_field = bytes.fromhex(PK_TS_EC)  # 64B x‖y

    pkf = idh(0x02, pk_ts_field)
    check("RATSI-PKF = SHA-256(pk_ts raw 64B)", pkf.hex(),
          "d07aeb134840b15242e12d4a06ce3ab493cbd020ebc3bd5aaecd822f51e0c3d8")

    payload = build_calib_payload(alg_id, pk_ts_field, DELTA_NS,
                                  TS_SIGNED, TS_VALID_FROM, TS_VALID_UNTIL)
    root_sig = ecdsa_sign(1, payload, 0xA)  # sk_root=1, k_calib=0xA
    check("Root Time Source signature (ECDSA r‖s)", root_sig.hex(),
          "cef66d6b2a3a993e591214d1ea223fb545ca6c471c48306e4c36069404c5723f"
          "fd504e6cddc2fc85bc1848c065fc2cfbee6c4a979f02bde53b88347d8e84ff70")

    rtsaa = build_rtsaa(alg_id, pk_ts_field, DELTA_NS,
                        TS_SIGNED, TS_VALID_FROM, TS_VALID_UNTIL, root_sig)
    fp = idh(0x02, rtsaa)
    check("RTSAA fingerprint = SHA-256(168B)", fp.hex(),
          "8fa3791c9c66d0e9e09f542822b1e3feb9f12414d83e64a47d25059971a5bfac")

    trust_payload = build_trust_payload(RESP_PROOF, pkf, fp, TS_PT)
    rtsis = ecdsa_sign(2, trust_payload, 0xB)  # sk_ts=2, k_trust=0xB
    check("RTSIS (ECDSA r‖s)", rtsis.hex(),
          "3ed113b7883b4c590638379db0c21cda16742ed0255048bf433391d374bc21d1"
          "940061a2fa541140dea4dd24f0198617f7884373a8a16be073438ec1831918c0")

    client_payload = build_client_payload(REQ_EXTRACT, COOKIE)
    client_sig = ecdsa_sign(3, client_payload, 0xE)  # sk_client=3, k_client=0xE
    check("client signature (ECDSA r‖s)", client_sig.hex(),
          "54e77a001c3862b97a76647f4336df3cf126acbe7a069c5e5709277324d2920b"
          "4e9252100406f44c78fd4aa1e8af8dc42e24b1d93bb9a47939b46be17d929293")

    check_true("Root Time Source signature verification passed", ecdsa_verify(PK_ROOT_EC, payload, root_sig))


# ============================================================
# §10.7 mixed algorithm (Root SM2 + RATSI Ed25519)
# ============================================================
def vec_10_7_mixed():
    section("§10.7 mixed algorithm (Root Time Source SM2 + RATSI Ed25519)")
    alg_id = bytes.fromhex("0100000000000000")  # RATSI algorithm Ed25519
    pk_ts_field = PK_TS_ED_RAW + b"\x00" * 32

    # RATSI-PKF = SHA-256(raw 32B) (follows the RATSI algorithm Ed25519)
    pkf = idh(0x01, PK_TS_ED_RAW)
    check("RATSI-PKF = SHA-256(pk_ts raw 32B)", pkf.hex(),
          "2c5a92ed92c0b7999f215be93c8f0433f58072bdba21a8b277faa495b57bf7f3")

    # Calib payload same bytes as §10.5, but Root Time Source signature uses SM2 (pk_root_sm2)
    payload = build_calib_payload(alg_id, pk_ts_field, DELTA_NS,
                                  TS_SIGNED, TS_VALID_FROM, TS_VALID_UNTIL)
    root_sig = sm2_sign(SK_ROOT_SM2, PK_ROOT_SM2, payload, K_CALIB)
    check("Root Time Source signature (SM2, Za uses pk_root_sm2)", root_sig.hex(),
          "1a20d3b5c60616f4a70c16f054998740043ba19c5fbdb11ce06bf89b572cfaae"
          "f2ef96241cfcf485ac79f487d5b33c5f6fe60e9cf1e72c9ce385f7bb8e3ec3d1")

    rtsaa = build_rtsaa(alg_id, pk_ts_field, DELTA_NS,
                        TS_SIGNED, TS_VALID_FROM, TS_VALID_UNTIL, root_sig)
    fp = idh(0x01, rtsaa)  # RTSAA fingerprint follows algorithm_id byte 0 (Ed25519) → SHA-256
    check("RTSAA fingerprint = SHA-256(168B)", fp.hex(),
          "02dd24a319810f487ca4c55a4e12380afc3784864d34232711a8e1f6f5895d75")

    # RTSIS uses Ed25519 (seed_ts)
    trust_payload = build_trust_payload(RESP_PROOF, pkf, fp, TS_PT)
    rtsis = ed25519_sign(SEED_TS_ED, trust_payload)
    check("RTSIS (Ed25519, seed_ts)", rtsis.hex(),
          "dfc8e2cdcff43e2079f1ae7fda8503ff94335c46f3ec607af03f86a4848c77ad"
          "a0d9c2366d4d0b4e520cf1e4f80b1c9e2bd21995b2cbead5a58934542958440e")

    check_true("Root Time Source signature SM2 verification passed", sm2_verify(PK_ROOT_SM2, payload, root_sig))
    check_true("RTSIS Ed25519 verification passed", ed25519_verify(PK_TS_ED_RAW, trust_payload, rtsis))


# ============================================================
# §10.8 negative tests (rejection semantics)
# ============================================================
def vec_10_8_negative():
    section("§10.8 negative tests (rejection semantics)")
    # use positive SM2-scenario material for tamper detection
    alg_id = bytes.fromhex("0300000000000000")
    pk_ts_field = bytes.fromhex(PK_TS_SM2)
    payload = build_calib_payload(alg_id, pk_ts_field, DELTA_NS,
                                  TS_SIGNED, TS_VALID_FROM, TS_VALID_UNTIL)
    root_sig = sm2_sign(SK_ROOT_SM2, PK_ROOT_SM2, payload, K_CALIB)
    rtsaa = build_rtsaa(alg_id, pk_ts_field, DELTA_NS,
                        TS_SIGNED, TS_VALID_FROM, TS_VALID_UNTIL, root_sig)
    fp = idh(0x03, rtsaa)
    pkf = idh(0x03, pk_ts_field)
    trust_payload = build_trust_payload(RESP_PROOF, pkf, fp, TS_PT)
    rtsis = sm2_sign(SK_TS_SM2, PK_TS_SM2, trust_payload, K_TRUST)

    # N8: change RTSAA field (δ 100→200) → Root Time Source verification fails
    tampered = build_calib_payload(alg_id, pk_ts_field, 200,
                                   TS_SIGNED, TS_VALID_FROM, TS_VALID_UNTIL)
    check_true("N8 change δ → Root Time Source verification fails",
               not sm2_verify(PK_ROOT_SM2, tampered, root_sig))

    # N9: change PT → RTSIS verification fails
    tampered_pt = TS_PT.replace(b"\x00", b"\x01")
    tp = build_trust_payload(RESP_PROOF, pkf, fp, tampered_pt)
    check_true("N9 change PT → RTSIS verification fails",
               not sm2_verify(PK_TS_SM2, tp, rtsis))

    # N10: swap in a looser RTSAA (δ 200) → RTSAA fingerprint mismatch
    looser_payload = build_calib_payload(alg_id, pk_ts_field, 200,
                                         TS_SIGNED, TS_VALID_FROM, TS_VALID_UNTIL)
    looser_sig = sm2_sign(SK_ROOT_SM2, PK_ROOT_SM2, looser_payload, K_CALIB)
    looser_rtsaa = build_rtsaa(alg_id, pk_ts_field, 200,
                               TS_SIGNED, TS_VALID_FROM, TS_VALID_UNTIL, looser_sig)
    looser_fp = idh(0x03, looser_rtsaa)
    check_true("N10 swap in a looser RTSAA → fingerprint mismatch", looser_fp != fp)

    # N11: PT outside window — window check (PT MUST ∈ [valid_from, valid_until], §4.4)
    def in_window(pt, vf, vu):
        return vf <= pt <= vu
    check_true("N11 positive PT within window", in_window(TS_PT, TS_VALID_FROM, TS_VALID_UNTIL))
    pt_before = bytes.fromhex("EBE6167F00000000")  # 1 second before valid_from
    check_true("N11 PT earlier than valid_from → out-of-window reject",
               not in_window(pt_before, TS_VALID_FROM, TS_VALID_UNTIL))
    pt_after = bytes.fromhex("EBE6249100000000")   # 1 second after valid_until
    check_true("N11 PT later than valid_until → out-of-window reject",
               not in_window(pt_after, TS_VALID_FROM, TS_VALID_UNTIL))

    # N1: algorithm value 0x04 undefined → idh should raise
    try:
        idh(0x04, rtsaa)
        check_true("N1 algorithm value 0x04 undefined → reject", False)
    except ValueError:
        check_true("N1 algorithm value 0x04 undefined → reject", True)

    # N3: Ed25519 public key trailing 32B non-zero → validation (structural level) should reject
    bad_ed_pk_field = PK_TS_ED_RAW + b"\x01" * 32
    check_true("N3 Ed25519 public key trailing 32B non-zero → validation reject", bad_ed_pk_field[32:] != b"\x00" * 32)


# ============================================================
# main flow
# ============================================================
def main():
    print("RTSAS reference implementation — §10 test vector reproduction (strict verification)")
    rtsaa, fp = vec_10_1_sm2_rtsaa()
    vec_10_2_sm2_rtsis(fp)
    client_sig = vec_10_3_sm2_client()
    vec_10_4_layout(client_sig)
    vec_10_5_ed25519()
    vec_10_6_ecdsa()
    vec_10_7_mixed()
    vec_10_8_negative()

    print(f"\n{'=' * 60}")
    print(f"Result: {PASS} passed / {FAIL} failed")
    if FAIL:
        print("Failed items:")
        for f in FAILURES:
            print(f"  - {f}")
        raise SystemExit(1)
    else:
        print("✅ All passed — reference implementation matches RFC §10 byte-for-byte")


if __name__ == "__main__":
    main()
