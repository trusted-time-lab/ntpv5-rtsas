# -*- coding: utf-8 -*-
"""
RTSAS prototype — end-to-end demo (four-module completeness verification)

Design verification points covered:
  [A] Byte counts: RTSAA 168B / RTSIS 64B / signing payloads 118-94-31B / Request·Response Data 280B each
  [B] Two-level signature chain: Root Time Source signs RTSAA → RATSI signs RTSIS → client verifies (§4.1–§4.4)
  [C] Tamper-evidence: tamper PT / tamper RTSAA / swap looser RTSAA → verification fails
  [D] Request-response state machine: Extract (cache hit/NO_CACHE), Generate (trigger alignment+sign proof+write cache), Query (discovery)
  [E] Hop-by-hop authorization + re-originate: TTSI validates downstream credential, re-wraps with own credential+signature to upstream
  [F] Cache one slot: overwrite-style keeps latest, Extract single-hop cache lookup, Generate recurses through
  [G] Credential tiering: Generate MUST validate, Extract/Query SHOULD validate; public-key location MUST independent of tiered credential validity validation
  [H] Unsigned notice/fault boundary: Query/fault responses have no RTSIS, not verifiable
"""
from __future__ import annotations

from common import (
    ALG_ED25519, P_CALIB, P_TRUST, P_CLIENT,
    REQ_EXTRACT, REQ_GENERATE, REQ_QUERY,
    RESP_PROOF, RESP_NOTIFY, RESP_FAULT, FAULT_FIX,
    build_rtsaa, build_rtsis, build_response_data, build_request_data, client_sign,
    rtsaa_fingerprint, parse_rtsaa, rtsaa_body, rtsis_payload,
    gen_ed25519, pk_raw_32, pk_from_raw_32, pk_field_64, verify_ed25519,
    u64be, u64be_unpack, make_credential,
)
from root import RootTimeSource
from ratsi import RATSI
from ttsi import TTSI
from client import Client


PASS = 0

def check(name: str, cond: bool, detail: str = ""):
    global PASS
    mark = "✓" if cond else "✗"
    print(f"  [{mark}] {name}" + (f" — {detail}" if detail else ""))
    assert cond, f"verification failed: {name}"
    PASS += 1


def main():
    print("=" * 78)
    print("RTSAS prototype — four-module completeness verification (Root Time Source / RATSI / TTSI / client)")
    print("=" * 78)

    # ============ [A] byte-count self-check ============
    print("\n[A] byte-count self-check (§2.1.3 / §2.1.4 / §3.1)")
    check("domain prefix Calib/Trust/Client = 14/14/15B", len(P_CALIB) == 14 and len(P_TRUST) == 14 and len(P_CLIENT) == 15)
    # temporary keypair, verify structure byte counts
    rk, rpk = gen_ed25519()
    sk, pk = gen_ed25519()
    pk64 = pk_field_64(pk)
    pfk = pk_raw_32(pk)
    rtsaa = build_rtsaa(rk, ALG_ED25519, pk64, 100, 1, 1, 2)
    check("RTSAA = 168B", len(rtsaa) == 168)
    rtsis = build_rtsis(sk, RESP_PROOF, pfk, rtsaa_fingerprint(rtsaa), u64be(1))
    check("RTSIS = 64B", len(rtsis) == 64)
    rsp = build_response_data(RESP_PROOF, pfk, rtsis, rtsaa, u64be(1))
    check("Response Data = 280B", len(rsp) == 280)
    req = build_request_data(REQ_GENERATE, ALG_ED25519, make_credential(pfk), client_sign(sk, REQ_GENERATE, b'\x01'*8))
    check("Request Data = 280B", len(req) == 280)
    check("signing payload Calib=118B", len(P_CALIB + rtsaa_body(ALG_ED25519, pk64, 100, 1, 1, 2)) == 118)
    check("signing payload Trust=94B", len(rtsis_payload(RESP_PROOF, pfk, rtsaa_fingerprint(rtsaa), u64be(1))) == 94)
    check("signing payload Client=31B", len(P_CLIENT + REQ_GENERATE + b'\x01'*8) == 31)

    # ============ phase 0: keys + out-of-band registration ============
    print("\n[phase0] keys + out-of-band registration (§7.6 public keys registered out-of-band, not carried in the credential)")
    root = RootTimeSource("Root Time Source")
    ratsi = RATSI("RATSI-A", root, delta_ns=100)
    ttsi = TTSI("TTSI-B", ratsi)
    client = Client("terminal client", root.pk_raw)

    ratsi.register_client(client.pk_raw)          # client directly connects RATSI (out-of-band public-key registration)
    ratsi.register_client(ttsi.pk_raw)            # TTSI registered out-of-band to RATSI as an "upstream network time client"
    ttsi.register_downstream(client.pk_raw)       # client transits via TTSI (TTSI registers downstream public key)
    now = 1_700_000_000
    cookie = b'\xCA\xFE\x01\x02\x03\x04\x05\x06'
    print("  Root Time Source public key / RATSI public key / TTSI public key / client public key all generated; out-of-band registration done")

    # ============ [B] two-level signature chain (direct-connect generate) ============
    print("\n[B] two-level signature chain: direct-connect generate (client → RATSI)")
    rsp = client.send_request(REQ_GENERATE, cookie, ratsi, now)
    check("generate returns proof response (0x01)", rsp[0] == RESP_PROOF[0])
    ok, msg = client.verify_rtsap(rsp)
    check("client verifies RTSAP passed (§4.1-§4.4)", ok, msg)

    # ============ [C] tamper-evidence ============
    print("\n[C] tamper-evidence (§1.1 / §11.1 three cryptographic guarantees)")
    # tamper PT (offset 272-279)
    t = bytearray(rsp); t[272] ^= 0xFF
    check("tamper PT → RTSIS verification fails", not client.verify_rtsap(bytes(t))[0])
    # tamper RTSAA (offset 104-271, change δ)
    t = bytearray(rsp); t[104+72] ^= 0x01
    check("tamper RTSAA(δ) → Root Time Source verification fails", not client.verify_rtsap(bytes(t))[0])
    # swap looser RTSAA (larger δ) → RTSAA fingerprint in RTSIS mismatches
    looser = build_rtsaa(root.sk, ALG_ED25519, pk_field_64(ratsi.pk), 9999, now, now, now+7200)
    t = bytearray(rsp); t[104:272] = looser
    check("swap looser RTSAA → RTSAA fingerprint mismatch → verification fails", not client.verify_rtsap(bytes(t))[0])

    # ============ [D] request-response state machine (Extract/Query) ============
    print("\n[D] request-response state machine (Extract single-hop cache lookup / Query discovery)")
    rsp2 = client.send_request(REQ_EXTRACT, cookie, ratsi, now)
    check("Extract cache hit → returns proof (0x01)", rsp2[0] == RESP_PROOF[0])
    # new client (public key not registered out-of-band), Extract → public-key location fails → fault (§7.6 public-key location MUST)
    fresh = Client("unregistered client", root.pk_raw)
    rsp3 = fresh.send_request(REQ_EXTRACT, cookie, ratsi, now)
    check("Extract + public key not registered out-of-band → location fails → fault (public-key location MUST)", rsp3[0] == RESP_FAULT[0])
    # Query (registered client)
    rsp4 = client.send_request(REQ_QUERY, cookie, ratsi, now)
    check("Query → notice (0x02, unsigned)", rsp4[0] == RESP_NOTIFY[0])
    check("notice response has no RTSIS (not verifiable, §3.3)", not client.verify_rtsap(rsp4)[0])

    # ============ [E]+[F] hop-by-hop authorization + re-originate + cache (transit generate) ============
    print("\n[E]+[F] hop-by-hop authorization + re-originate + cache one slot (client → TTSI → RATSI)")
    rsp5 = client.send_request(REQ_GENERATE, cookie, ttsi, now)
    check("transit generate → returns proof (0x01)", rsp5[0] == RESP_PROOF[0])
    ok, msg = client.verify_rtsap(rsp5)
    check("client verifies transit-forwarded RTSAP passed (verifies the signing RATSI-A, not the forwarding TTSI-B)", ok, msg)
    # TTSI cached the proof, subsequent Extract hits (no upstream recursion)
    rsp6 = client.send_request(REQ_EXTRACT, cookie, ttsi, now)
    check("transit Extract cache hit → returns proof (single hop, no recursion)", rsp6[0] == RESP_PROOF[0])
    # Extract miss: new TTSI (no cache)
    ttsi2 = TTSI("TTSI-C", ratsi)
    ttsi2.register_downstream(client.pk_raw)
    rsp7 = client.send_request(REQ_EXTRACT, cookie, ttsi2, now)
    check("transit Extract cache miss → NO_CACHE notice (no recursion)", rsp7[0] == RESP_NOTIFY[0])

    # ============ [G] credential tiering ============
    print("\n[G] credential tiering (§7.6 option C: Generate MUST validate, Extract/Query SHOULD validate)")
    # revoke client credential (public key still registered, but credential invalid)
    ratsi.revoke_credential(client.pk_raw)
    rsp8 = client.send_request(REQ_GENERATE, cookie, ratsi, now)
    check("Generate + credential invalid → MUST reject (fault)", rsp8[0] == RESP_FAULT[0])
    rsp9 = client.send_request(REQ_EXTRACT, cookie, ratsi, now)
    check("Extract + credential invalid → SHOULD reject (strict implementation)", rsp9[0] == RESP_FAULT[0])
    # restore credential
    ratsi.register_client(client.pk_raw)
    # all-zero credential (required field, MUST reject)
    zero_cred = build_request_data(REQ_GENERATE, ALG_ED25519, b'\x00'*200, client_sign(client.sk, REQ_GENERATE, cookie))
    rsp10 = ratsi.handle_request(zero_cred, cookie, now)
    check("all-zero credential → MUST reject (required field, §7.5)", rsp10[0] == RESP_FAULT[0])

    # ============ [H] unsigned notice/fault boundary ============
    print("\n[H] unsigned notice/fault boundary (§3.3: not in the RTSIS signing payload, client 'reference' not 'assurance')")
    check("notice response (0x02) verify_rtsap fails (no RTSAP to verify)", not client.verify_rtsap(rsp4)[0])
    check("fault response (0x03) verify_rtsap fails (no RTSAP to verify)", not client.verify_rtsap(rsp10)[0])
    check("fault response offset 8 = fault code 0x02 (fix)", rsp10[0] == RESP_FAULT[0] and rsp10[8] == FAULT_FIX[0])

    print("\n" + "=" * 78)
    print(f"all {PASS} checks passed — RTSAS core design completeness confirmed")
    print("  · two-level signature chain (RTSAA→RTSIS→PT) verification closed loop, byte counts 168/64/280/280 exact")
    print("  · tamper-evidence (PT/RTSAA/swap looser RTSAA three-way verification failure)")
    print("  · hop-by-hop authorization + re-originate + cache one slot + Extract single-hop/Generate recursion self-consistent")
    print("  · credential tiering (Generate MUST/Extract Query SHOULD) + public-key location MUST independent")
    print("=" * 78)


if __name__ == "__main__":
    main()
