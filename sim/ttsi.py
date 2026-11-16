# -*- coding: utf-8 -*-
"""
RTSAS prototype — Transit Time Service Instance (TTSI)

Responsibilities (§8.1 / §8.2 / §8.4):
  - Intermediate node: acts as an "upstream network time client" sending requests upstream and
    verifying the upstream RTSAP, while serving time downstream.
  - Does not hold RTSAA, does not sign RTSIS (a "listed source", not a "Root Time Source-approved" one).
  - Hop-by-hop authorization (§8.1): TTSI validates the downstream credential (tiered), and on
    success re-originates (re-wraps with its own Cookie + credential + signature) to upstream.
  - bearer authorization (§7.5 boundary): TTSI does not validate the client signature; credential
    confidentiality relies on TLS/DTLS (the protocol only provides the framework).
  - Cache one slot (§8.2): overwrite-style keeps the latest proof response; Extract does a
    single-hop cache lookup, Generate recurses through upstream.
"""
from __future__ import annotations

import os

from common import (
    P_CLIENT, ALG_ED25519, RESP_PROOF, REQ_EXTRACT, REQ_GENERATE, FAULT_FIX,
    sha256, gen_ed25519, pk_raw_32,
    build_request_data, build_notify, build_fault, client_sign, make_credential,
    credential_key_hash,
)
from ratsi import RATSI


class TTSI:
    def __init__(self, name: str, upstream: RATSI):
        self.name = name
        self.sk, self.pk = gen_ed25519()          # TTSI key as an "upstream network time client"
        self.pk_raw = pk_raw_32(self.pk)
        self.upstream = upstream                  # upstream RATSI
        self.credential = make_credential(self.pk_raw)   # TTSI's own API credential (for re-originate)
        self.cache: bytes | None = None           # cache one slot: latest proof response Data 280B
        self.registered_pks: dict = {}            # downstream client public-key registration
        self.valid_cred_hashes: set = set()       # valid credential hashes (downstream authorization check)
        self._seen_requests: set = set()          # per-hop dedup (§8.1: dedup key = H(full request Data))

    def register_downstream(self, pk_raw_32: bytes):
        kh = sha256(pk_raw_32)
        self.registered_pks[kh] = pk_raw_32
        self.valid_cred_hashes.add(kh)

    def revoke_downstream(self, pk_raw_32: bytes):
        self.valid_cred_hashes.discard(sha256(pk_raw_32))

    # ---- re-originate (§8.1): re-wrap with own Cookie + credential + signature, send upstream ----
    def re_originate(self, req_mode: bytes, now: int) -> bytes:
        cookie = os.urandom(8)                    # TTSI per-hop Client Cookie (does not reuse downstream Cookie)
        csig = client_sign(self.sk, req_mode, cookie)
        req_data = build_request_data(req_mode, ALG_ED25519, self.credential, csig)
        return self.upstream.handle_request(req_data, cookie, now)

    # ---- handle downstream request ----
    def handle_request(self, req_data: bytes, cookie: bytes, now: int) -> bytes:
        req_mode = req_data[0:8]
        credential = req_data[16:216]
        mode_byte = req_mode[0]

        # 0. per-hop dedup (§8.1: MUST dedup the full request Data before re-originate)
        dedup_key = sha256(req_data)
        if dedup_key in self._seen_requests:
            return build_fault(FAULT_FIX, "duplicate request (per-hop dedup)")
        self._seen_requests.add(dedup_key)

        # 1. all-zero credential → MUST reject (required field)
        if credential == b'\x00' * 200:
            return build_fault(FAULT_FIX, "all-zero credential")

        # 2. validate credential validity (tiered: Generate MUST, Extract/Query SHOULD) — TTSI does not validate client signature (bearer authorization)
        kh = credential_key_hash(credential)
        cred_valid = kh in self.valid_cred_hashes
        if mode_byte == 0x02 and not cred_valid:
            return build_fault(FAULT_FIX, "credential invalid (Generate MUST validate)")
        if mode_byte in (0x01, 0x03) and not cred_valid:
            return build_fault(FAULT_FIX, "credential invalid (Extract/Query SHOULD validate, this implementation chooses to reject)")

        # 3. dispatch (§8.2 request handling rule table)
        if mode_byte == 0x01:        # Extract: single-hop cache lookup (no recursion), hit forwards / miss returns "none"
            return self.cache if self.cache is not None else build_notify("NO_CACHE")
        elif mode_byte == 0x02:      # Generate: re-originate recursively through to upstream RATSI → cache and forward
            proof = self.re_originate(REQ_GENERATE, now)
            if proof[0] == RESP_PROOF[0]:      # proof response → write cache (one slot, overwrite-style)
                self.cache = proof
            return proof
        elif mode_byte == 0x03:      # Query: return notice (discovery info, unsigned)
            return build_notify(f"upstream RATSI={self.upstream.name}, TTSI={self.name}")
        else:
            return build_fault(FAULT_FIX, "unknown request mode")
