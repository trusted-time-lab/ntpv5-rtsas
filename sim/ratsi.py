# -*- coding: utf-8 -*-
"""
RTSAS prototype — Root-Anchored Time Service Instance (RATSI)

Responsibilities (§2.1.1 / §8.2):
  - Hold the RATSI private key, pre-provision the Root Time Source public key; it is the
    "proof source" authenticated by Root Time Source alignment (holds RTSAA, signs RTSIS).
  - Sign out proofs (RTSIS 64B + RTSAP 280B); cache the "latest proof response" (one slot).
  - Handle downstream requests (Extract/Generate/Query): credential tiering validation +
    client signature validation + dispatch.
  - Credential validation tiering (§7.6, user-approved option C): Generate MUST validate,
    Extract/Query SHOULD validate.
  - Public-key location (§7.6, MUST for all requests) and credential validity validation (tiered)
    are two independent operations.
"""
from __future__ import annotations

from common import (
    P_CLIENT, RESP_PROOF, REQ_GENERATE, FAULT_FIX,
    sha256, ratpsi_pkf, rtsaa_fingerprint,
    gen_ed25519, pk_raw_32, pk_from_raw_32, pk_field_64, verify_ed25519,
    u64be, build_rtsis, build_response_data, build_notify, build_fault,
    credential_key_hash,
)
from root import RootTimeSource


class RATSI:
    def __init__(self, name: str, root: RootTimeSource, delta_ns: int = 100):
        self.name = name
        self.sk, self.pk = gen_ed25519()
        self.pk_raw = pk_raw_32(self.pk)
        self.pkf = ratpsi_pkf(self.pk_raw)          # RATSI-PKF 32B
        self.root = root                            # Root Time Source (alignment authentication, signs RTSAA)
        self.delta_ns = delta_ns
        self.rtsaa: bytes | None = None             # current RTSAA 168B
        self.cache: bytes | None = None             # cache one slot: latest proof response Data 280B
        # out-of-band registration (§7.6): public-key hash -> client public key raw; valid credential hash set (authorization check)
        self.registered_pks: dict = {}
        self.valid_cred_hashes: set = set()

    # ---- register client public key out-of-band (§7.6: public keys are registered out-of-band, not carried in the credential) ----
    def register_client(self, pk_raw_32: bytes):
        kh = sha256(pk_raw_32)
        self.registered_pks[kh] = pk_raw_32
        self.valid_cred_hashes.add(kh)

    def revoke_credential(self, pk_raw_32: bytes):
        """Revoke a credential (demonstrates tiered handling of "credential invalid"): remove from the valid set, but keep the public-key registration."""
        self.valid_cred_hashes.discard(sha256(pk_raw_32))

    # ---- alignment: Root Time Source measures offset, signs RTSAA (§2.1.3) ----
    def align(self, now: int, valid_seconds: int = 3600) -> bytes:
        self.rtsaa = self.root.sign_rtsaa(
            pk_field_64(self.pk), self.delta_ns, now, now, now + valid_seconds
        )
        return self.rtsaa

    # ---- sign out proof: RTSIS + RTSAP (response Data 280B) ----
    def sign_proof(self, pt: int) -> bytes:
        assert self.rtsaa is not None, f"{self.name} not aligned, no RTSAA"
        rtsaa_fp = rtsaa_fingerprint(self.rtsaa)
        rtsis = build_rtsis(self.sk, RESP_PROOF, self.pkf, rtsaa_fp, u64be(pt))
        return build_response_data(RESP_PROOF, self.pkf, rtsis, self.rtsaa, u64be(pt))

    # ---- handle request (RATSI direct-connect scenario) ----
    def handle_request(self, req_data: bytes, cookie: bytes, now: int) -> bytes:
        """§7.6: first locate the public key (MUST) → validate credential validity (tiered) → validate client signature (MUST) → dispatch."""
        req_mode = req_data[0:8]
        credential = req_data[16:216]
        client_sig = req_data[216:280]
        mode_byte = req_mode[0]

        # 1. all-zero credential → MUST reject (required field, §7.5)
        if credential == b'\x00' * 200:
            return build_fault(FAULT_FIX, "all-zero credential")

        # 2. locate client public key (MUST for all requests, §7.6 — an operation independent of "credential validity validation")
        kh = credential_key_hash(credential)
        client_pk_raw = self.registered_pks.get(kh)
        if client_pk_raw is None:
            return build_fault(FAULT_FIX, "public key associated with the credential is not registered out-of-band")
        client_pk = pk_from_raw_32(client_pk_raw)

        # 3. validate credential validity (tiered: Generate MUST, Extract/Query SHOULD, §7.6)
        cred_valid = kh in self.valid_cred_hashes
        if mode_byte == 0x02 and not cred_valid:
            return build_fault(FAULT_FIX, "credential invalid (Generate MUST validate)")
        if mode_byte in (0x01, 0x03) and not cred_valid:
            # SHOULD reject (strict implementation); a lenient implementation may pass — prototype demonstrates strict implementation
            return build_fault(FAULT_FIX, "credential invalid (Extract/Query SHOULD validate, this implementation chooses to reject)")

        # 4. validate client signature (MUST for all requests, §7.6)
        if not verify_ed25519(client_pk, P_CLIENT + req_mode + cookie, client_sig):
            return build_fault(FAULT_FIX, "invalid client signature")

        # 5. dispatch (§8.2 request handling rule table)
        if mode_byte == 0x01:      # Extract: single-hop cache lookup, hit returns proof / miss returns NO_CACHE
            return self.cache if self.cache is not None else build_notify("NO_CACHE")
        elif mode_byte == 0x02:    # Generate: trigger alignment → sign proof → write cache → return proof
            self.align(now)
            proof = self.sign_proof(now)
            self.cache = proof
            return proof
        elif mode_byte == 0x03:    # Query: return notice (discovery info, unsigned)
            return build_notify(f"Root public key=<root>, RATSI={self.name}")
        else:
            return build_fault(FAULT_FIX, "unknown request mode")
