# -*- coding: utf-8 -*-
"""
RTSAS prototype — Root Time Source (RTS)

Responsibilities (§2.1.3): operate the physical time source, hold the Root Time Source private key,
and sign RTSAA (first-level signature).
  - Alignment authentication: measure the RATSI time offset |Δ_measured|, sign RTSAA if within bound
    (promising "offset no greater than δ").
  - Does not participate in credential signing/verification and does not touch the "client↔RATSI"
    authorization relationship (§0.3 "the protocol only anchors, does not authenticate").
"""
from __future__ import annotations

from common import (
    ALG_ED25519, P_CALIB, build_rtsaa, parse_rtsaa, rtsaa_body,
    gen_ed25519, pk_raw_32, verify_ed25519,
)


class RootTimeSource:
    def __init__(self, name: str = "Root Time Source"):
        self.name = name
        self.sk, self.pk = gen_ed25519()
        self.pk_raw = pk_raw_32(self.pk)   # Root Time Source public key (pre-provisioned downstream)

    # ---- alignment authentication: sign RTSAA (first-level signature) ----
    def sign_rtsaa(self, ratsi_pk_64: bytes, delta_ns: int, issued: int, vfrom: int, vuntil: int) -> bytes:
        """Root Time Source measures RATSI offset, signs RTSAA if within bound (promising offset ≤ δ)."""
        return build_rtsaa(self.sk, ALG_ED25519, ratsi_pk_64, delta_ns, issued, vfrom, vuntil)

    # ---- verify RTSAA (for downstream verification of the first-level signature) ----
    def verify_rtsaa(self, rtsaa: bytes) -> bool:
        p = parse_rtsaa(rtsaa)
        body = rtsaa_body(p['alg_id'], p['pk_64'], p['delta'], p['issued'], p['vfrom'], p['vuntil'])
        return verify_ed25519(self.pk, P_CALIB + body, p['root_sig'])
