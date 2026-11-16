# -*- coding: utf-8 -*-
"""
RTSAS prototype — network time client (NTP Client)

Responsibilities (§4 verification flow): send RTSAS-Request, verify RTSAP (§4.1–§4.4).
  - Hold the client private key (for the client signature), pre-provision the Root Time Source
    public key (for verifying RTSAA).
  - Verify RTSAP in five steps (the prototype focuses on the RTSAP verification chain of §4.1–§4.4;
    §4.5 Cookie matching is a native NTPv5 rule and the outer message header's responsibility,
    demonstrated separately in demo).
  - What is verified is the "signing RATSI A", not the "forwarding TTSI" (§8.1).
"""
from __future__ import annotations

from common import (
    P_CALIB, ALG_ED25519, RESP_PROOF,
    gen_ed25519, pk_raw_32, pk_from_raw_32, verify_ed25519,
    ratpsi_pkf, rtsaa_fingerprint, parse_rtsaa, rtsaa_body, rtsis_payload,
    u64be_unpack, build_request_data, client_sign, make_credential,
)


class Client:
    def __init__(self, name: str, root_pk_raw: bytes):
        self.name = name
        self.sk, self.pk = gen_ed25519()
        self.pk_raw = pk_raw_32(self.pk)
        self.root_pk = pk_from_raw_32(root_pk_raw)   # pre-provisioned Root Time Source public key (verify RTSAA)
        self.credential = make_credential(self.pk_raw)

    # ---- send request (construct Request Data 280B, send to RATSI or TTSI) ----
    def send_request(self, req_mode: bytes, cookie: bytes, target, now: int) -> bytes:
        csig = client_sign(self.sk, req_mode, cookie)
        req_data = build_request_data(req_mode, ALG_ED25519, self.credential, csig)
        return target.handle_request(req_data, cookie, now)

    # ---- verify RTSAP (§4.1–§4.4, what is verified is the signing RATSI A) ----
    def verify_rtsap(self, resp_data: bytes):
        """Return (passed?, description). resp_data is 280B RTSAS-Response Data (proof response)."""
        if len(resp_data) != 280:
            return False, "response length is not 280B"
        resp_mode = resp_data[0:8]
        if resp_mode[0] != RESP_PROOF[0]:
            return False, "not a proof response (response mode is not 0x01)"

        ratpsi_pkf_field = resp_data[8:40]
        rtsis = resp_data[40:104]
        rtsaa = resp_data[104:272]
        pt = resp_data[272:280]

        # §4.1 RATSI-PKF association: hash of the RATSI public key inside RTSAA (first 32B raw of the 64B) == RATSI-PKF field
        ratsi_pk_64 = rtsaa[8:72]
        ratsi_pk_raw = ratsi_pk_64[0:32]
        if ratpsi_pkf(ratsi_pk_raw) != ratpsi_pkf_field:
            return False, "RATSI-PKF association failed"

        # §4.2 verify RTSAA with the Root Time Source public key
        p = parse_rtsaa(rtsaa)
        body = rtsaa_body(p['alg_id'], p['pk_64'], p['delta'], p['issued'], p['vfrom'], p['vuntil'])
        if not verify_ed25519(self.root_pk, P_CALIB + body, p['root_sig']):
            return False, "Root Time Source verification of RTSAA failed"

        # §4.3 verify RTSIS with the RATSI public key
        ratsi_pk = pk_from_raw_32(ratsi_pk_raw)
        rtsaa_fp = rtsaa_fingerprint(rtsaa)
        if not verify_ed25519(ratsi_pk, rtsis_payload(resp_mode, ratpsi_pkf_field, rtsaa_fp, pt), rtsis):
            return False, "RATSI verification of RTSIS failed"

        # §4.4 signature window check: valid_from ≤ PT ≤ valid_until (zero value reject + window)
        pt_val = u64be_unpack(pt)
        if pt_val == 0:
            return False, "PT is zero"
        if not (p['vfrom'] <= pt_val <= p['vuntil']):
            return False, "PT is outside the signature window"

        return True, f"PT={pt_val}, δ={p['delta']}ns, valid_until={p['vuntil']}"
