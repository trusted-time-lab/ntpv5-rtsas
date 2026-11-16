# -*- coding: utf-8 -*-
"""
RTSAS 原型 — 根时源（Root Time Source, RTS）

职责（§2.1.3）：运营物理时源、持根时源私钥、签发 RTSAA（第一级签名）。
  - 对齐认证：测量 RATSI 的时间偏移 |Δ_measured|，界内签发 RTSAA（承诺「偏移不超过 δ」）。
  - 不参与凭证签发/验证、不碰「客户端↔RATSI」授权关系（§0.3「协议只锚定、不鉴别」）。
"""
from __future__ import annotations

from common import (
    ALG_ED25519, P_CALIB, build_rtsaa, parse_rtsaa, rtsaa_body,
    gen_ed25519, pk_raw_32, verify_ed25519,
)


class RootTimeSource:
    def __init__(self, name: str = "根时源"):
        self.name = name
        self.sk, self.pk = gen_ed25519()
        self.pk_raw = pk_raw_32(self.pk)   # 根时源公钥（预置给下游）

    # ---- 对齐认证：签发 RTSAA（第一级签名）----
    def sign_rtsaa(self, ratsi_pk_64: bytes, delta_ns: int, issued: int, vfrom: int, vuntil: int) -> bytes:
        """根时源测量 RATSI 偏移、界内签发 RTSAA（承诺偏移 ≤ δ）。"""
        return build_rtsaa(self.sk, ALG_ED25519, ratsi_pk_64, delta_ns, issued, vfrom, vuntil)

    # ---- 验 RTSAA（下游验证第一级签名用）----
    def verify_rtsaa(self, rtsaa: bytes) -> bool:
        p = parse_rtsaa(rtsaa)
        body = rtsaa_body(p['alg_id'], p['pk_64'], p['delta'], p['issued'], p['vfrom'], p['vuntil'])
        return verify_ed25519(self.pk, P_CALIB + body, p['root_sig'])
