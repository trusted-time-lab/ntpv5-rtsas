# -*- coding: utf-8 -*-
"""
RTSAS 原型 — 网络时间客户端（NTP Client）

职责（§4 验证流程）：发 RTSAS-Request、验 RTSAP（§4.1–§4.4）。
  - 持客户端私钥（签客户端签名）、预置根时源公钥（验 RTSAA）。
  - 验 RTSAP 五步（原型聚焦 §4.1–§4.4 的 RTSAP 验签链；§4.5 Cookie 匹配是 NTPv5 原生规则、外层消息头职责，demo 单独演示）。
  - 验的是「签出者 RATSI A」、不是「转发者 TTSI」（§8.1）。
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
        self.root_pk = pk_from_raw_32(root_pk_raw)   # 预置根时源公钥（验 RTSAA）
        self.credential = make_credential(self.pk_raw)

    # ---- 发请求（构造 Request Data 280B，发给 RATSI 或 TTSI）----
    def send_request(self, req_mode: bytes, cookie: bytes, target, now: int) -> bytes:
        csig = client_sign(self.sk, req_mode, cookie)
        req_data = build_request_data(req_mode, ALG_ED25519, self.credential, csig)
        return target.handle_request(req_data, cookie, now)

    # ---- 验 RTSAP（§4.1–§4.4，验的是签出者 RATSI A）----
    def verify_rtsap(self, resp_data: bytes):
        """返回 (通过?, 说明)。resp_data 是 280B RTSAS-Response Data（证明响应）。"""
        if len(resp_data) != 280:
            return False, "响应长度非 280B"
        resp_mode = resp_data[0:8]
        if resp_mode[0] != RESP_PROOF[0]:
            return False, "非证明响应（响应模式非 0x01）"

        ratpsi_pkf_field = resp_data[8:40]
        rtsis = resp_data[40:104]
        rtsaa = resp_data[104:272]
        pt = resp_data[272:280]

        # §4.1 RATSI-PKF 关联：RTSAA 内 RATSI 公钥（64B 前 32B raw）的哈希 == RATSI-PKF 字段
        ratsi_pk_64 = rtsaa[8:72]
        ratsi_pk_raw = ratsi_pk_64[0:32]
        if ratpsi_pkf(ratsi_pk_raw) != ratpsi_pkf_field:
            return False, "RATSI-PKF 关联失败"

        # §4.2 根时源公钥验 RTSAA
        p = parse_rtsaa(rtsaa)
        body = rtsaa_body(p['alg_id'], p['pk_64'], p['delta'], p['issued'], p['vfrom'], p['vuntil'])
        if not verify_ed25519(self.root_pk, P_CALIB + body, p['root_sig']):
            return False, "根时源验 RTSAA 失败"

        # §4.3 RATSI 公钥验 RTSIS
        ratsi_pk = pk_from_raw_32(ratsi_pk_raw)
        rtsaa_fp = rtsaa_fingerprint(rtsaa)
        if not verify_ed25519(ratsi_pk, rtsis_payload(resp_mode, ratpsi_pkf_field, rtsaa_fp, pt), rtsis):
            return False, "RATSI 验 RTSIS 失败"

        # §4.4 签名窗口检查：valid_from ≤ PT ≤ valid_until（零值拒绝 + 窗口）
        pt_val = u64be_unpack(pt)
        if pt_val == 0:
            return False, "PT 为零值"
        if not (p['vfrom'] <= pt_val <= p['vuntil']):
            return False, "PT 不在签名窗口内"

        return True, f"PT={pt_val}, δ={p['delta']}ns, valid_until={p['vuntil']}"
