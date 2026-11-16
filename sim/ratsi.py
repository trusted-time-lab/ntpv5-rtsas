# -*- coding: utf-8 -*-
"""
RTSAS 原型 — 锚定根时源的时间服务实例（RATSI）

职责（§2.1.1 / §8.2）：
  - 持 RATSI 私钥、预置根时源公钥；是被根时源对齐认证的「证源」（持 RTSAA、签 RTSIS）。
  - 签出证明（RTSIS 64B + RTSAP 280B）；缓存「最新一份证明响应」（一个槽）。
  - 处理下游请求（提取/生成/查询）：凭证分级验证 + 客户端签名验证 + 分流。
  - 凭证验证分级（§7.6，用户拍板方案 C）：生成 MUST 验、提取/查询 SHOULD 验。
  - 公钥定位（§7.6，所有请求 MUST）与凭证有效性验证（分级）是两个独立操作。
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
        self.root = root                            # 根时源（对齐认证、签 RTSAA）
        self.delta_ns = delta_ns
        self.rtsaa: bytes | None = None             # 当前 RTSAA 168B
        self.cache: bytes | None = None             # 缓存一个槽：最新证明响应 Data 280B
        # 带外注册（§7.6）：公钥哈希 -> 客户端公钥 raw；有效凭证哈希集合（授权检查）
        self.registered_pks: dict = {}
        self.valid_cred_hashes: set = set()

    # ---- 带外注册客户端公钥（§7.6：公钥经带外注册、不承载于凭证内）----
    def register_client(self, pk_raw_32: bytes):
        kh = sha256(pk_raw_32)
        self.registered_pks[kh] = pk_raw_32
        self.valid_cred_hashes.add(kh)

    def revoke_credential(self, pk_raw_32: bytes):
        """撤销凭证（演示「凭证无效」的分级处理）：移出有效集合，但保留公钥注册。"""
        self.valid_cred_hashes.discard(sha256(pk_raw_32))

    # ---- 对齐：根时源测偏移、签 RTSAA（§2.1.3）----
    def align(self, now: int, valid_seconds: int = 3600) -> bytes:
        self.rtsaa = self.root.sign_rtsaa(
            pk_field_64(self.pk), self.delta_ns, now, now, now + valid_seconds
        )
        return self.rtsaa

    # ---- 签出证明：RTSIS + RTSAP（响应 Data 280B）----
    def sign_proof(self, pt: int) -> bytes:
        assert self.rtsaa is not None, f"{self.name} 未对齐，无 RTSAA"
        rtsaa_fp = rtsaa_fingerprint(self.rtsaa)
        rtsis = build_rtsis(self.sk, RESP_PROOF, self.pkf, rtsaa_fp, u64be(pt))
        return build_response_data(RESP_PROOF, self.pkf, rtsis, self.rtsaa, u64be(pt))

    # ---- 处理请求（RATSI 直连场景）----
    def handle_request(self, req_data: bytes, cookie: bytes, now: int) -> bytes:
        """§7.6：先定位公钥（MUST）→ 验凭证有效性（分级）→ 验客户端签名（MUST）→ 分流。"""
        req_mode = req_data[0:8]
        credential = req_data[16:216]
        client_sig = req_data[216:280]
        mode_byte = req_mode[0]

        # 1. 凭证全 0 → MUST 拒绝（字段必备，§7.5）
        if credential == b'\x00' * 200:
            return build_fault(FAULT_FIX, "凭证全 0")

        # 2. 定位客户端公钥（所有请求 MUST，§7.6 —— 与「验凭证有效性」独立的操作）
        kh = credential_key_hash(credential)
        client_pk_raw = self.registered_pks.get(kh)
        if client_pk_raw is None:
            return build_fault(FAULT_FIX, "凭证关联的公钥未带外注册")
        client_pk = pk_from_raw_32(client_pk_raw)

        # 3. 验凭证有效性（分级：生成 MUST、提取/查询 SHOULD，§7.6）
        cred_valid = kh in self.valid_cred_hashes
        if mode_byte == 0x02 and not cred_valid:
            return build_fault(FAULT_FIX, "凭证无效（生成 MUST 验）")
        if mode_byte in (0x01, 0x03) and not cred_valid:
            # SHOULD 拒绝（严格实现）；宽松实现可放行 —— 原型按严格实现演示
            return build_fault(FAULT_FIX, "凭证无效（提取/查询 SHOULD 验，本实现选择拒绝）")

        # 4. 验客户端签名（所有请求 MUST，§7.6）
        if not verify_ed25519(client_pk, P_CLIENT + req_mode + cookie, client_sig):
            return build_fault(FAULT_FIX, "客户端签名无效")

        # 5. 分流（§8.2 请求处理规则表）
        if mode_byte == 0x01:      # 提取：单跳查缓存，命中回证明 / 未命中回 NO_CACHE
            return self.cache if self.cache is not None else build_notify("NO_CACHE")
        elif mode_byte == 0x02:    # 生成：触发对齐 → 签证明 → 写缓存 → 回证明
            self.align(now)
            proof = self.sign_proof(now)
            self.cache = proof
            return proof
        elif mode_byte == 0x03:    # 查询：回通知（发现信息，未签名）
            return build_notify(f"根公钥=<root>, RATSI={self.name}")
        else:
            return build_fault(FAULT_FIX, "未知请求模式")
