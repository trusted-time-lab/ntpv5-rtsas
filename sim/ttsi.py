# -*- coding: utf-8 -*-
"""
RTSAS 原型 — 中转时间服务实例（TTSI）

职责（§8.1 / §8.2 / §8.4）：
  - 中间节点：既作为「上游的网络时间客户端」向上游发请求、验上游 RTSAP，又向下游授时。
  - 不持 RTSAA、不签 RTSIS（「列源」的，非「被根时源认可」的）。
  - 逐跳授权（§8.1）：TTSI 验下游凭证（分级），通过后 re-originate（用自己的 Cookie + 凭证 + 签名重包装）发上游。
  - bearer 授权（§7.5 边界）：TTSI 不验客户端签名，凭证机密性靠 TLS/DTLS（协议只做框架）。
  - 缓存一个槽（§8.2）：覆盖式留最新一份证明响应；提取单跳查缓存、生成递归穿透上游。
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
        self.sk, self.pk = gen_ed25519()          # TTSI 作为「上游网络时间客户端」的密钥
        self.pk_raw = pk_raw_32(self.pk)
        self.upstream = upstream                  # 上游 RATSI
        self.credential = make_credential(self.pk_raw)   # TTSI 自己的 API 凭证（re-originate 用）
        self.cache: bytes | None = None           # 缓存一个槽：最新证明响应 Data 280B
        self.registered_pks: dict = {}            # 下游客户端公钥注册
        self.valid_cred_hashes: set = set()       # 有效凭证哈希（下游授权检查）
        self._seen_requests: set = set()          # 本跳去重（§8.1：去重键 = H(完整请求 Data)）

    def register_downstream(self, pk_raw_32: bytes):
        kh = sha256(pk_raw_32)
        self.registered_pks[kh] = pk_raw_32
        self.valid_cred_hashes.add(kh)

    def revoke_downstream(self, pk_raw_32: bytes):
        self.valid_cred_hashes.discard(sha256(pk_raw_32))

    # ---- re-originate（§8.1）：用自己的 Cookie + 凭证 + 签名重包装，发上游 ----
    def re_originate(self, req_mode: bytes, now: int) -> bytes:
        cookie = os.urandom(8)                    # TTSI 本跳 Client Cookie（不复用下游 Cookie）
        csig = client_sign(self.sk, req_mode, cookie)
        req_data = build_request_data(req_mode, ALG_ED25519, self.credential, csig)
        return self.upstream.handle_request(req_data, cookie, now)

    # ---- 处理下游请求 ----
    def handle_request(self, req_data: bytes, cookie: bytes, now: int) -> bytes:
        req_mode = req_data[0:8]
        credential = req_data[16:216]
        mode_byte = req_mode[0]

        # 0. 本跳去重（§8.1：re-originate 前 MUST 对完整请求 Data 去重）
        dedup_key = sha256(req_data)
        if dedup_key in self._seen_requests:
            return build_fault(FAULT_FIX, "重复请求（本跳去重）")
        self._seen_requests.add(dedup_key)

        # 1. 凭证全 0 → MUST 拒绝（字段必备）
        if credential == b'\x00' * 200:
            return build_fault(FAULT_FIX, "凭证全 0")

        # 2. 验凭证有效性（分级：生成 MUST、提取/查询 SHOULD）—— TTSI 不验客户端签名（bearer 授权）
        kh = credential_key_hash(credential)
        cred_valid = kh in self.valid_cred_hashes
        if mode_byte == 0x02 and not cred_valid:
            return build_fault(FAULT_FIX, "凭证无效（生成 MUST 验）")
        if mode_byte in (0x01, 0x03) and not cred_valid:
            return build_fault(FAULT_FIX, "凭证无效（提取/查询 SHOULD 验，本实现选择拒绝）")

        # 3. 分流（§8.2 请求处理规则表）
        if mode_byte == 0x01:        # 提取：单跳查缓存（不递归），命中转发 / 未命中回「无」
            return self.cache if self.cache is not None else build_notify("NO_CACHE")
        elif mode_byte == 0x02:      # 生成：re-originate 递归穿透到上游 RATSI → 缓存转发
            proof = self.re_originate(REQ_GENERATE, now)
            if proof[0] == RESP_PROOF[0]:      # 证明响应 → 写缓存（一个槽，覆盖式）
                self.cache = proof
            return proof
        elif mode_byte == 0x03:      # 查询：回通知（发现信息，未签名）
            return build_notify(f"上游 RATSI={self.upstream.name}, TTSI={self.name}")
        else:
            return build_fault(FAULT_FIX, "未知请求模式")
