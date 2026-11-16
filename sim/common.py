# -*- coding: utf-8 -*-
"""
RTSAS 模拟实现层 — 公共模块（复用框架层 ref）

分层架构（2026-11-16 确立）：
  框架层（framework）ref
    = 协议本体的可执行规范：三算法签名/验签 + 标识派生哈希 + 字段编解码 + 签名原文。
    逐字节精确、严格校对 RFC §10（51 项测试向量零失败）。
  模拟实现层（simulation）sim
    = 系统组网各节点行为：根时源 / RATSI / TTSI / 客户端，验证对齐、缓存、
    逐跳授权、递归、凭证分级等设计完备性。

本模块是「模拟层」的公共部分，只做模拟业务逻辑（凭证 / 通知 / 故障 / 常量 / 密钥工具），
**不重复实现**协议字段编解码与密码学原语——统一复用框架层 algo + fields。
（「整个数据结构里，相同语义的数据，如无必要，不应该重复」——字段编解码与签名只有一个权威实现。）
"""
from __future__ import annotations

import hashlib
import os
import sys

# ---- 复用框架层（跨目录 import ref）----
_REF_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', 'ref')
if _REF_DIR not in sys.path:
    sys.path.insert(0, _REF_DIR)

from algo import ed25519_sign, ed25519_verify, idh
from fields import (
    DOMAIN_CALIB as P_CALIB,
    DOMAIN_TRUST as P_TRUST,
    DOMAIN_CLIENT as P_CLIENT,
    build_calib_payload,
    build_trust_payload,
    build_client_payload,
    build_rtsaa as _ref_build_rtsaa,
    build_request as _ref_build_request,
    build_response as _ref_build_response,
    split_rtsaa as _ref_split_rtsaa,
)

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

# ============ 常量（模拟层业务常量，对齐 RFC §2.1.2 / §3.1-§3.3）============
ALG_ED25519  = b'\x01' + b'\x00' * 7           # algorithm_id 字节 0 = 0x01 Ed25519；字节 1 = RTSAA Era = 0
REQ_EXTRACT  = b'\x01' + b'\x00' * 7           # 请求模式 0x01 提取（单跳查缓存）
REQ_GENERATE = b'\x02' + b'\x00' * 7           # 请求模式 0x02 生成（递归到 RATSI、触发对齐）
REQ_QUERY    = b'\x03' + b'\x01' + b'\x00' * 6  # 请求模式 0x03 查询，字节 1 = 查询类型 0x01
RESP_PROOF   = b'\x01' + b'\x00' * 7           # 响应模式 0x01 证明（RTSAP，签名）
RESP_NOTIFY  = b'\x02' + b'\x00' * 7           # 响应模式 0x02 通知（未签名）
RESP_FAULT   = b'\x03' + b'\x00' * 7           # 响应模式 0x03 故障（未签名）
FAULT_FIX    = b'\x02' + b'\x00' * 7           # 故障编码 0x02 修（客户端自身问题）

# ============ 密钥工具（seed bytes 化，复用框架层签名/验签）============
def gen_ed25519():
    """生成 Ed25519 密钥对，返回 (seed 32B, 公钥 raw 32B)。"""
    sk = Ed25519PrivateKey.generate()
    seed = sk.private_bytes(serialization.Encoding.Raw,
                            serialization.PrivateFormat.Raw,
                            serialization.NoEncryption())
    pk_raw = sk.public_key().public_bytes(serialization.Encoding.Raw,
                                          serialization.PublicFormat.Raw)
    return seed, pk_raw


def pk_raw_32(pk: bytes) -> bytes:
    """公钥 raw 32B（本模拟层密钥已 seed bytes 化，pk 即 raw bytes，恒等）。"""
    return pk


def pk_from_raw_32(raw: bytes) -> bytes:
    """从 raw 32B 取公钥（本模拟层验签直接收 raw bytes，恒等）。"""
    return raw


def pk_field_64(pk_raw: bytes) -> bytes:
    """RTSAA 内 RATSI 公钥字段 = raw 32B 左对齐 + 尾 32B 零（Ed25519，§2.1.2）。"""
    return pk_raw + b'\x00' * 32


def sign_ed25519(seed: bytes, payload: bytes) -> bytes:
    return ed25519_sign(seed, payload)          # 64B


def verify_ed25519(pk_raw: bytes, payload: bytes, sig: bytes) -> bool:
    return ed25519_verify(pk_raw, payload, sig)


# ============ 哈希（复用框架层 idh，Ed25519 → SHA-256）============
def sha256(data: bytes) -> bytes:
    return hashlib.sha256(data).digest()


def ratpsi_pkf(pk_raw_32: bytes) -> bytes:
    """RATSI-PKF = 标识派生哈希（raw 32B 公钥，SHA-256，§2.1.2）。"""
    return idh(0x01, pk_raw_32)


def rtsaa_fingerprint(rtsaa_168: bytes) -> bytes:
    """RTSAA 指纹 = 对象哈希（完整 168B RTSAA，SHA-256，§2.1.2）。"""
    return idh(0x01, rtsaa_168)


# ============ uint64 BE 编解码（时间 / δ，8B）============
def u64be(n: int) -> bytes:
    return n.to_bytes(8, 'big')


def u64be_unpack(b: bytes) -> int:
    return int.from_bytes(b, 'big')


# ============ RTSAA（168B，复用框架层 build_calib_payload + build_rtsaa）============
def rtsaa_body(alg_id: bytes, pk_64: bytes, delta: int,
               issued: int, vfrom: int, vuntil: int) -> bytes:
    """RTSAA 签名原文 body（104B，= 框架层 Calib payload 去掉 14B 域前缀）。"""
    payload = build_calib_payload(alg_id, pk_64, delta, u64be(issued), u64be(vfrom), u64be(vuntil))
    return payload[14:]                          # 去掉 "RTSAS-Calib-v1"


def build_rtsaa(seed: bytes, alg_id: bytes, pk_64: bytes, delta: int,
                issued: int, vfrom: int, vuntil: int) -> bytes:
    """根时源签 RTSAA（第一级签名，168B）。seed 为根时源 Ed25519 种子。"""
    payload = build_calib_payload(alg_id, pk_64, delta, u64be(issued), u64be(vfrom), u64be(vuntil))
    sig = ed25519_sign(seed, payload)
    return _ref_build_rtsaa(alg_id, pk_64, delta, u64be(issued), u64be(vfrom), u64be(vuntil), sig)


def parse_rtsaa(rtsaa: bytes) -> dict:
    """切分 RTSAA 168B（复用框架层 split_rtsaa，时间转 int 供模拟层比较）。"""
    p = _ref_split_rtsaa(rtsaa)
    return {
        'alg_id': p['algorithm_id'],
        'pk_64': p['ratsi_pubkey'],
        'delta': p['delta_ns'],
        'issued': int.from_bytes(p['signed_time'], 'big'),
        'vfrom': int.from_bytes(p['valid_from'], 'big'),
        'vuntil': int.from_bytes(p['valid_until'], 'big'),
        'root_sig': p['root_signature'],
    }


# ============ RTSIS（64B，复用框架层 build_trust_payload）============
def rtsis_payload(resp_mode: bytes, pkf: bytes, rtsaa_fp: bytes, pt: bytes) -> bytes:
    """RTSIS 签名原文 94B（= 框架层 Trust payload，含域前缀）。"""
    return build_trust_payload(resp_mode, pkf, rtsaa_fp, pt)


def build_rtsis(seed: bytes, resp_mode: bytes, pkf: bytes, rtsaa_fp: bytes, pt: bytes) -> bytes:
    """RATSI 签 RTSIS（第二级签名，64B）。seed 为 RATSI Ed25519 种子。"""
    payload = build_trust_payload(resp_mode, pkf, rtsaa_fp, pt)
    return ed25519_sign(seed, payload)


# ============ RTSAS-Request / Response Data（各 280B，复用框架层）============
def build_response_data(resp_mode: bytes, pkf: bytes, rtsis: bytes,
                        rtsaa: bytes, pt: bytes) -> bytes:
    return _ref_build_response(resp_mode, pkf, rtsis, rtsaa, pt)


def build_request_data(req_mode: bytes, client_alg: bytes,
                       credential: bytes, client_sig: bytes) -> bytes:
    return _ref_build_request(req_mode, client_alg, credential, client_sig)


def client_sign(seed: bytes, req_mode: bytes, cookie: bytes) -> bytes:
    """客户端签名（复用框架层 build_client_payload + Ed25519 签名）。"""
    payload = build_client_payload(req_mode, cookie)
    return ed25519_sign(seed, payload)


# ============ API 凭证（200B，内部结构由发放权威自定，协议不规定）============
# 简化：凭证前 32B = 客户端公钥哈希（作「凭证→公钥」关联键，定位公钥用），其余填充。
def make_credential(pk_raw_32: bytes) -> bytes:
    assert len(pk_raw_32) == 32
    return sha256(pk_raw_32) + b'\xAB' * (200 - 32)   # 前 32B = 公钥指纹（关联键）


def credential_key_hash(credential: bytes) -> bytes:
    """从凭证提取「客户端公钥哈希」（关联键，定位公钥用）。"""
    assert len(credential) == 200
    return credential[0:32]


# ============ 通知 / 故障响应（§3.3，未签名，复用 272B 字段）============
def build_notify(text: str) -> bytes:
    """通知响应 Data 280B = 响应模式(8, 0x02) + 通知结果(272, UTF-8 + 0x00 结束 + 0x00 填充)。"""
    raw = text.encode('utf-8')[:271]
    result = raw + b'\x00' + b'\x00' * (271 - len(raw))
    assert len(result) == 272
    return RESP_NOTIFY + result


def build_fault(fault_code: bytes, text: str) -> bytes:
    """故障响应 Data 280B = 响应模式(8, 0x03) + 故障编码(8) + 描述文本(264, UTF-8 + 0x00 结束 + 填充)。"""
    raw = text.encode('utf-8')[:263]
    desc = raw + b'\x00' + b'\x00' * (263 - len(raw))
    assert len(desc) == 264
    return RESP_FAULT + fault_code + desc
