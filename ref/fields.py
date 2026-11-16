# -*- coding: utf-8 -*-
"""
fields.py — RTSAS 参考实现：字段编解码 + 三签名原文构造

严格对齐 RFC §2.1.3（RTSAA 168B）、§2.1.4（RTSIS）、§3.1（承载与偏移）、
§3.2（上行 Request 280B）、§3.3（下行 Response 280B）。

所有字段定长、按序拼接、无分隔符无长度前缀（RFC §3.1「字段切分 MUST 定长偏移」）。
"""

# ============================================================
# 签名域前缀（RFC §2.1.2「签名域前缀」）
# ============================================================
DOMAIN_CALIB = b"RTSAS-Calib-v1"    # 14B（RTSAA 根时源签名）
DOMAIN_TRUST = b"RTSAS-Trust-v1"    # 14B（RTSIS）
DOMAIN_CLIENT = b"RTSAS-Client-v1"  # 15B（客户端签名）


# ============================================================
# 签名原文构造（三原文，字节数各对齐 RFC）
# ============================================================
def build_calib_payload(algorithm_id: bytes, ratsi_pubkey_field: bytes,
                        delta_ns: int, signed_time: bytes,
                        valid_from: bytes, valid_until: bytes) -> bytes:
    """
    RTSAA 签名原文（118B，RFC §2.1.3）：
      "RTSAS-Calib-v1"(14B) ∥ algorithm_id(8B) ∥ RATSI 公钥(64B)
      ∥ BE64(δ)(8B) ∥ 签发时间(8B) ∥ valid_from(8B) ∥ valid_until(8B)
    """
    assert len(algorithm_id) == 8
    assert len(ratsi_pubkey_field) == 64
    assert len(signed_time) == len(valid_from) == len(valid_until) == 8
    payload = (DOMAIN_CALIB + algorithm_id + ratsi_pubkey_field +
               delta_ns.to_bytes(8, 'big') + signed_time + valid_from + valid_until)
    assert len(payload) == 118, f"Calib payload 长度 {len(payload)} ≠ 118"
    return payload


def build_trust_payload(response_mode: bytes, ratsi_pkf: bytes,
                        rtsaa_fingerprint: bytes, proven_time: bytes) -> bytes:
    """
    RTSIS 签名原文（94B，RFC §2.1.4）：
      "RTSAS-Trust-v1"(14B) ∥ 响应模式(8B) ∥ RATSI-PKF(32B)
      ∥ RTSAA 指纹(32B) ∥ 被证明时间(PT)(8B)
    """
    assert len(response_mode) == 8
    assert len(ratsi_pkf) == 32
    assert len(rtsaa_fingerprint) == 32
    assert len(proven_time) == 8
    payload = DOMAIN_TRUST + response_mode + ratsi_pkf + rtsaa_fingerprint + proven_time
    assert len(payload) == 94, f"Trust payload 长度 {len(payload)} ≠ 94"
    return payload


def build_client_payload(request_mode: bytes, client_cookie: bytes) -> bytes:
    """
    客户端签名原文（31B，RFC §3.2）：
      "RTSAS-Client-v1"(15B) ∥ 请求模式(8B) ∥ Client Cookie(8B)
    """
    assert len(request_mode) == 8
    assert len(client_cookie) == 8
    payload = DOMAIN_CLIENT + request_mode + client_cookie
    assert len(payload) == 31, f"Client payload 长度 {len(payload)} ≠ 31"
    return payload


# ============================================================
# 结构构造（RTSAA 168B / Request 280B / Response 280B）
# ============================================================
def build_rtsaa(algorithm_id: bytes, ratsi_pubkey_field: bytes, delta_ns: int,
                signed_time: bytes, valid_from: bytes, valid_until: bytes,
                root_signature: bytes) -> bytes:
    """
    RTSAA（168B，RFC §2.1.3）：
      algorithm_id(8B) ∥ RATSI 公钥(64B) ∥ δ(8B) ∥ 签发时间(8B)
      ∥ valid_from(8B) ∥ valid_until(8B) ∥ 根时源签名(64B)
    """
    assert len(root_signature) == 64
    rtsaa = (algorithm_id + ratsi_pubkey_field + delta_ns.to_bytes(8, 'big') +
             signed_time + valid_from + valid_until + root_signature)
    assert len(rtsaa) == 168, f"RTSAA 长度 {len(rtsaa)} ≠ 168"
    return rtsaa


def build_request(request_mode: bytes, client_sig_algo: bytes,
                  api_credential: bytes, client_signature: bytes) -> bytes:
    """
    RTSAS-Request Data（280B，RFC §3.1/§3.2）：
      请求模式(8B) ∥ 客户端签名算法(8B) ∥ API 凭证(200B) ∥ 客户端签名(64B)
    """
    assert len(request_mode) == 8
    assert len(client_sig_algo) == 8
    assert len(api_credential) == 200
    assert len(client_signature) == 64
    data = request_mode + client_sig_algo + api_credential + client_signature
    assert len(data) == 280, f"Request 长度 {len(data)} ≠ 280"
    return data


def build_response(response_mode: bytes, ratsi_pkf: bytes, rtsis: bytes,
                   rtsaa: bytes, proven_time: bytes) -> bytes:
    """
    RTSAS-Response Data（280B，RFC §3.1/§3.3）：
      响应模式(8B) ∥ RATSI-PKF(32B) ∥ RTSIS(64B) ∥ RTSAA(168B) ∥ 被证明时间(PT)(8B)
    """
    assert len(response_mode) == 8
    assert len(ratsi_pkf) == 32
    assert len(rtsis) == 64
    assert len(rtsaa) == 168
    assert len(proven_time) == 8
    data = response_mode + ratsi_pkf + rtsis + rtsaa + proven_time
    assert len(data) == 280, f"Response 长度 {len(data)} ≠ 280"
    return data


# ============================================================
# 字段切分（定长偏移，RFC §3.1）
# ============================================================
def split_rtsaa(rtsaa: bytes) -> dict:
    """切分 RTSAA 168B（偏移定义见 RFC §2.1.3 / §3.1）。"""
    assert len(rtsaa) == 168
    return {
        'algorithm_id': rtsaa[0:8],
        'ratsi_pubkey': rtsaa[8:72],
        'delta_ns': int.from_bytes(rtsaa[72:80], 'big'),
        'signed_time': rtsaa[80:88],
        'valid_from': rtsaa[88:96],
        'valid_until': rtsaa[96:104],
        'root_signature': rtsaa[104:168],
    }


def split_request(data: bytes) -> dict:
    """切分 RTSAS-Request Data 280B（偏移定义见 RFC §3.1）。"""
    assert len(data) == 280
    return {
        'request_mode': data[0:8],
        'client_sig_algo': data[8:16],
        'api_credential': data[16:216],
        'client_signature': data[216:280],
    }


def split_response(data: bytes) -> dict:
    """切分 RTSAS-Response Data 280B（偏移定义见 RFC §3.1）。"""
    assert len(data) == 280
    return {
        'response_mode': data[0:8],
        'ratsi_pkf': data[8:40],
        'rtsis': data[40:104],
        'rtsaa': data[104:272],
        'proven_time': data[272:280],
    }
