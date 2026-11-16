# -*- coding: utf-8 -*-
"""
algo.py — RTSAS 参考实现：三算法签名 / 验签 + 标识派生哈希（IDH）

严格对齐 RFC §2.1.2（算法标识）与 §10（测试向量）。本模块只做「算法层」，
不涉及字段编解码（字段层见 fields.py）。

三种算法（algorithm_id 字节 0）：
  0x01  Ed25519 / SHA-512    —— 签名 64B，IDH = SHA-256，公钥 32B（左对齐填 64B 尾 32B 零）
  0x02  ECDSA P-256 / SHA-256—— 签名 r‖s（32+32B），IDH = SHA-256，公钥 64B（x‖y 无 0x04）
  0x03  SM2 / SM3            —— 签名 r‖s（32+32B），IDH = SM3，公钥 64B（x‖y 无 0x04）

依赖：gmssl（SM2/SM3）、cryptography（Ed25519）。ECDSA 手动实现（点乘 + 模逆）
以便固定 k 复现签名值（pycryptodome 的固定 k 语义不透明，手动最可控）。
"""

import hashlib
from gmssl import sm2 as gmssl_sm2, sm3 as gmssl_sm3, func as gmssl_func


# ============================================================
# SM2 曲线参数（GB/T 32918.5 标准曲线，gmssl 默认参数）
# ============================================================
SM2_P = int("FFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF00000000FFFFFFFFFFFFFFFF", 16)
SM2_A = "FFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF00000000FFFFFFFFFFFFFFFC"
SM2_B = "28E9FA9E9D9F5E344D5A9E4BCF6509A7F39789F515AB8F92DDBCBD414D940E93"
SM2_XG = "32c4ae2c1f1981195f9904466a39c9948fe30bbff2660be1715a4589334c74c7"
SM2_YG = "bc3736a2f4f6779c59bdcee36b692153d0a9877cc62a474002df32e52139f0a0"
SM2_N = int("FFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFF7203DF6B21C6052B53BBF40939D54123", 16)


# ============================================================
# SM2（0x03）
# ============================================================
def sm2_za(public_key_hex_xy: str) -> bytes:
    """
    计算 SM2 的 Za = SM3(ENTL(0x0000) ∥ a ∥ b ∥ xG ∥ yG ∥ xA ∥ yA)。
    user_id 定死为空串（ENTL=0x0000，RFC §2.1.2）。
    public_key_hex_xy：签名者公钥的 x‖y 十六进制（128 字符 = 64B，无 0x04 前缀）。
    返回 32B bytes。
    """
    # 空串 user_id → ENTL = 0x0000（2 字节），ID 为空
    entl = "0000"
    za_input_hex = entl + SM2_A + SM2_B + SM2_XG + SM2_YG + public_key_hex_xy
    za_hex = gmssl_sm3.sm3_hash(gmssl_func.bytes_to_list(bytes.fromhex(za_input_hex)))
    return bytes.fromhex(za_hex)


def sm2_e(public_key_hex_xy: str, message: bytes) -> bytes:
    """
    SM2 的预摘要 e = SM3(Za ∥ M)（RFC §2.1.2「签名原文 M 到签名的过程」）。
    返回 32B bytes（e 的值，作为 SM2 签名的输入）。
    """
    za = sm2_za(public_key_hex_xy)
    e_hex = gmssl_sm3.sm3_hash(gmssl_func.bytes_to_list(za + message))
    return bytes.fromhex(e_hex)


def sm2_sign(private_key_hex: str, public_key_hex_xy: str, message: bytes,
             k_hex: str) -> bytes:
    """
    SM2 签名（r‖s，64B，固定 k 以便复现测试向量）。
    private_key_hex：签名者私钥（64 hex 字符）
    public_key_hex_xy：签名者公钥 x‖y（128 hex 字符，用于算 Za）
    message：signing_payload（原始字节）
    k_hex：固定随机数 k（RFC §10.0）
    """
    e = sm2_e(public_key_hex_xy, message)
    crypt = gmssl_sm2.CryptSM2(private_key=private_key_hex,
                               public_key=public_key_hex_xy, asn1=False)
    sig_hex = crypt.sign(e, k_hex)  # gmssl sign 返回 hex 字符串（r‖s，128 hex 字符 = 64B）
    return bytes.fromhex(sig_hex)


def sm2_verify(public_key_hex_xy: str, message: bytes, signature: bytes) -> bool:
    """
    SM2 验签。signature 为 r‖s（64B）。
    """
    e = sm2_e(public_key_hex_xy, message)
    crypt = gmssl_sm2.CryptSM2(private_key="00", public_key=public_key_hex_xy, asn1=False)
    return crypt.verify(signature.hex(), e)


# ============================================================
# Ed25519（0x01，cryptography，确定性签名，无固定 k 需求）
# ============================================================
def ed25519_sign(seed: bytes, message: bytes) -> bytes:
    """Ed25519 签名（64B）。seed 为 32B 种子（RFC §10.5 固定 seed）。"""
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    sk = Ed25519PrivateKey.from_private_bytes(seed)
    return sk.sign(message)


def ed25519_verify(public_key_raw32: bytes, message: bytes, signature: bytes) -> bool:
    """Ed25519 验签。public_key_raw32 为 raw 32B 公钥。"""
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
    from cryptography.exceptions import InvalidSignature
    pk = Ed25519PublicKey.from_public_bytes(public_key_raw32)
    try:
        pk.verify(signature, message)
        return True
    except InvalidSignature:
        return False


# ============================================================
# ECDSA P-256（0x02，手动实现以便固定 k）
# ============================================================
def _p256_point_mult(k: int):
    """P-256 基点 G 的 k 倍点（返回 pycryptodome EccPoint）。"""
    from Cryptodome.PublicKey import ECC
    G = ECC._curves['P-256'].G
    return G * k


def ecdsa_sign(private_key_int: int, message: bytes, k: int) -> bytes:
    """
    ECDSA P-256 签名（r‖s，64B，固定 k）。
    private_key_int：签名者私钥（整数，RFC §10.6 用 1/2/3）
    message：signing_payload
    k：固定随机数（RFC §10.6 用 0xA/0xB/0xE）
    实现：e = SHA-256(M)，P = k×G，r = P.x mod n，s = k⁻¹(e + r·d) mod n。
    """
    n = int("FFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551", 16)
    e = int.from_bytes(hashlib.sha256(message).digest(), 'big')
    d = private_key_int
    P = _p256_point_mult(k)
    r = int(P.x) % n
    s = (pow(k, -1, n) * (e + r * d)) % n
    return r.to_bytes(32, 'big') + s.to_bytes(32, 'big')


def ecdsa_verify(public_key_hex_xy: str, message: bytes, signature: bytes) -> bool:
    """
    ECDSA P-256 验签（标准规则，接受高 s / 低 s 两种形式，RFC §2.1.2 Low-S 不要求）。
    """
    from Cryptodome.PublicKey import ECC
    from Cryptodome.Signature import DSS
    from Cryptodome.Hash import SHA256
    x = int(public_key_hex_xy[:64], 16)
    y = int(public_key_hex_xy[64:], 16)
    key = ECC.construct(curve='P-256', point_x=x, point_y=y)
    h = SHA256.new(message)
    verifier = DSS.new(key, 'fips-186-3')
    from Cryptodome.Signature import DSS as _DSS
    # 标准 DSS.verify 接受 binary 模式 raw r‖s
    try:
        verifier.verify(h, signature)
        return True
    except ValueError:
        return False


# ============================================================
# 标识派生哈希（IDH）—— RATSI-PKF / RTSAA 指纹（RFC §2.1.2）
# ============================================================
def idh(algorithm_id_byte0: int, raw_bytes: bytes) -> bytes:
    """
    标识派生哈希（32B）。算法按 algorithm_id 字节 0：
      0x01 Ed25519 / 0x02 ECDSA → SHA-256；0x03 SM2 → SM3。
    raw_bytes：哈希输入（RATSI-PKF = raw 公钥字节；RTSAA 指纹 = 完整 168B RTSAA）。
    """
    if algorithm_id_byte0 in (0x01, 0x02):
        return hashlib.sha256(raw_bytes).digest()
    elif algorithm_id_byte0 == 0x03:
        return bytes.fromhex(gmssl_sm3.sm3_hash(gmssl_func.bytes_to_list(raw_bytes)))
    else:
        raise ValueError(f"未定义算法值 0x{algorithm_id_byte0:02x}（RFC §2.1.2）")
