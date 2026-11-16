# -*- coding: utf-8 -*-
"""
algo.py — RTSAS reference implementation: three-algorithm signing / verification + Identifier-Derived Hash (IDH)

Strictly aligned with RFC §2.1.2 (algorithm identifiers) and §10 (test vectors). This module is the
"algorithm layer" only; it does not handle field encoding/decoding (see fields.py for the field layer).

Three algorithms (algorithm_id byte 0):
  0x01  Ed25519 / SHA-512    — 64B signature, IDH = SHA-256, 32B public key (left-aligned in a 64B field, trailing 32B zero)
  0x02  ECDSA P-256 / SHA-256 — signature r‖s (32+32B), IDH = SHA-256, 64B public key (x‖y, no 0x04)
  0x03  SM2 / SM3            — signature r‖s (32+32B), IDH = SM3, 64B public key (x‖y, no 0x04)

Dependencies: gmssl (SM2/SM3), cryptography (Ed25519). ECDSA is implemented manually (point
multiplication + modular inverse) so that a fixed k reproduces signature values (pycryptodome's
fixed-k semantics are opaque; manual implementation is the most controllable).
"""

import hashlib
from gmssl import sm2 as gmssl_sm2, sm3 as gmssl_sm3, func as gmssl_func


# ============================================================
# SM2 curve parameters (GB/T 32918.5 standard curve, gmssl default parameters)
# ============================================================
SM2_P = int("FFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF00000000FFFFFFFFFFFFFFFF", 16)
SM2_A = "FFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF00000000FFFFFFFFFFFFFFFC"
SM2_B = "28E9FA9E9D9F5E344D5A9E4BCF6509A7F39789F515AB8F92DDBCBD414D940E93"
SM2_XG = "32c4ae2c1f1981195f9904466a39c9948fe30bbff2660be1715a4589334c74c7"
SM2_YG = "bc3736a2f4f6779c59bdcee36b692153d0a9877cc62a474002df32e52139f0a0"
SM2_N = int("FFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFF7203DF6B21C6052B53BBF40939D54123", 16)


# ============================================================
# SM2 (0x03)
# ============================================================
def sm2_za(public_key_hex_xy: str) -> bytes:
    """
    Compute SM2 Za = SM3(ENTL(0x0000) ∥ a ∥ b ∥ xG ∥ yG ∥ xA ∥ yA).
    user_id is fixed to the empty string (ENTL=0x0000, RFC §2.1.2).
    public_key_hex_xy: the signer's public key x‖y in hex (128 chars = 64B, no 0x04 prefix).
    Returns 32B bytes.
    """
    # Empty user_id → ENTL = 0x0000 (2 bytes), ID is empty
    entl = "0000"
    za_input_hex = entl + SM2_A + SM2_B + SM2_XG + SM2_YG + public_key_hex_xy
    za_hex = gmssl_sm3.sm3_hash(gmssl_func.bytes_to_list(bytes.fromhex(za_input_hex)))
    return bytes.fromhex(za_hex)


def sm2_e(public_key_hex_xy: str, message: bytes) -> bytes:
    """
    SM2 pre-digest e = SM3(Za ∥ M) (RFC §2.1.2, "the process from signing payload M to the signature").
    Returns 32B bytes (the value of e, used as input to the SM2 signature).
    """
    za = sm2_za(public_key_hex_xy)
    e_hex = gmssl_sm3.sm3_hash(gmssl_func.bytes_to_list(za + message))
    return bytes.fromhex(e_hex)


def sm2_sign(private_key_hex: str, public_key_hex_xy: str, message: bytes,
             k_hex: str) -> bytes:
    """
    SM2 signature (r‖s, 64B, fixed k to reproduce test vectors).
    private_key_hex: the signer's private key (64 hex chars)
    public_key_hex_xy: the signer's public key x‖y (128 hex chars, used to compute Za)
    message: signing_payload (raw bytes)
    k_hex: fixed nonce k (RFC §10.0)
    """
    e = sm2_e(public_key_hex_xy, message)
    crypt = gmssl_sm2.CryptSM2(private_key=private_key_hex,
                               public_key=public_key_hex_xy, asn1=False)
    sig_hex = crypt.sign(e, k_hex)  # gmssl sign returns a hex string (r‖s, 128 hex chars = 64B)
    return bytes.fromhex(sig_hex)


def sm2_verify(public_key_hex_xy: str, message: bytes, signature: bytes) -> bool:
    """
    SM2 verification. signature is r‖s (64B).
    """
    e = sm2_e(public_key_hex_xy, message)
    crypt = gmssl_sm2.CryptSM2(private_key="00", public_key=public_key_hex_xy, asn1=False)
    return crypt.verify(signature.hex(), e)


# ============================================================
# Ed25519 (0x01, cryptography, deterministic signing, no fixed-k requirement)
# ============================================================
def ed25519_sign(seed: bytes, message: bytes) -> bytes:
    """Ed25519 signature (64B). seed is a 32B seed (fixed seed, RFC §10.5)."""
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    sk = Ed25519PrivateKey.from_private_bytes(seed)
    return sk.sign(message)


def ed25519_verify(public_key_raw32: bytes, message: bytes, signature: bytes) -> bool:
    """Ed25519 verification. public_key_raw32 is the raw 32B public key."""
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
    from cryptography.exceptions import InvalidSignature
    pk = Ed25519PublicKey.from_public_bytes(public_key_raw32)
    try:
        pk.verify(signature, message)
        return True
    except InvalidSignature:
        return False


# ============================================================
# ECDSA P-256 (0x02, implemented manually to fix k)
# ============================================================
def _p256_point_mult(k: int):
    """k-th multiple of the P-256 base point G (returns a pycryptodome EccPoint)."""
    from Cryptodome.PublicKey import ECC
    G = ECC._curves['P-256'].G
    return G * k


def ecdsa_sign(private_key_int: int, message: bytes, k: int) -> bytes:
    """
    ECDSA P-256 signature (r‖s, 64B, fixed k).
    private_key_int: the signer's private key (integer, RFC §10.6 uses 1/2/3)
    message: signing_payload
    k: fixed nonce (RFC §10.6 uses 0xA/0xB/0xE)
    Implementation: e = SHA-256(M), P = k×G, r = P.x mod n, s = k⁻¹(e + r·d) mod n.
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
    ECDSA P-256 verification (standard rules, accepts both high-s and low-s forms; Low-S is not required by RFC §2.1.2).
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
    # Standard DSS.verify accepts binary-mode raw r‖s
    try:
        verifier.verify(h, signature)
        return True
    except ValueError:
        return False


# ============================================================
# Identifier-Derived Hash (IDH) — RATSI-PKF / RTSAA fingerprint (RFC §2.1.2)
# ============================================================
def idh(algorithm_id_byte0: int, raw_bytes: bytes) -> bytes:
    """
    Identifier-Derived Hash (32B). The algorithm follows algorithm_id byte 0:
      0x01 Ed25519 / 0x02 ECDSA → SHA-256; 0x03 SM2 → SM3.
    raw_bytes: hash input (RATSI-PKF = raw public-key bytes; RTSAA fingerprint = full 168B RTSAA).
    """
    if algorithm_id_byte0 in (0x01, 0x02):
        return hashlib.sha256(raw_bytes).digest()
    elif algorithm_id_byte0 == 0x03:
        return bytes.fromhex(gmssl_sm3.sm3_hash(gmssl_func.bytes_to_list(raw_bytes)))
    else:
        raise ValueError(f"undefined algorithm value 0x{algorithm_id_byte0:02x} (RFC §2.1.2)")
