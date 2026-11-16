# -*- coding: utf-8 -*-
"""
RTSAS simulation layer — common module (reuses the framework layer ref)

Layered architecture (established 2026-11-16):
  Framework layer ref
    = executable specification of the protocol core: three-algorithm signing/verification
      + Identifier-Derived Hash + field encoding/decoding + signing payloads.
      Byte-exact, strictly checked against RFC §10 (51 test vectors, zero failures).
  Simulation layer sim
    = behavior of each node in the system topology: Root Time Source / RATSI / TTSI / client,
      validating design completeness for alignment, cache, hop-by-hop authorization,
      recursion, and credential tiering.

This module is the shared part of the "simulation layer": it only implements simulation business
logic (credentials / notices / faults / constants / key utilities), and does **not** re-implement
protocol field encoding/decoding or cryptographic primitives — it uniformly reuses the framework
layer algo + fields.
("Within the whole data structure, data with the same semantics should not be duplicated unless
necessary" — field encoding/decoding and signing have a single authoritative implementation.)
"""
from __future__ import annotations

import hashlib
import os
import sys

# ---- reuse framework layer (cross-directory import ref) ----
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

# ============ constants (simulation-layer business constants, aligned to RFC §2.1.2 / §3.1-§3.3) ============
ALG_ED25519  = b'\x01' + b'\x00' * 7           # algorithm_id byte 0 = 0x01 Ed25519; byte 1 = RTSAA Era = 0
REQ_EXTRACT  = b'\x01' + b'\x00' * 7           # request mode 0x01 Extract (single-hop cache lookup)
REQ_GENERATE = b'\x02' + b'\x00' * 7           # request mode 0x02 Generate (recurse to RATSI, trigger alignment)
REQ_QUERY    = b'\x03' + b'\x01' + b'\x00' * 6  # request mode 0x03 Query, byte 1 = query type 0x01
RESP_PROOF   = b'\x01' + b'\x00' * 7           # response mode 0x01 Proof (RTSAP, signed)
RESP_NOTIFY  = b'\x02' + b'\x00' * 7           # response mode 0x02 Notice (unsigned)
RESP_FAULT   = b'\x03' + b'\x00' * 7           # response mode 0x03 Fault (unsigned)
FAULT_FIX    = b'\x02' + b'\x00' * 7           # fault code 0x02 fix (client's own problem)

# ============ key utilities (seed as bytes, reuse framework-layer signing/verification) ============
def gen_ed25519():
    """Generate an Ed25519 keypair, return (seed 32B, public key raw 32B)."""
    sk = Ed25519PrivateKey.generate()
    seed = sk.private_bytes(serialization.Encoding.Raw,
                            serialization.PrivateFormat.Raw,
                            serialization.NoEncryption())
    pk_raw = sk.public_key().public_bytes(serialization.Encoding.Raw,
                                          serialization.PublicFormat.Raw)
    return seed, pk_raw


def pk_raw_32(pk: bytes) -> bytes:
    """Public key raw 32B (in this simulation layer keys are seed-bytes, pk is raw bytes, identity)."""
    return pk


def pk_from_raw_32(raw: bytes) -> bytes:
    """Get public key from raw 32B (this simulation layer verifies against raw bytes, identity)."""
    return raw


def pk_field_64(pk_raw: bytes) -> bytes:
    """RATSI public key field inside RTSAA = raw 32B left-aligned + trailing 32B zeros (Ed25519, §2.1.2)."""
    return pk_raw + b'\x00' * 32


def sign_ed25519(seed: bytes, payload: bytes) -> bytes:
    return ed25519_sign(seed, payload)          # 64B


def verify_ed25519(pk_raw: bytes, payload: bytes, sig: bytes) -> bool:
    return ed25519_verify(pk_raw, payload, sig)


# ============ hashes (reuse framework-layer idh, Ed25519 → SHA-256) ============
def sha256(data: bytes) -> bytes:
    return hashlib.sha256(data).digest()


def ratpsi_pkf(pk_raw_32: bytes) -> bytes:
    """RATSI-PKF = Identifier-Derived Hash (raw 32B public key, SHA-256, §2.1.2)."""
    return idh(0x01, pk_raw_32)


def rtsaa_fingerprint(rtsaa_168: bytes) -> bytes:
    """RTSAA fingerprint = object hash (full 168B RTSAA, SHA-256, §2.1.2)."""
    return idh(0x01, rtsaa_168)


# ============ uint64 BE encoding/decoding (time / δ, 8B) ============
def u64be(n: int) -> bytes:
    return n.to_bytes(8, 'big')


def u64be_unpack(b: bytes) -> int:
    return int.from_bytes(b, 'big')


# ============ RTSAA (168B, reuse framework-layer build_calib_payload + build_rtsaa) ============
def rtsaa_body(alg_id: bytes, pk_64: bytes, delta: int,
               issued: int, vfrom: int, vuntil: int) -> bytes:
    """RTSAA signing payload body (104B, = framework-layer Calib payload minus the 14B domain prefix)."""
    payload = build_calib_payload(alg_id, pk_64, delta, u64be(issued), u64be(vfrom), u64be(vuntil))
    return payload[14:]                          # strip "RTSAS-Calib-v1"


def build_rtsaa(seed: bytes, alg_id: bytes, pk_64: bytes, delta: int,
                issued: int, vfrom: int, vuntil: int) -> bytes:
    """Root Time Source signs RTSAA (first-level signature, 168B). seed is the Root Time Source Ed25519 seed."""
    payload = build_calib_payload(alg_id, pk_64, delta, u64be(issued), u64be(vfrom), u64be(vuntil))
    sig = ed25519_sign(seed, payload)
    return _ref_build_rtsaa(alg_id, pk_64, delta, u64be(issued), u64be(vfrom), u64be(vuntil), sig)


def parse_rtsaa(rtsaa: bytes) -> dict:
    """Split RTSAA 168B (reuse framework-layer split_rtsaa, convert times to int for simulation-layer comparison)."""
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


# ============ RTSIS (64B, reuse framework-layer build_trust_payload) ============
def rtsis_payload(resp_mode: bytes, pkf: bytes, rtsaa_fp: bytes, pt: bytes) -> bytes:
    """RTSIS signing payload 94B (= framework-layer Trust payload, includes domain prefix)."""
    return build_trust_payload(resp_mode, pkf, rtsaa_fp, pt)


def build_rtsis(seed: bytes, resp_mode: bytes, pkf: bytes, rtsaa_fp: bytes, pt: bytes) -> bytes:
    """RATSI signs RTSIS (second-level signature, 64B). seed is the RATSI Ed25519 seed."""
    payload = build_trust_payload(resp_mode, pkf, rtsaa_fp, pt)
    return ed25519_sign(seed, payload)


# ============ RTSAS-Request / Response Data (280B each, reuse framework layer) ============
def build_response_data(resp_mode: bytes, pkf: bytes, rtsis: bytes,
                        rtsaa: bytes, pt: bytes) -> bytes:
    return _ref_build_response(resp_mode, pkf, rtsis, rtsaa, pt)


def build_request_data(req_mode: bytes, client_alg: bytes,
                       credential: bytes, client_sig: bytes) -> bytes:
    return _ref_build_request(req_mode, client_alg, credential, client_sig)


def client_sign(seed: bytes, req_mode: bytes, cookie: bytes) -> bytes:
    """Client signature (reuse framework-layer build_client_payload + Ed25519 signing)."""
    payload = build_client_payload(req_mode, cookie)
    return ed25519_sign(seed, payload)


# ============ API credential (200B, internal structure is issuer-defined, not specified by the protocol) ============
# Simplification: first 32B of the credential = client public-key hash (as the "credential→public key" association key, for locating the public key), the rest is padding.
def make_credential(pk_raw_32: bytes) -> bytes:
    assert len(pk_raw_32) == 32
    return sha256(pk_raw_32) + b'\xAB' * (200 - 32)   # first 32B = public-key fingerprint (association key)


def credential_key_hash(credential: bytes) -> bytes:
    """Extract the "client public-key hash" from the credential (association key, for locating the public key)."""
    assert len(credential) == 200
    return credential[0:32]


# ============ notice / fault responses (§3.3, unsigned, reuse 272B field) ============
def build_notify(text: str) -> bytes:
    """Notice response Data 280B = response mode(8, 0x02) + notice result(272, UTF-8 + 0x00 terminator + 0x00 padding)."""
    raw = text.encode('utf-8')[:271]
    result = raw + b'\x00' + b'\x00' * (271 - len(raw))
    assert len(result) == 272
    return RESP_NOTIFY + result


def build_fault(fault_code: bytes, text: str) -> bytes:
    """Fault response Data 280B = response mode(8, 0x03) + fault code(8) + description text(264, UTF-8 + 0x00 terminator + padding)."""
    raw = text.encode('utf-8')[:263]
    desc = raw + b'\x00' + b'\x00' * (263 - len(raw))
    assert len(desc) == 264
    return RESP_FAULT + fault_code + desc
