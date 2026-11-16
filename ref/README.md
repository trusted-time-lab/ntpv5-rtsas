# RTSAS Reference Implementation (Framework Layer)

This directory is the **complete reference implementation** of RTSAS (Root Time Source Alignment
Signature and Transport Protocol, `draft-qiu-ntpv5-root-time-source-alignment-01`). It reproduces
every test vector in draft §11, demonstrating that the protocol is runnable and reproducible across
independent implementations.

> Positioning: this is "running code", intended for IETF Datatracker `related_implementations`
> association (not pseudo-code in the I-D body). The protocol itself is in the draft; this code only
> does byte-exact reproduction and strict cross-checking, and adds no new contract.

**Layering**: this directory is the **framework layer** — the executable specification (three
algorithms + field encoding + test vectors). The **simulation layer** (four-node network) is in
`../sim/`, and reuses this framework layer for signing and field encoding.

## Files

| File | Role | Draft reference |
|---|---|---|
| `algo.py` | Three-algorithm sign/verify + identifier-derived hash (IDH) | §4.4 |
| `fields.py` | Field encoding + three signing-payload constructions | §4.3/§4.5/§4.6 |
| `vectors.py` | Reproduces every §11 test vector (strict cross-check) | §11 |

## Dependencies

```
pip install gmssl cryptography pycryptodome
```

- `gmssl`: SM2 / SM3
- `cryptography`: Ed25519
- `pycryptodome` (`Cryptodome` namespace): ECDSA P-256 point arithmetic (manual fixed k)

## Running

```
python vectors.py
```

Expected output: `51 passed / 0 failed`.

## Three-algorithm coverage

| algorithm_id octet 0 | Algorithm | Signature (64B) | IDH (32B) | Public-key encoding |
|:--:|---|---|---|---|
| 0x01 | Ed25519 / SHA-512 | Ed25519 | SHA-256 | 32B left-aligned, padded to 64B (trailing 32B zero) |
| 0x02 | ECDSA P-256 / SHA-256 | r‖s | SHA-256 | 64B (x‖y, no 0x04) |
| 0x03 | SM2 / SM3 | r‖s | SM3 | 64B (x‖y, no 0x04) |

## Key implementation notes (byte-exact alignment with the draft)

1. **SM2 Za user_id is fixed to the empty string** (`ENTL=0x0000`), `Za = SM3(0x0000 ∥ a ∥ b ∥ xG ∥ yG ∥ xA ∥ yA)`,
   pre-digest `e = SM3(Za ∥ M)`, then sign with fixed k.
2. **Ed25519 public-key field = raw 32B left-aligned + trailing 32B zero** (64B); RATSI-PKF is SHA-256 over the **raw 32B**, not the padded 64B field.
3. **ECDSA fixed k**: manual implementation (`P = k×G`, `r = P.x mod n`, `s = k⁻¹(e + r·d) mod n`).
4. **RTSAA fingerprint = object hash (the full 168B RTSAA, including the root signature)**, using the algorithm indicated by the RTSAA's algorithm_id octet 0.
5. **Mixed algorithms**: root signs with SM2, RTSIS with Ed25519 — independent, each verified under its own algorithm.

## Test-vector coverage

- SM2 RTSAA / RTSIS / client signature
- Query request / notice / fault byte layouts (280B)
- Ed25519 / ECDSA P-256 full set
- Mixed algorithm (root SM2 + RATSI Ed25519)
- Negative cases (algorithm value / public-key padding / tamper and window)

## Test-key warning

The private keys and fixed k used in draft §11 are **public test values**, intended only to reproduce
the test vectors, and must **never be used in production**.
