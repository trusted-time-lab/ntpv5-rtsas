# RTSAS Reference Implementation

Reference implementation for the **Root Time Source Alignment Signature and Transport Protocol (RTSAS)**,
as specified in Internet-Draft `draft-qiu-ntpv5-root-time-source-alignment-01`.

> **Draft text**: [`trusted-time-lab/draft-ntpv5-rtsas`](https://github.com/trusted-time-lab/draft-ntpv5-rtsas)

RTSAS is an NTPv5 extension that turns a time value's provenance from a *claim* into *evidence*: a
pre-trusted Root Time Source first attests that a given time service instance's clock has been
checked for alignment against a physical source; that instance then signs the time value itself. A
client holding only the root public key verifies both signatures offline.

This repository is "running code" — three-algorithm signing (Ed25519 / ECDSA P-256 / SM2), field
encoding, the two-level signature chain, and a four-node simulation, reproducing every test vector
in draft §11 (positive and negative cases).

## Structure

| Directory | Role |
|---|---|
| [`ref/`](ref/) | Framework layer: the executable specification (three algorithms + field encoding + test-vector reproduction) |
| [`sim/`](sim/) | Simulation layer: four-node network (Root Time Source / RATSI / TTSI / Client) end-to-end verification |

## Dependencies

```
pip install gmssl cryptography pycryptodome
```

- `gmssl`: SM2 / SM3
- `cryptography`: Ed25519
- `pycryptodome` (`Cryptodome` namespace): ECDSA P-256 point arithmetic (manual fixed k)

## Running

Framework layer (reproduces draft §11 test vectors, 51 positive/negative cases):

```
cd ref && python vectors.py
```

Simulation layer (four-node network completeness, 27 checks):

```
cd sim && python demo.py
```

## License

Simplified BSD License (see [LICENSE](LICENSE)). All private keys used in the test vectors are public test values, never for production use.
