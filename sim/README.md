# RTSAS Simulation Layer (Network Nodes)

This directory is the **simulation layer**, verifying RTSAS's system-design completeness — running
end-to-end flows across four nodes (Root Time Source / RATSI / TTSI / Client).

## Layering

```
ntpv5-rtsas/
├── ref/              Framework layer: executable specification
│   ├── algo.py           Three-algorithm sign/verify + IDH (byte-exact)
│   ├── fields.py         Field encoding + signing payloads (byte-exact)
│   └── vectors.py        Reproduces draft §11 test vectors (51, strict)
└── sim/              Simulation layer: network behavior (this directory)
    ├── root.py           Root Time Source node (signs RTSAA, first level)
    ├── ratsi.py          RATSI node (signs RTSIS + cache + credential tiering)
    ├── ttsi.py           TTSI node (bearer auth + re-originate + relay)
    ├── client.py         Client node (sends requests + verifies RTSAP)
    ├── common.py         Shared simulation logic (reuses framework layer)
    └── demo.py           End-to-end demo (27 completeness checks)
```

**Division**: the framework layer checks "are the bytes right" (byte-exact against the draft); the
simulation layer checks "is the behavior right" (self-consistent networking). The simulation layer
reuses the framework layer for field encoding and signing — no duplication.

## Running

```
python demo.py
```

Expected: `All 27 checks passed`.

## Design points covered

| Mark | Check | Draft |
|---|---|---|
| [A] | Byte sizes: RTSAA 168 / RTSIS 64 / payloads 118·94·31 / Request·Response 280 each | §4 |
| [B] | Two-level chain: Root signs RTSAA → RATSI signs RTSIS → client verifies | §4 |
| [C] | Tamper-evidence: tamper PT / RTSAA / looser RTSAA all fail verification | §8 |
| [D] | State machine: extract hit/NO_CACHE, generate triggers alignment, query discovery | §3.4 |
| [E][F] | Hop-by-hop authorization + re-originate + one-slot cache | §6 |
| [G] | Credential tiering: Generate MUST, Extract/Query SHOULD; public-key location MUST independent | §6.4 |
| [H] | Unsigned notice/fault boundary | §4.3 |
