# -*- coding: utf-8 -*-
"""
draft01_check.py — 拿 draft-01 的 §11 测试向量去跑模拟（严格校对）

做法：读 draft-01 文件，用正则提取 §11 里「手写的」测试向量输出值
（e / 根签名 / RTSIS / RATSI-PKF / RTSAA 指纹），再用 algo 的算法
从固定密钥 + 时间戳实际派生，逐项断言「文件里写的值 == 代码派生值」。

零失败 = draft-01 §11 的测试向量逐字节正确、可复现，不是手抄错误。

运行：python draft01_check.py "<draft-01 路径>"
"""

import re
import sys
from pathlib import Path

from algo import sm2_e, sm2_sign, ed25519_sign, idh


def load(path):
    return Path(path).read_text(encoding="utf-8")


def extract(pattern, text, name):
    """从文本提取匹配 group(1)，找不到就报错。"""
    m = re.search(pattern, text)
    if not m:
        raise ValueError(f"找不到 {name}（正则 {pattern}）")
    return m.group(1)


def main(draft_path):
    text = load(draft_path)
    passed = 0
    failed = 0

    def check(name, actual_bytes, expected_hex):
        nonlocal passed, failed
        ok = actual_bytes.hex() == expected_hex.lower()
        if ok:
            passed += 1
            print(f"  ✅ {name}")
        else:
            failed += 1
            print(f"  ❌ {name}\n      文件写: {expected_hex}\n      代码算: {actual_bytes.hex()}")

    print("=== 从 draft-01 §11 提取测试向量，代码派生对比 ===\n")

    # ---- 固定输入（标准测试密钥，来自 RFC §10.0，硬编码）----
    SK_ROOT = "0000000000000000000000000000000000000000000000000000000000000001"
    SK_TS   = "0000000000000000000000000000000000000000000000000000000000000002"
    K_CALIB = "000000000000000000000000000000000000000000000000000000000000000A"
    K_TRUST = "000000000000000000000000000000000000000000000000000000000000000B"
    PK_ROOT = "32c4ae2c1f1981195f9904466a39c9948fe30bbff2660be1715a4589334c74c7bc3736a2f4f6779c59bdcee36b692153d0a9877cc62a474002df32e52139f0a0"
    PK_TS   = "56cefd60d7c87c000d58ef57fa73ba4d9c0dfa08c08a7331495c2e1da3f2bd5231b7e7e6cc8189f668535ce0f8eaf1bd6de84c182f6c8e716f780d3a970a23c3"
    # Ed25519 raw 公钥（§11.3）
    PK_TS_ED = "7422b9887598068e32c4448a949adb290d0f4e35b9e01b0ee5f1a1e600fe2674"
    # 时间戳
    TS_SIGNED = "EBE6168000000000"
    TS_FROM   = "EBE6168000000000"
    TS_UNTIL  = "EBE6249000000000"
    TS_PT     = "EBE618D880000000"

    # ---- 从 draft-01 提取输出值 ----
    # §11.1 SM2 RTSAA
    e1_hex     = extract(r"Za_root.*?0x([0-9a-fA-F]{64})", text, "§11.1 e")
    sig1_hex   = extract(r"root_signature = 0x([0-9a-fA-F]{128})", text, "§11.1 root_signature")
    fp1_hex    = extract(r"RTSAA fingerprint = SM3.*?0x([0-9a-fA-F]{64})", text, "§11.1 fingerprint")
    # §11.2 SM2 RTSIS
    pkf_sm2_hex = extract(r"RATSI-PKF = SM3\(pk_ts\).*?0x([0-9a-fA-F]{64})", text, "§11.2 RATSI-PKF")
    e2_hex     = extract(r"Za_ts.*?0x([0-9a-fA-F]{64})", text, "§11.2 e")
    rtsis_hex  = extract(r"RTSIS = 0x([0-9a-fA-F]{128})", text, "§11.2 RTSIS")
    # §11.3 Ed25519 RTSAA
    pkf_ed_hex = extract(r"RATSI-PKF = SHA-256.*?0x([0-9a-fA-F]{64})", text, "§11.3 RATSI-PKF")
    sig_ed_hex = re.findall(r"root_signature = 0x([0-9a-fA-F]{128})", text)[1]  # 第二个 = §11.3 Ed25519
    fp_ed_hex  = extract(r"RTSAA fingerprint = SHA-256.*?0x([0-9a-fA-F]{64})", text, "§11.3 fingerprint")

    # ---- 派生 ----
    # §11.1 SM2 RTSAA（algorithm_id = 0x03）
    alg_sm2 = bytes.fromhex("0300000000000000")
    calib_sm2 = (b"RTSAS-Calib-v1" + alg_sm2 + bytes.fromhex(PK_TS)
                 + (100).to_bytes(8, "big")
                 + bytes.fromhex(TS_SIGNED) + bytes.fromhex(TS_FROM) + bytes.fromhex(TS_UNTIL))
    e1 = sm2_e(PK_ROOT, calib_sm2)
    sig1 = sm2_sign(SK_ROOT, PK_ROOT, calib_sm2, K_CALIB)
    rtsaa_sm2 = alg_sm2 + bytes.fromhex(PK_TS) + (100).to_bytes(8, "big") \
                + bytes.fromhex(TS_SIGNED) + bytes.fromhex(TS_FROM) + bytes.fromhex(TS_UNTIL) + sig1
    fp1 = idh(0x03, rtsaa_sm2)

    print("[§11.1 SM2 RTSAA]")
    check("e", e1, e1_hex)
    check("root_signature", sig1, sig1_hex)
    check("RTSAA fingerprint", fp1, fp1_hex)

    # §11.2 SM2 RTSIS
    pkf_sm2 = idh(0x03, bytes.fromhex(PK_TS))
    trust_sm2 = (b"RTSAS-Trust-v1" + bytes.fromhex("0100000000000000")
                 + pkf_sm2 + fp1 + bytes.fromhex(TS_PT))
    e2 = sm2_e(PK_TS, trust_sm2)
    rtsis = sm2_sign(SK_TS, PK_TS, trust_sm2, K_TRUST)

    print("\n[§11.2 SM2 RTSIS]")
    check("RATSI-PKF", pkf_sm2, pkf_sm2_hex)
    check("e", e2, e2_hex)
    check("RTSIS", rtsis, rtsis_hex)

    # §11.3 Ed25519 RTSAA（algorithm_id = 0x01）
    alg_ed = bytes.fromhex("0100000000000000")
    pk_ed_field = bytes.fromhex(PK_TS_ED) + bytes(32)  # 32B raw + 32B 零填充
    calib_ed = (b"RTSAS-Calib-v1" + alg_ed + pk_ed_field
                + (100).to_bytes(8, "big")
                + bytes.fromhex(TS_SIGNED) + bytes.fromhex(TS_FROM) + bytes.fromhex(TS_UNTIL))
    pkf_ed = idh(0x01, bytes.fromhex(PK_TS_ED))
    sig_ed = ed25519_sign(bytes.fromhex(SK_ROOT), calib_ed)  # seed_root = 1
    rtsaa_ed = alg_ed + pk_ed_field + (100).to_bytes(8, "big") \
               + bytes.fromhex(TS_SIGNED) + bytes.fromhex(TS_FROM) + bytes.fromhex(TS_UNTIL) + sig_ed
    fp_ed = idh(0x01, rtsaa_ed)

    print("\n[§11.3 Ed25519 RTSAA]")
    check("RATSI-PKF", pkf_ed, pkf_ed_hex)
    check("root_signature", sig_ed, sig_ed_hex)
    check("RTSAA fingerprint", fp_ed, fp_ed_hex)

    print(f"\n===== 结果：{passed} 通过 / {failed} 失败 =====")
    if failed == 0:
        print("✅ draft-01 §11 测试向量逐字节正确、可复现")
    else:
        print("❌ 存在手抄错误，需修正 draft-01 §11")
    return failed


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("用法：python draft01_check.py <draft-01 文件路径>")
        sys.exit(1)
    sys.exit(main(sys.argv[1]))
