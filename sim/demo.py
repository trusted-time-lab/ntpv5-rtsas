# -*- coding: utf-8 -*-
"""
RTSAS 原型 — 端到端演示（四模块完备性验证）

覆盖的设计验证点：
  [A] 字节数：RTSAA 168B / RTSIS 64B / 签名原文 118-94-31B / Request·Response Data 各 280B
  [B] 两级签名链：根时源签 RTSAA → RATSI 签 RTSIS → 客户端验（§4.1–§4.4）
  [C] 篡改必暴露：篡改 PT / 篡改 RTSAA / 换宽松 RTSAA → 验签失败
  [D] 请求-响应状态机：提取（命中缓存/NO_CACHE）、生成（触发对齐+签证明+写缓存）、查询（发现）
  [E] 逐跳授权 + re-originate：TTSI 验下游凭证、用自己的凭证+签名重包装发上游
  [F] 缓存一个槽：覆盖式留最新、提取单跳查缓存、生成递归穿透
  [G] 凭证分级：生成 MUST 验、提取/查询 SHOULD 验；公钥定位 MUST 与凭证有效性验证分级独立
  [H] 未签名通知/故障边界：查询/故障响应无 RTSIS、不可验
"""
from __future__ import annotations

from common import (
    ALG_ED25519, P_CALIB, P_TRUST, P_CLIENT,
    REQ_EXTRACT, REQ_GENERATE, REQ_QUERY,
    RESP_PROOF, RESP_NOTIFY, RESP_FAULT, FAULT_FIX,
    build_rtsaa, build_rtsis, build_response_data, build_request_data, client_sign,
    rtsaa_fingerprint, parse_rtsaa, rtsaa_body, rtsis_payload,
    gen_ed25519, pk_raw_32, pk_from_raw_32, pk_field_64, verify_ed25519,
    u64be, u64be_unpack, make_credential,
)
from root import RootTimeSource
from ratsi import RATSI
from ttsi import TTSI
from client import Client


PASS = 0

def check(name: str, cond: bool, detail: str = ""):
    global PASS
    mark = "✓" if cond else "✗"
    print(f"  [{mark}] {name}" + (f" — {detail}" if detail else ""))
    assert cond, f"验证失败：{name}"
    PASS += 1


def main():
    print("=" * 78)
    print("RTSAS 原型 — 四模块完备性验证（根时源 / RATSI / TTSI / 客户端）")
    print("=" * 78)

    # ============ [A] 字节数自检 ============
    print("\n[A] 字节数自检（§2.1.3 / §2.1.4 / §3.1）")
    check("域前缀 Calib/Trust/Client = 14/14/15B", len(P_CALIB) == 14 and len(P_TRUST) == 14 and len(P_CLIENT) == 15)
    # 临时密钥对，验证结构字节数
    rk, rpk = gen_ed25519()
    sk, pk = gen_ed25519()
    pk64 = pk_field_64(pk)
    pfk = pk_raw_32(pk)
    rtsaa = build_rtsaa(rk, ALG_ED25519, pk64, 100, 1, 1, 2)
    check("RTSAA = 168B", len(rtsaa) == 168)
    rtsis = build_rtsis(sk, RESP_PROOF, pfk, rtsaa_fingerprint(rtsaa), u64be(1))
    check("RTSIS = 64B", len(rtsis) == 64)
    rsp = build_response_data(RESP_PROOF, pfk, rtsis, rtsaa, u64be(1))
    check("Response Data = 280B", len(rsp) == 280)
    req = build_request_data(REQ_GENERATE, ALG_ED25519, make_credential(pfk), client_sign(sk, REQ_GENERATE, b'\x01'*8))
    check("Request Data = 280B", len(req) == 280)
    check("签名原文 Calib=118B", len(P_CALIB + rtsaa_body(ALG_ED25519, pk64, 100, 1, 1, 2)) == 118)
    check("签名原文 Trust=94B", len(rtsis_payload(RESP_PROOF, pfk, rtsaa_fingerprint(rtsaa), u64be(1))) == 94)
    check("签名原文 Client=31B", len(P_CLIENT + REQ_GENERATE + b'\x01'*8) == 31)

    # ============ 阶段 0：密钥 + 带外注册 ============
    print("\n[阶段0] 密钥 + 带外注册（§7.6 公钥带外注册、不承载于凭证内）")
    root = RootTimeSource("Root Time Source")
    ratsi = RATSI("RATSI-A", root, delta_ns=100)
    ttsi = TTSI("TTSI-B", ratsi)
    client = Client("终端客户端", root.pk_raw)

    ratsi.register_client(client.pk_raw)          # 客户端直连 RATSI（带外注册公钥）
    ratsi.register_client(ttsi.pk_raw)            # TTSI 作为「上游的网络时间客户端」带外注册给 RATSI
    ttsi.register_downstream(client.pk_raw)       # 客户端经 TTSI 中转（TTSI 注册下游公钥）
    now = 1_700_000_000
    cookie = b'\xCA\xFE\x01\x02\x03\x04\x05\x06'
    print("  根时源公钥 / RATSI 公钥 / TTSI 公钥 / 客户端公钥 均生成；带外注册完成")

    # ============ [B] 两级签名链（直连生成）============
    print("\n[B] 两级签名链：直连生成（客户端 → RATSI）")
    rsp = client.send_request(REQ_GENERATE, cookie, ratsi, now)
    check("生成返回证明响应（0x01）", rsp[0] == RESP_PROOF[0])
    ok, msg = client.verify_rtsap(rsp)
    check("客户端验 RTSAP 通过（§4.1-§4.4）", ok, msg)

    # ============ [C] 篡改必暴露 ============
    print("\n[C] 篡改必暴露（§1.1 / §11.1 三条密码学保证）")
    # 篡改 PT（偏移 272-279）
    t = bytearray(rsp); t[272] ^= 0xFF
    check("篡改 PT → RTSIS 验签失败", not client.verify_rtsap(bytes(t))[0])
    # 篡改 RTSAA（偏移 104-271，改 δ）
    t = bytearray(rsp); t[104+72] ^= 0x01
    check("篡改 RTSAA(δ) → 根时源验签失败", not client.verify_rtsap(bytes(t))[0])
    # 换宽松 RTSAA（δ 更大）→ RTSIS 中 RTSAA 指纹不匹配
    looser = build_rtsaa(root.sk, ALG_ED25519, pk_field_64(ratsi.pk), 9999, now, now, now+7200)
    t = bytearray(rsp); t[104:272] = looser
    check("换宽松 RTSAA → RTSAA 指纹不匹配 → 验签失败", not client.verify_rtsap(bytes(t))[0])

    # ============ [D] 请求-响应状态机（提取/查询）============
    print("\n[D] 请求-响应状态机（提取单跳查缓存 / 查询发现）")
    rsp2 = client.send_request(REQ_EXTRACT, cookie, ratsi, now)
    check("提取命中缓存 → 返回证明（0x01）", rsp2[0] == RESP_PROOF[0])
    # 新客户端（公钥未带外注册），提取 → 公钥定位失败 → 故障（§7.6 公钥定位 MUST）
    fresh = Client("未注册客户端", root.pk_raw)
    rsp3 = fresh.send_request(REQ_EXTRACT, cookie, ratsi, now)
    check("提取 + 公钥未带外注册 → 定位失败 → 故障（公钥定位 MUST）", rsp3[0] == RESP_FAULT[0])
    # 查询（已注册客户端）
    rsp4 = client.send_request(REQ_QUERY, cookie, ratsi, now)
    check("查询 → 通知（0x02，未签名）", rsp4[0] == RESP_NOTIFY[0])
    check("通知响应无 RTSIS（不可验，§3.3）", not client.verify_rtsap(rsp4)[0])

    # ============ [E]+[F] 逐跳授权 + re-originate + 缓存（中转生成）============
    print("\n[E]+[F] 逐跳授权 + re-originate + 缓存一个槽（客户端 → TTSI → RATSI）")
    rsp5 = client.send_request(REQ_GENERATE, cookie, ttsi, now)
    check("中转生成 → 返回证明（0x01）", rsp5[0] == RESP_PROOF[0])
    ok, msg = client.verify_rtsap(rsp5)
    check("客户端验中转转发的 RTSAP 通过（验签出者 RATSI-A，非转发者 TTSI-B）", ok, msg)
    # TTSI 缓存了证明，后续提取命中（不递归上游）
    rsp6 = client.send_request(REQ_EXTRACT, cookie, ttsi, now)
    check("中转提取命中缓存 → 返回证明（单跳、不递归）", rsp6[0] == RESP_PROOF[0])
    # 提取未命中：新 TTSI（无缓存）
    ttsi2 = TTSI("TTSI-C", ratsi)
    ttsi2.register_downstream(client.pk_raw)
    rsp7 = client.send_request(REQ_EXTRACT, cookie, ttsi2, now)
    check("中转提取未命中缓存 → NO_CACHE 通知（不递归）", rsp7[0] == RESP_NOTIFY[0])

    # ============ [G] 凭证分级 ============
    print("\n[G] 凭证分级（§7.6 方案 C：生成 MUST 验、提取/查询 SHOULD 验）")
    # 撤销客户端凭证（公钥仍在册，但凭证失效）
    ratsi.revoke_credential(client.pk_raw)
    rsp8 = client.send_request(REQ_GENERATE, cookie, ratsi, now)
    check("生成 + 凭证失效 → MUST 拒绝（故障）", rsp8[0] == RESP_FAULT[0])
    rsp9 = client.send_request(REQ_EXTRACT, cookie, ratsi, now)
    check("提取 + 凭证失效 → SHOULD 拒绝（严格实现）", rsp9[0] == RESP_FAULT[0])
    # 恢复凭证
    ratsi.register_client(client.pk_raw)
    # 凭证全 0（字段必备 MUST 拒绝）
    zero_cred = build_request_data(REQ_GENERATE, ALG_ED25519, b'\x00'*200, client_sign(client.sk, REQ_GENERATE, cookie))
    rsp10 = ratsi.handle_request(zero_cred, cookie, now)
    check("凭证全 0 → MUST 拒绝（字段必备，§7.5）", rsp10[0] == RESP_FAULT[0])

    # ============ [H] 未签名通知/故障边界 ============
    print("\n[H] 未签名通知/故障边界（§3.3：不进 RTSIS 原文、客户端「参考」非「确信」）")
    check("通知响应（0x02）verify_rtsap 失败（无 RTSAP 可验）", not client.verify_rtsap(rsp4)[0])
    check("故障响应（0x03）verify_rtsap 失败（无 RTSAP 可验）", not client.verify_rtsap(rsp10)[0])
    check("故障响应偏移 8 = 故障编码 0x02（修）", rsp10[0] == RESP_FAULT[0] and rsp10[8] == FAULT_FIX[0])

    print("\n" + "=" * 78)
    print(f"全部 {PASS} 项验证通过 — RTSAS 核心设计完备性确认")
    print("  · 两级签名链（RTSAA→RTSIS→PT）验签闭环，字节数 168/64/280/280 精确")
    print("  · 篡改必暴露（PT/RTSAA/换宽松 RTSAA 三路验签失败）")
    print("  · 逐跳授权 + re-originate + 缓存一个槽 + 提取单跳/生成递归 行为自洽")
    print("  · 凭证分级（生成 MUST/提取查询 SHOULD）+ 公钥定位 MUST 独立")
    print("=" * 78)


if __name__ == "__main__":
    main()
