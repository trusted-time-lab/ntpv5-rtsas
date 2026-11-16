# RTSAS 模拟实现层（系统组网各节点）

本目录是「**模拟实现层**（simulation）」，验证 RTSAS 的系统设计完备性——
用四个节点（根时源 / RATSI / TTSI / 客户端）组网跑端到端流程。

## 分层架构

```
ntpv5-rtsas/
├── ref/              框架层（framework）：协议本体的可执行规范
│   ├── algo.py           三算法签名/验签 + 标识派生哈希（逐字节精确）
│   ├── fields.py         字段编解码 + 三签名原文（逐字节精确）
│   └── vectors.py        复现 draft §11 全部测试向量（51 项，严格校对）
└── sim/              模拟实现层（simulation）：系统组网行为（本目录）
    ├── root.py           根时源节点（签 RTSAA，第一级签名）
    ├── ratsi.py          RATSI 节点（签 RTSIS + 缓存 + 凭证分级）
    ├── ttsi.py           TTSI 节点（bearer 授权 + re-originate + 转发）
    ├── client.py         客户端节点（发请求 + 验 RTSAP）
    ├── common.py         模拟层公共（复用框架层，不重复实现字段/签名）
    └── demo.py           端到端 demo（27 项完备性验证）
```

**分界**：框架层管「字节对不对」（逐字节对齐 draft），模拟层管「行为对不对」（组网流程自洽）。
模拟层**复用框架层**做字段编解码与签名，不重复实现——字段编解码与密码学原语只有一个权威实现。

## 运行

```
python demo.py
```

期望：`全部 27 项验证通过`。

## 覆盖的设计验证点

| 标记 | 验证点 | draft |
|---|---|---|
| [A] | 字节数：RTSAA 168 / RTSIS 64 / 签名原文 118·94·31 / Request·Response 各 280 | §4 |
| [B] | 两级签名链：根时源签 RTSAA → RATSI 签 RTSIS → 客户端验 | §4 |
| [C] | 篡改必暴露：篡改 PT / RTSAA / 换宽松 RTSAA 三路验签失败 | §8 |
| [D] | 状态机：提取命中/NO_CACHE、生成触发对齐、查询发现 | §3.4 |
| [E][F] | 逐跳授权 + re-originate + 缓存一个槽 | §6 |
| [G] | 凭证分级：生成 MUST 验、提取/查询 SHOULD 验；公钥定位 MUST 独立 | §6.4 |
| [H] | 未签名通知/故障边界 | §4.3 |
