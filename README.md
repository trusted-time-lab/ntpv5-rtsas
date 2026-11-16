# RTSAS Reference Implementation

参考实现 for the **Root Time Source Alignment Signature and Transport Protocol (RTSAS)**，
对应 Internet-Draft `draft-qiu-ntpv5-root-time-source-alignment-01`。

RTSAS 是一个 NTPv5 扩展字段协议，把时间值的出身从「声称」变成「证据」：一个预信任的
根时源（Root Time Source）先认证某个时间服务实例的时钟已对齐物理源，该实例再签时间值；
客户端只持根公钥，离线验证两级签名。

本仓库是「running code」——三算法（Ed25519 / ECDSA P-256 / SM2）签名、字段编解码、
两级签名链、四节点组网，复现 draft §11 全部测试向量（正例 + 反例）。

## 结构

| 目录 | 职责 |
|---|---|
| [`ref/`](ref/) | 框架层：协议本体的可执行规范（三算法 + 字段编解码 + 测试向量复现） |
| [`sim/`](sim/) | 模拟层：四节点组网（根时源 / RATSI / TTSI / 客户端）端到端验证 |

## 依赖

```
pip install gmssl cryptography pycryptodome
```

- `gmssl`：SM2 / SM3
- `cryptography`：Ed25519
- `pycryptodome`（`Cryptodome` 命名空间）：ECDSA P-256 点运算（手动固定 k）

## 运行

框架层（复现 draft §11 测试向量，51 项正反例）：

```
cd ref && python vectors.py
```

模拟层（四节点组网完备性，27 项）：

```
cd sim && python demo.py
```

## 许可

Simplified BSD License（见 [LICENSE](LICENSE)）。测试向量所用私钥均为公开测试值，严禁用于生产。
