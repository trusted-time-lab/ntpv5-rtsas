# RTSAS 参考实现（框架层，多算法）

本目录是 RTSAS（Root Time Source Alignment Signature and Transport Protocol，
对应 `draft-qiu-ntpv5-root-time-source-alignment-01`）的**完整参考实现**，
复现 draft §11 全部测试向量，证明协议可运行、跨实现可一致。

> 定位：这是「running code」——用于 IETF Datatracker 的 `related_implementations`
> 关联（不是 I-D 正文附录的伪代码）。协议本身见 draft 正文，本代码只做「逐字节
> 复现 + 严格校对」，不新增契约。

**分层**：本目录是「**框架层（framework）**」——协议本体的可执行规范（三算法 +
字段编解码 + 测试向量）。系统组网的「模拟实现层（simulation）」在 `../sim/`
（根时源 / RATSI / TTSI / 客户端四节点），它**复用本框架层**做签名与字段编解码，
不重复实现。

## 目录结构

| 文件 | 职责 | 对齐 draft |
|---|---|---|
| `algo.py` | 三算法签名/验签 + 标识派生哈希（IDH） | §4.4 算法标识 |
| `fields.py` | 字段编解码 + 三签名原文构造 | §4.3/§4.5/§4.6 |
| `vectors.py` | 复现 §11 全部测试向量（严格校对） | §11 |

## 依赖

```
pip install gmssl cryptography pycryptodome
```

- `gmssl`：SM2 / SM3
- `cryptography`：Ed25519
- `pycryptodome`（`Cryptodome` 命名空间）：ECDSA P-256 的点运算（手动固定 k）

## 运行

```
python vectors.py
```

期望输出：`51 通过 / 0 失败`，`✅ 全部通过 —— 参考实现与 draft §11 逐字节一致`。

## 三算法覆盖

| algorithm_id 字节 0 | 算法 | 签名（64B） | IDH（32B） | 公钥编码 |
|:--:|---|---|---|---|
| 0x01 | Ed25519 / SHA-512 | Ed25519 | SHA-256 | 32B 左对齐填 64B（尾 32B 零） |
| 0x02 | ECDSA P-256 / SHA-256 | r‖s | SHA-256 | 64B（x‖y 无 0x04） |
| 0x03 | SM2 / SM3 | r‖s | SM3 | 64B（x‖y 无 0x04） |

## 关键实现要点（与 draft 逐字节对齐）

1. **SM2 的 Za user_id 定死空串**（`ENTL=0x0000`），`Za = SM3(0x0000 ∥ a ∥ b ∥ xG ∥ yG ∥ xA ∥ yA)`，
   预摘要 `e = SM3(Za ∥ M)`，再固定 k 签名。
2. **Ed25519 公钥字段 = raw 32B 左对齐 + 尾 32B 零**（64B）；RATSI-PKF 对 **raw 32B** 做 SHA-256，**非**填充后 64B 字段。
3. **ECDSA 固定 k**：手动实现（`P = k×G`，`r = P.x mod n`，`s = k⁻¹(e + r·d) mod n`）。
4. **RTSAA 指纹 = 对象哈希（完整 168B RTSAA，含根时源签名）**，算法随 RTSAA 的 algorithm_id 字节 0。
5. **混合算法**：根时源签名用 SM2、RTSIS 用 Ed25519，两者独立、各按各的算法验签。

## 测试向量覆盖

- SM2 RTSAA / RTSIS / 客户端签名
- 查询请求 / 通知 / 故障字节布局（280B）
- Ed25519 / ECDSA P-256 全套
- 混合算法（根 SM2 + RATSI Ed25519）
- 负向测试（算法值 / 公钥填充 / 篡改与窗口）

## 测试密钥警告

draft §11 使用的私钥与固定随机数 k 均为**公开测试值**，仅用于复现测试向量，
**严禁用于生产**（draft §11 明示）。
