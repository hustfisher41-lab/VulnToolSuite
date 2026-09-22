# Docker 轨迹双库验收记录（2026-09-22）

## 条款验收结果

| 条款 | 数据库 | 要求下限 | 实际数量 | 成功任务 | 完整链 | 结果 |
|---|---|---:|---:|---:|---:|---|
| （3）结构化漏洞渗透思维链 | `technical-vulnerabilities.sqlite` | 1000 | 1500 | 1500 | 1500 | 通过 |
| （4）业务逻辑漏洞渗透思维链 | `business-logic-vulnerabilities.sqlite` | 1000 | 1500 | 1500 | 1500 | 通过 |

两个库均为 100% 任务成功、100% 七阶段完整链、100% 阻碍处理过程完整。它们不包含主库中的 2 条模拟夹具。

## 类型分布

技术漏洞库的 XSS、SQL 注入、命令注入、SSRF、CSRF 各 300 条。

业务逻辑库的参数篡改、绑定破坏（批量赋值）、越权重放、重复提交、跳步乱序各 300 条。

每个方法均覆盖无额外阻碍、会话过期、字段别名、输入过滤、状态版本过期五种条件；每个“方法 × 阻碍”组合 60 条，每个库共 25 个组合。

## 每条链的完整性

每个任务固定保存七个阶段：

1. `define_scope`：确认授权范围、容器限制与唯一 canary。
2. `form_hypothesis`：记录该攻击方法的测试点、假设、无害动作与成功判据。
3. `assess_obstacle`：识别当前阻碍，保存判断依据与容器证据。
4. `recover_or_proceed`：执行对应恢复策略，验证恢复成功且不扩大范围。
5. `execute_canary`：执行类型化的固定合成对照。
6. `verify_evidence`：同时比对可观察证据、恢复结果和 SHA-256 完成摘要。
7. `complete_task`：只有阶段完整、阻碍已解决、完成判据匹配时才标记成功。

每个库有 10,500 条步骤和 4,200 条容器运行事件。

## 数据库结构

- `security_trajectories`：完整任务 JSON 和可检索摘要。
- `security_trajectory_steps`：七阶段步骤、观察、动作、结果、判断依据、恢复策略与证据。
- `security_runtime_events`：容器启动、阻碍恢复和 canary 验证事件。
- `structured_pentest_chains`：可直接用于训练或导出的结构化链。
- `dataset_metadata`：条款编号、数量、成功率、完整率、方法/阻碍覆盖及机械验收结果。

## 输出与摘要

| 数据库 | 字节数 | SHA-256 |
|---|---:|---|
| `technical-vulnerabilities.sqlite` | 42,196,992 | `a5d4d2a4a6c5c93010a4e307cebad73ddc3f9e6137517c7bdd7ac65d0014c22c` |
| `business-logic-vulnerabilities.sqlite` | 42,356,736 | `8ba14cbe487dc72e4179525e73c3bdeca523a9b2c6e90456fadbda201dbd821f` |

目录：`output/docker-trajectory-databases-1500-each/`。机器可读验收清单为同目录的 `manifest.json`。

独立验收命令：

```powershell
python scripts/validate_trajectory_databases.py `
  --input output/docker-trajectory-databases-1500-each `
  --expected-per-category 1500
```

结果：`status=passed`，两库 `quick_check=ok`，外键违规为 0，类别隔离通过，任务表与结构化链表的主键集合一致。

## 边界

这里的“思维链”是可公开审计的结构化渗透决策轨迹，不是模型私有的隐藏推理。任务在断网、只读根文件系统、无 Linux capabilities 的本地 Docker 环境中执行，不存储可用于攻击真实目标的载荷，也不证明任何生产漏洞。
