# Docker 轨迹双库拆分记录（2026-09-22）

## 结果

- Docker 合成 canary 轨迹：3000 条，全部成功。
- 通用技术漏洞：1500 条，5 个子类型各 300 条。
- 业务逻辑漏洞：1500 条，5 个子类型各 300 条。
- 两个拆分库均通过 SQLite `quick_check` 和外键检查。
- 每个库均只含自己的大类，不包含原主库中的 2 条模拟夹具。

## 输出

- `output/docker-trajectory-databases-1500-each/technical-vulnerabilities.sqlite`
- `output/docker-trajectory-databases-1500-each/business-logic-vulnerabilities.sqlite`
- `output/docker-trajectory-databases-1500-each/manifest.json`
- `output/docker-trajectories-3000/docker-run-manifest.json`

## 数据库摘要

| 数据库 | 字节数 | SHA-256 |
|---|---:|---|
| `technical-vulnerabilities.sqlite` | 15,822,848 | `2abebe7dcb308a7747747b22de92860ef4ed11084c47b3bfe14eeb3e5dfb1678` |
| `business-logic-vulnerabilities.sqlite` | 16,609,280 | `a725f493ce63724341359103164cd39eb10c4f47168fb362f044a320a0669399` |

## 边界

这些是在断网、只读根文件系统、无 Linux capabilities 的本地 Docker 环境中执行的合成 canary 轨迹。它们可用于训练“可观察安全测试步骤与证据总结”，但不是模型隐藏思维链，也不证明任何真实生产漏洞。
