# Docker 结构化安全测试轨迹

`trajectory-docker-generate` 在本地 Docker 容器中执行内置、确定性、无害的 canary，并将可观察动作、结果、阻碍、恢复策略、容器事件和 SHA-256 证据写入轨迹库。它不会保存模型内部思维过程。

## 快速生成

镜像必须已经存在于本地，命令不会自动拉取：

```powershell
python -m vulntools --db output/vulnerability-master.sqlite trajectory-docker-generate `
  --count 3000 `
  --seed vulntools-docker-lab-v1 `
  --image python:3.12 `
  --output output/docker-trajectories-3000
```

默认 3,000 条在十类场景间轮询分配，因此每个子类型 300 条，技术漏洞与业务逻辑漏洞各 1,500 条：

- 技术类：XSS、SQL 注入、命令注入、SSRF、CSRF。
- 业务逻辑类：参数篡改、批量字段绑定、授权重放、重复提交、流程顺序绕过。

每条场景都有唯一 canary、变体、可选阻碍和主机预先计算的完成摘要。容器返回的场景哈希、证据摘要和身份必须全部匹配，且 canary 验证必须成功，否则整批拒绝导入。确定性的 `task_id` 使相同 seed 重跑时更新原记录，不会重复累加。

## 按大类拆分数据库

```powershell
python -m vulntools --db output/vulnerability-master.sqlite trajectory-split-databases `
  --output output/docker-trajectory-databases-1500-each `
  --expected-per-category 1500
```

该命令仅导出 `environment_kind=docker_canary_lab` 的轨迹，生成通用技术漏洞库 `technical-vulnerabilities.sqlite` 和业务逻辑漏洞库 `business-logic-vulnerabilities.sqlite`。导出器会对每个库执行 SQLite 完整性、外键及类别隔离检查。默认不覆盖已有文件；重新生成时需使用 `--overwrite`。

每个拆分库额外包含：

- `structured_pentest_chains`：任务目标、方法、阻碍、七阶段步骤、恢复策略、完成判据和证据指针。
- `dataset_metadata`：条款编号、最低数量、实际数量、成功数、完整数、类型和阻碍分布以及验收布尔值。

七个固定阶段为：`define_scope`、`form_hypothesis`、`assess_obstacle`、`recover_or_proceed`、`execute_canary`、`verify_evidence`、`complete_task`。每个方法都覆盖无额外阻碍、会话过期、字段别名、输入过滤和状态版本过期五种条件。

可执行独立验收：

```powershell
python scripts/validate_trajectory_databases.py `
  --input output/docker-trajectory-databases-1500-each `
  --expected-per-category 1500
```

## 容器边界

运行参数固定包含：

- `--network=none`
- `--read-only`
- `--cap-drop=ALL`
- `--security-opt=no-new-privileges`
- `--pids-limit=64`
- `--memory=256m`
- `--cpus=1.0`
- 非 root UID/GID 65534
- 仅 `/tmp` 为 32 MiB、`noexec` 的临时文件系统
- `--pull=never`

这些限制适合内置 canary 开发和数据构造，但不宣称等价于经过九项隔离验收的独立 VM。轨迹会记录 `synthetic_scenario=true`、`real_vulnerability_verified=false`、`production_isolation_attested=false` 和 `outcome_scope=docker_lab_canary_only`。

## 产物

- `scenario-input.jsonl`：授权场景清单。
- `container-results.jsonl`：容器逐场景结果。
- `container-stderr.txt`：容器标准错误。
- `trajectories.jsonl`：导入数据库的结构化轨迹。
- `docker-run-manifest.json`：镜像 ID、runner 哈希、限制、数量与工件哈希。
- `dataset/trajectories.jsonl`：数据库内全部轨迹。
- `dataset/trajectory_sft.jsonl`：可观察动作总结 SFT，不包含隐藏思维。

该流程不运行收集到的 PoC，不接受用户提供的 shell/SQL/URL 载荷，也不扫描或请求第三方目标。
