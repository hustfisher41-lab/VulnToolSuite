# Docker 轨迹运行报告（2026-09-22）

## 结果

在本机 Docker Desktop Linux Engine 上执行了 1,500 个合成授权 canary 场景，并写入 `output/vulnerability-master.sqlite`。

- 批次：`docker-batch:7159f42d7065bfe1da32940f`
- 镜像：`python:3.12`
- 镜像 ID：`sha256:356b87c73c62498fc05b45bd17d7ba87c2ef37b0515beeda690a70982206650b`
- 请求 / 执行 / 成功 / 导入：1,500 / 1,500 / 1,500 / 1,500
- 技术漏洞：750 条
- 业务逻辑：750 条
- 既有 fixture：2 条
- 主库总轨迹：1,502 条
- 总步骤：5,706
- 总运行事件：4,204
- 内部思维字段：0
- 真实互联网漏洞验证：0

十类场景各 150 条：XSS、SQL 注入、命令注入、SSRF、CSRF、参数篡改、批量字段绑定、授权重放、重复提交和流程顺序绕过。五种阻碍 `none`、`session_expired`、`field_alias`、`input_filter`、`state_version` 各 300 条。

## 容器内观测

每条结果均由容器自身返回并由主机校验：

- UID/GID 为 65534。
- `CapEff=0000000000000000`。
- `NoNewPrivs=1`。
- 网络接口仅有 `lo`。
- 根文件系统探测写入被阻断。
- 主机预计算的场景摘要与容器证据摘要一致。

启动限制同时包括禁网、只读根文件系统、丢弃全部 capabilities、禁止提权、64 PID、256 MiB 内存、1 CPU、32 MiB `noexec` 临时目录和禁止自动拉取镜像。

## 工件哈希

- 场景输入：`7ea01c44fbeacfa43de0d432ae84310f2015e1f64d889c8b575dc5b1cae4847a`
- 容器结果：`d10237fa312250eb8c8259495001adc7d1a262d79305cec9a4fb0521cb817bb2`
- 结构化轨迹：`4aa6a9cb0ab6af7eee7e758a2ae327b431c72ba074b7b45903a721e8607162cb`
- 容器 stderr：空文件 SHA-256 `e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855`
- Runner：`0ff51bc93f8c42b5fb25179252b7564abed93c6e21444eca66ee8aa91009c4c8`

独立验证命令：

```powershell
python scripts/validate_docker_trajectories.py `
  --db output/vulnerability-master.sqlite `
  --input output/docker-trajectories-1500 `
  --expected-count 1500
```

验证结果为 `passed`，SQLite `quick_check=ok`，1,500 个任务 ID 与 1,500 个证据摘要均唯一。完整测试为 143 项通过。

## 能力边界

这些轨迹是容器中真实执行的合成 canary，不是简单复制的文本模板；但它们仍不代表真实互联网目标、真实 PoC 或生产级独立 VM 隔离。每条均明确保存 `synthetic_scenario=true`、`real_vulnerability_verified=false`、`production_isolation_attested=false` 和 `outcome_scope=docker_lab_canary_only`。
