# 自动复现小链路：先验流程，再验真实漏洞

当前交付是小链路的离线协议验证，不是实际 CVE 成功复现。当前工作站没有找到已配置并通过隔离验收的独立 VM 后端。真实 PoC 的审核状态和主数据库不会因此改变。

## 两条独立流程

1. 无害 commissioning canary：计划、环境配方、两次提交、结果绑定、日志检查、效果对照、销毁确认和报告。
2. 真实候选 shortlist：从主库只读选择少量活跃漏洞的候选利用代码，生成待审核计划；不导出代码、不执行样本。

canary 是纯内存的虚构权限检查：`owner` 的虚构记录包含 `CANARY_ONLY`，`observer` 访问时，缺少检查版本返回该标记，加入检查版本拒绝访问。没有真实账号、文件访问、子进程或网络，不映射到 CVE，也不生成渗透思维链。

```powershell
# 默认只创建计划，绝不执行
python -m vulntools reproduction-smoke --output output/reproduction-smoke

# 明确使用协议模拟：虚构后端响应，样例也不会在本机运行
python -m vulntools reproduction-smoke --mode fixture --output output/reproduction-smoke

# 真实数据选样：先按可观测效果标题提示选样，再考虑 Linux/Python；不证明兼容性或安全性
python -m vulntools --db output/vulnerability-master.sqlite reproduction-candidates `
  --limit 3 --output output/reproduction-candidates.json
```

每次创建独立的 `attempt_<随机值>` 目录，不覆盖之前的报告；随机 nonce 同时写入样例与预期输出，确保重复尝试的内容摘要和提交幂等键不同。

## 文件与判定

- `plan.json`：样例源文件与提交文件哈希、随机 nonce、策略、环境 pin、运行前提与 oracle。
- `samples/`：准备给隔离 VM 的两个无害 Python 样例；准备文件不等于运行。
- 两个 variant 目录：系统调用日志、stdout、stderr、result、运行报告；只在销毁得到确认后保存。
- `verification-report.json`：每次运行、证据 SHA-256、对照判定及失败原因。

成功必须同时满足：两次运行都完成且已销毁、系统调用日志非空且无关键异常、`result.json` 的 run_id 和 sample_sha256 正确、整数 exit_code 为 0、stdout 结构化观测的 case/nonce/variant/actor/owner 匹配，以及两个版本呈现相反的权限效果。监控丢失、信号、超时、OOM 和策略违规属于关键异常；常见的负返回系统调用（例如解释器查找不存在的库路径）保留计数，但不单独视为漏洞验证失败。仅打印“成功”或退出码 0 不足以通过。runtime 元数据必须由受信 monitor/supervisor 写入，不能直接复制样例声称的元数据。

这个效果 oracle 用于合成样例，不是独立漏洞真实性 oracle，也不能证明虚拟化没有逃逸。真实漏洞必须另外取得独立观测、明确版本和经审核的正负对照。

| 状态 | 含义 |
|---|---|
| `planned` | 仅生成配方与样例 |
| `fixture_passed` | 模拟协议链路通过；没有执行任何样例 |
| `canary_passed` | 独立 VM 中无害合成对照通过；不是 CVE 已验证 |
| `not_confirmed` | 已取回证据，但日志、效果或绑定不符合预期 |
| `blocked_or_failed` | 预检、提交、运行、回收或销毁失败；查看问题和后端审计 |

所有模式都保留 `real_vulnerability_verified=false` 和 `database_updated=false`。fixture 模式还保留 `is_simulated=true`、`sample_executed=false`、`execution_ready=false`。fixture 的 capabilities 和验收项是假数据，只用于检查协议代码，不能用于上线验收。真实执行失败时，如不能知道样例是否运行过，`sample_executed=null`，而不是冒称未运行。

## 接入真实独立节点

先按 [沙箱部署手册](sandbox-deployment.md) 安装独立 Linux/KVM 节点、受审核 supervisor、guest monitor 和镜像，并在节点上完成九项无害验收。canary 的 guest 需有 Python 3 标准库，无 NIC、无宿主挂载、无秘密信息。受信 guest runner 在 monitor 就绪后用 Python 3 执行已验摘要的样例；stdout 仅包含一份 JSON 观测。

supervisor 在原有工件白名单内生成 `result.json`，至少包含：

```json
{"run_id":"实际运行ID","sample_sha256":"实际提交文件的SHA-256","exit_code":0}
```

环境 image/kernel/supervisor 的 SHA-256 都必须提前审核并固定。CLI 只使用校验签名证明的 mTLS HTTPS 后端，不支持本机、WSL、Docker 或未验收后端回退：

```powershell
python -m vulntools reproduction-smoke --mode vm `
  --output output/reproduction-smoke `
  --backend-url https://sandbox-linux-01.internal:9443 `
  --ca-file certs/ca.pem --cert-file certs/client.pem --key-file certs/client-key.pem `
  --token-env SANDBOX_TOKEN --attestation-key-env SANDBOX_ATTESTATION_KEY `
  --image-sha256 <已审核的镜像摘要> `
  --kernel-sha256 <已审核的内核摘要> `
  --supervisor-sha256 <已审核的supervisor摘要>
```

这些是占位参数；没有真实节点、证书、环境变量和摘要时不能运行。不会自动联网安装依赖，也不会下载或运行主库 PoC。

## 本机只读检查结论

2026-09-17：Windows 报告 `HypervisorPresent=true`，vmcompute 与 WslService 正在运行；WSL2 安装 Ubuntu、docker-desktop，两者均停止。未找到 Hyper-V 管理命令 Get-VM、项目生产沙箱配置、沙箱密钥环境变量或本机 9443 监听服务。没有启动 WSL/VM，也没有扫描外部网络。

这仅说明当前工作站/项目没有找到已配置的独立后端，不证明机构其他机器不存在执行节点。已运行的 Windows hypervisor 可能影响 CPU 虚拟化标志的读数，不能仅凭这些标志判断 BIOS 未开启虚拟化。WSL/Docker 可用于开发，但不作为本项目未知 PoC 的生产安全执行边界。

真实 shortlist 仍须人工检查代码、受影响版本和依赖，固定漏洞版与修复版环境，定义独立效果 oracle。先将一个经审核的样本接入，而不是直接执行三个候选或全库样本。

初期 shortlist 保守排除标题/描述中明确的内核、提权和远程代码执行/内存破坏提示，先按信息披露、目录穿越或 XSS 等可观测效果的标题提示排序，再考虑 Linux/Python。关键词筛选不是风险审计，不保证未出现关键词的代码安全；所有候选仍为待审核、不可执行。
