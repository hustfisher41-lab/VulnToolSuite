# 工具六：受控沙箱执行协议

工具六的本地协调器只允许把样本提交到独立的一次性 VM 后端。代码中没有本地进程、容器、PowerShell、WSL 或宿主机执行回退。没有通过能力与隔离验收校验时，样本不会提交。

## 强制安全契约

策略要求：VM 隔离、来宾网络关闭、无宿主挂载、只读基础镜像、一次性 overlay、外部看门狗、系统调用监控、超时、内存、CPU 和进程数限制。后端还必须返回以下已通过的验收项：

- 网络阻断；
- 宿主文件系统不可见；
- 超时强制终止；
- 资源超限终止；
- 监控丢失时失败关闭；
- 执行后 overlay 已销毁。

另有三项恢复与完整性验收：控制连接中断后 watchdog 仍销毁、Agent 重启后孤儿资源清理，以及跨任务、重复、超限或篡改工件拒绝。

能力响应必须包含非空 `attestation_id`，以及最长五分钟有效、使用预配置信任密钥签名的结构化证明。证明绑定 backend、Agent 版本、guest 镜像、内核、supervisor 和验收记录摘要。验收记录最长有效 30 天；它不能替代独立安全审计。

## 后端 API

协调器通过双向 TLS 调用：

- `GET /v1/capabilities`；
- `POST /v1/runs`；
- `GET /v1/runs/{run_id}`；
- `GET /v1/runs/{run_id}/artifacts`；
- `DELETE /v1/runs/{run_id}`。

提交内容包含文件名、SHA-256、Base64 样本和完整策略。工件接口只接受 `events.jsonl`、`stdout.txt`、`stderr.txt` 和 `result.json`，每项必须提供 SHA-256。协调器拒绝额外文件名、路径穿越、摘要不匹配、过大响应和缺失的 `events.jsonl`。

`events.jsonl` 每行必须含 `run_id`、`timestamp` 和 `type`。系统调用事件还需 `name` 与整数 `pid`；signal、timeout、oom、policy_violation 和 monitor_lost 会进入异常列表。

## 使用方式

只检查本地策略：

```powershell
python -m vulntools sandbox-check --policy examples/sandbox-policy.json
```

连接已部署并完成验收的 VM 后端：

```powershell
python -m vulntools sandbox-run `
  --policy examples/sandbox-policy.json `
  --sample path/to/sample.bin `
  --output output/sandbox/run-001 `
  --backend-url https://sandbox-control.internal `
  --ca-file certs/ca.pem `
  --cert-file certs/client.pem `
  --key-file certs/client-key.pem `
  --token-env SANDBOX_TOKEN `
  --attestation-key-env SANDBOX_ATTESTATION_KEY
```

令牌和证明密钥都只从环境变量读取。协调器在所有成功或失败路径上请求销毁 VM；销毁未得到确认时整个命令失败，制品也不会发布到最终输出目录。系统调用日志也可离线分析：

```powershell
python -m vulntools sandbox-events --input output/sandbox/run-001/events.jsonl
```

## 部署边界

仓库已经实现协调器、Agent 控制 API、SQLite 状态/审计、幂等键、重启恢复、销毁失败隔离、短期签名证明、验收记录、工件校验、被动分析和可替换 supervisor 接口，并使用不执行样本的 fixture 完成自动测试。部署方法见 [sandbox-deployment.md](sandbox-deployment.md)，特权边界见 [sandbox-supervisor-contract.md](sandbox-supervisor-contract.md)。实际执行仍要求组织在专用 Linux/KVM 节点安装经评审的 Firecracker supervisor、guest monitor 与一次性镜像，并在该真实节点完成九项验收。当前 Windows 开发机不能作为未知样例执行节点。
