# 独立沙箱节点执行资产：当前交付与启用边界

本轮补齐可导出的节点资产和 canary-only 来宾监控器，不代表已建立或验收独立 VM。当前 Windows 主机只作为控制端，不安装执行节点，也不启动 WSL、Docker、虚拟机或未知 PoC。

## 新增工程能力

- `sandbox-node-check`：只读检查 Linux、专用节点确认、非 WSL/容器、KVM API、cgroup v2、watchdog 工具、生产配置、环境变量、文件所有权/摘要和新鲜签名验收。KVM ioctl 只读取 API 版本，不创建 VM。诊断本身不是联网验证或安全验收，`execution_ready` 始终为 false。
- `sandbox-node-bundle`：导出固定文件清单内的代码、systemd 单元、离线 bootstrap、哈希验证器和配置样例；不含数据、证书、密钥或环境文件，不安装、不启用服务。
- `guest_channel`：有长度上限的 JSON framing，拒绝截断、重复键、非有限数字和超限数据；支持 Firecracker host-initiated vsock UDS 握手，不使用 TCP/IP。回复需校验 run_id、样例哈希、工件白名单/哈希和日志绑定。
- `guest_monitor`：单 VM、单请求、仅内置无害权限对照 canary；受信 root monitor 启动 strace 后，以 UID/GID 10000 运行 Python 样例。限制内存、CPU、进程、文件和输出大小，记录 syscall、返回值、信号与退出结果。不存在任意命令、用户指定解释器/路径、真实 PoC 模式或宿主回退。
- 门禁修复：生产验收记录在服务持续运行时过期，也立即禁止新任务；隔离或明确不可执行的节点在控制端预检失败。Agent 资源配置严格验证整数和范围。

这些组件在 Windows 上仅做纯数据和模拟测试；来宾 Popen/strace、KVM、镜像、watchdog、VM 销毁均没有真实 Linux 节点验证，不得用测试通过替代隔离认证。

## 生成与自检

```powershell
python -m vulntools sandbox-node-check --output output/sandbox-node/node-check.json
python -m vulntools sandbox-node-bundle --output output/sandbox-node
```

Windows 自检返回 2 表示节点条件未满足，不是工具故障。输出 zip 和其 SHA-256，应经批准通道传送并独立确认 SHA-256 后解压。包内清单只检查一致性，不证明来源可信；如果清单、验证器同时被篡改，内部自检不能认证安全。

在专用 Linux 节点上，由管理员审查代码和部署文件，准备离线 wheelhouse 后执行：

```bash
python3 deployment/verify-node-bundle.py /approved/extracted/bundle
bash deployment/install-sandbox-node.sh --confirm-dedicated-node --wheelhouse /approved/wheels
```

bootstrap 只安装 venv、专用非登录用户、Agent 单元和未填写的配置模板，拒绝覆盖已有安装；不运行 acceptance、不启用 systemd、不生成或泄露密钥、不创建 VM。Python 3.11+、venv 和 wheelhouse（包括构建依赖及 FastAPI/Uvicorn）须管理员提前准备。保留 agent.env 和 mTLS 所需证书，按部署手册设置权限与机构密钥管理，不在代码/JSON 中写秘密。

## 来宾镜像准备：只在镜像构建环境内

guest rootfs 使用相同已审查 bundle 的 Python 包，提前安装 Python 3、strace 与 vsock 内核支持。创建 UID/GID 10000，准备只读基础镜像与可写 `/run` tmpfs，不含外部凭据、宿主目录或 NIC。

在构建中的来宾文件系统内放入 root-owned、不可组/其他写入的 `/etc/vulntools-guest-canary`，内容为 `canary-only-v1`。安装 `vulntools-guest-monitor.service` 作为来宾服务，不是宿主服务；启动参数加入精确 token `vulntools_guest=canary`。将 package 安装到 `/usr/bin/python3` 能读取的系统路径。不能通过在工作站伪造 marker 来声称虚拟机隔离成立。

监控器检查 Linux/root/marker/boot token/无 NIC/受信解释器和 strace；只接受 host CID=2 的一次请求，监听 vsock port 4050。请求 policy 与控制端一致，样例必须与镜像内置 canary 字节一致并绑定随机 nonce。其他代码即使有正确 SHA-256 也被拒绝。

strace 首版仅规范完整行，保留 raw 与位置；不支持的 unfinished/resumed 行、日志格式错误、超限或无 syscall 会失败关闭。不能拿它声称覆盖所有恶意行为或内核权限样例。监控程序自身与 tracer 的抗干扰仍须真实 guest 验收；未知 PoC 不能仅凭这个监控器启用。

## 与真实 supervisor 的集成

现有 Agent 对接的是 hash-pinned supervisor 客户端。Agent 的 NoNewPrivileges 和非 root 身份不可放宽；有权限创建 microVM 的独立服务必须经评审并通过本地 peer credential/权限验证，不得改成任意 sudo/shell 包装器。该特权服务/VM launcher **本项目仍未提供或上线**。

经评审 supervisor 在单次 VM 启动和 monitor 就绪后，可以使用以下纯数据与通道 helper：

```python
from vulntools.guest_monitor import canary_guest_request
from vulntools.guest_channel import request_guest, decode_guest_response

request = canary_guest_request(sample_bytes, run_id, policy)
response = request_guest(actual_vm_vsock_uds, request, port=4050,
                         timeout=policy.timeout_seconds + 15)
artifacts = decode_guest_response(response, run_id=run_id,
                                  sample_sha256=request["sample_sha256"])
```

helper 不创建 VM、cgroup 或 watchdog，也不销毁 VM。supervisor 必须先完成 jailer、只读 base/一次性 overlay、无 NIC、CPU/内存/PID/磁盘限制、宿主独立 watchdog；只写四个允许工件，始终停止 VM 和销毁 overlay 后返回。不得把 guest 的“成功”作为宿主清理成功。Firecracker vsock 的设计参考 [官方通道文档](https://github.com/firecracker-microvm/firecracker/blob/main/docs/vsock.md)，隔离宿主配置仍按 [官方 jailer 文档](https://github.com/firecracker-microvm/firecracker/blob/main/docs/jailer.md)独立审查。

配齐节点、supervisor 服务、镜像、mTLS 与环境变量后，先做九项真实验收，再启用 Agent；`reproduction-smoke --mode vm` 只运行无害对照。可复现且记录正确后再扩展经审核的任务配方和独立效果 oracle，不能将 canary 通过直接标为真实 CVE 的 `sandbox_verified`。

## 尚缺资产

1. 独立 Linux/KVM 主机及管理员部署许可。
2. 经评审的特权 Firecracker supervisor/launcher 和独立 watchdog 实现。
3. 实际构建并固定摘要的 rootfs/内核。
4. mTLS 证书、秘密环境变量和防火墙规则。
5. 九项真实隔离/恢复/完整性验收记录。

所以当前状态为“可交付节点组件，未部署，未认证”，不是“沙箱已经能执行全库 PoC”。
