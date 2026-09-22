# 第一版验证记录

日期：2026-09-17。环境：Windows、Python 3.13.9。功能代码要求 Python 3.11+。

已执行：

- `python -m pytest -q`：70项测试通过，包括HTTP TestClient。
- 工具一离线测试：覆盖NVD分页与中断恢复、修改时间窗口、CVE滚动增量去重、CVE目录基线续传、旧快照拒绝、AVD页面解析、WAF识别、批量失败与恢复、HTTPS主机限制和429重试。
- 工具一联网抽查：CVE-2024-3094分别通过CVE官方cvelistV5和NVD API 2.0成功采集并写入独立临时库，无失败记录。
- 离线 demo：四类来源、5 条虚构来源记录归并为 3 条规范记录，生成索引与检索产物。
- 中英文路径穿越查询：目标虚构记录 CVE-2099-1001 排在首位。
- 多视图检索：验证 aggregate、description、PoC、component 等视图增量索引，dense/sparse/hybrid 三种模式，严格 CWE/来源过滤、索引状态和逐通道解释。
- 版本与适用性：验证 SemVer 预发布、Python/PEP 440、状态变化、未知厂商规则拒绝，以及 NVD CPE AND/OR/negate 条件、非漏洞环境项和完整环境上下文。
- 检索批量读取：多视图一次查询装载，图像 Evidence 无文本时仍可安全生成检索结果；后端明确报告 `sqlite_exact`。
- 相似度与评测：验证同记录多视图相似度，以及固定相关性标注的 Recall@K、MRR、nDCG 可复算输出。
- 工具五完整离线分析：规范数据指纹、缺失/冲突/分布、训练数据重复与跨划分泄漏、训练曲线和资源诊断、知识注入按种子/数据版本成对比较均通过测试。
- 漂移与增量日志：验证历史质量报告的 Jensen–Shannon/覆盖率漂移、稳定与告警状态、漂移 CSV/API，以及多文件训练日志中的版本切换、失败中断、梯度尖峰和吞吐崩塌。
- 质量、训练和知识注入模拟日志绘图：生成 quality.png、training.png、knowledge-effects.png，人工视觉检查无裁切或文字重叠。
- 工具二：验证 Markdown/HTML 代码、图片引用、OCR 转录和原生图像向量工件的统一 Evidence，图像/模型/向量哈希校验，PURL/CPE/厂商产品分层消歧，强标识冲突进入复核，静态代码行为、来源证据补齐和冲突保留；测试未执行 PoC。
- AVD/CNNVD 授权 API 契约：验证 HTTPS 配置、环境变量认证、JSON Pointer 严格映射、明文凭据拒绝、返回身份校验，以及认证值不进入来源记录。
- 工具三：生成 5 个跨字段正样本和 3 个不同 CWE 负样本，领域适配器 4 轮演示损失从 0.6461 降至 0.6403；适配后的聚类、CWE 类型识别、索引和检索命令可运行。
- sandbox-check：默认策略合法；未配置后端时 execution_ready=false。
- 工具六：不执行样本的 fixture 验证 Agent 鉴权、短期签名证明、九项验收门禁、幂等提交、状态持久化、系统调用日志回收、跨任务与工件限制、销毁、重启恢复及销毁失败节点隔离；不合格能力在提交前失败关闭。

验证重点：幂等导入、原始版本历史、规范修订、撤回失效、冲突保留、严格过滤、版本区间边界、模型不匹配拒绝、非有限向量事务回滚、静态代码不执行、训练异常记录、沙箱无宿主回退。

未验证：CVE/NVD全量生产规模吞吐、AVD/CNNVD真实授权端点的联网可用性、本地真实语义/视觉模型效果、实际 OCR 引擎及语言包、大规模检索性能、真实领域训练效果、真实训练平台，以及专用 Linux/KVM 节点上的 Firecracker supervisor、guest monitor 与九项隔离验收。模拟 API、模拟数据、不执行样本的 fixture、曲线和效果差值仅用于工程验收，不能证明真实隔离。

本轮仅在 VulnToolSuite 内写入代码与产物；未改动旧 VulnPulse。

## 工具六节点资产追加验证（2026-09-17）

本次完整测试：131 项通过；此前 70 项是历史第一版记录。新增覆盖 bounded guest framing、重复键/非有限数/超限拒绝、canary 字节白名单、宿主执行门禁、strace 静态规范化、工件/运行绑定、节点自检不写状态、不输出秘密、部署包清单、验收运行中到期和隔离节点预检。包解压后独立清单复核 39 个文件通过；原生 Git Bash 的 `bash -n` 安装脚本语法检查通过，没有执行安装脚本。

尚未安装独立节点或 VM launcher，没有构建实际 rootfs/内核，没有启动 WSL/Docker/VM 或样例，没有做真实九项隔离验收。guest Popen、strace、vsock 和 cgroup/watchdog 只提供执行组件或协议，不能用 Windows 上的静态/fixture 测试证明实机行为。真实数据库 SHA-256 未变化。资产与缺口见 [节点资产说明](sandbox-node-assets.md) 和 `output/sandbox-node/readiness.json`。
