# VulnToolSuite

六个漏洞工具的独立 Python 工程。代码、配置、测试和产物均保存在此目录；不导入或修改相邻 VulnPulse 项目。

当前版本 0.2：采集、处理、嵌入、检索和分析的本地工程链路已经贯通；沙箱仅完成控制面和离线验收资产，连接通过验收的独立执行节点前不可执行样本。标准库即可运行导入、多模态处理、领域度量训练、混合检索、JSON/CSV 分析和远程 VM 协调；绘图、OCR、本地语义模型和 HTTP API 是可选能力。

PoC 工件使用独立表保存代码版本、SHA-256、上游提交和 CVE 多对多关联。目前支持静态导入 Nuclei 与 Exploit-DB；检测模板和利用代码分开统计，采集过程绝不执行代码。详见 [PoC 工件说明](docs/poc.md)。

自动复现先提供无害双版本 canary 的计划/协议模拟/真实 VM 三种模式，以及真实主库的只读候选选样。当前只完成离线链路，模拟通过不标记 PoC 已验证；真实 VM 仍须独立节点和隔离验收。详见 [复现小链路说明](docs/reproduction-smoke.md)。

工具六另提供只读节点自检、离线部署包、受限 vsock 通道和 canary-only 来宾监控器。当前未安装独立 VM、镜像或特权 launcher；这些组件与单元测试不能代替真实隔离验收。详见 [沙箱节点资产](docs/sandbox-node-assets.md)。

训练数据 v2 使用按共享 PoC 和重复内容家族固定划分的 JSONL 数据包，提供知识注入、证据抽取 SFT、RAG 与 CVE 查询数据；自动偏好候选独立待审，正式 DPO 文件为空，缺少补丁证据时不生成虚构修复建议。详见 [训练数据集说明](docs/training-dataset.md)。

## 六个工具的实现状态

| 模块 | 已实现 | 后续工作 |
|---|---|---|
| 采集 | CVE JSON 5.2/CNA+ADP、NVD 2.x、AVD/CNNVD公开页及交换文件解析；CVE滚动增量、官方仓库基线续传、NVD 120天窗口分页与全量续传；配置化授权 JSON API、环境变量认证、单条/批量采集、限速重试、时间水位、防旧快照覆盖、失败队列、状态接口 | AVD/CNNVD没有稳定免登录公开API；生产可用性仍须用机构取得的真实授权接口和凭据验收，不绕过访问控制 |
| 处理 | CVE 精确统一、字段来源与冲突；文本、Markdown/HTML 代码、图片引用、OCR 转录、原生图像向量工件及补丁的 aligned/v1 表征；PURL/CPE/厂商产品保守消歧；静态代码行为；受预算约束的联网补齐；疑似重复审核 | 厂商更名、收购和缺少稳定标识的产品仍需人工词表；视觉模型效果仍须使用本地模型和标注集验收 |
| 嵌入 | 特征哈希和本地 SentenceTransformer；监督式领域余弦适配器训练；多视图增量索引；相似检索、PoC 匹配、聚类、CWE 类型识别及 CLI/HTTP 接口 | 大模型端到端微调、人工困难负例集、真实冻结基准上的领域效果验收 |
| 检索 | 描述/PoC/组件/补丁多视图索引，余弦 + BM25 + RRF，批量视图读取，Top-K 与分页；SemVer、PEP 440、Maven、日期/数字版本及状态变化；NVD CPE AND/OR/negate 条件树严格过滤；逐通道解释、离线 Recall/MRR/nDCG 评测及 Python/CLI/HTTP 接口 | 超大规模数据可按部署容量换用 ANN 后端，并在固定规模和硬件上重新验收召回与延迟 |
| 分析 | 规范数据质量、样本/标签/模态/划分统计，类别不均衡、重复样本及跨划分泄漏检查；单文件或增量日志目录的 loss/梯度/吞吐/资源/中断诊断；知识注入成对比较；基于历史报告的分布与覆盖率漂移；JSON/CSV、四类 PNG 图表及漂移 API | 训练平台专用连接器和多人交互看板属于部署集成工作 |
| 沙箱 | 严格策略、mTLS 协调器；独立 Agent API、持久状态/审计、幂等提交、重启清理、节点隔离、短期签名证明、样本删除、工件哈希与任务绑定；真实 VM supervisor 契约及九项验收工作流 | 在专用 Linux/KVM 节点安装经评审的 Firecracker supervisor、guest monitor 和镜像，执行硬件环境验收；Windows及内核样本需独立池 |

默认特征哈希向量**不是语义嵌入**；在其上训练的领域适配器仍是词法度量。OCR 接口要求已安装 Tesseract 和语言包；语义接口要求已有本地模型目录，均不会自动下载。沙箱只有连接通过验收的独立 VM 后端后才可执行。

## 快速开始（PowerShell）

Python 3.11+，在本项目根目录执行：

```powershell
python -m vulntools --db output/demo.sqlite demo --output output/demo
python -m vulntools --db output/demo.sqlite search --query "解压路径穿越"
python -m vulntools --db output/demo.sqlite search --query "archive" --component demo-archive --version 1.1.0
python -m vulntools --db output/demo.sqlite index-status
python -m vulntools --db output/demo.sqlite similarity --left CVE-2099-1001 --right CVE-2099-1002
python -m vulntools --db output/demo.sqlite evaluate-search --input examples/search-eval.jsonl --cutoffs 1 3
python -m vulntools --db output/demo.sqlite collection-status
python -m vulntools sandbox-check --policy examples/sandbox-policy.json
python -m vulntools sandbox-events --input examples/syscalls.jsonl
```

真实主库的“一键可用闭环”（数据库 → 索引 → 检索 → 现有训练集 → 无害 fixture → 结构化轨迹 → 轨迹 SFT）如下：

```powershell
python -m vulntools --db output/vulnerability-master.sqlite simple-closure `
  --output output/simple-closure `
  --query "CVE-1999-0001 BSD crafted packets" `
  --expected-id CVE-1999-0001
```

该命令的安全测试部分明确是 fixture 工作流，只验证轨迹、证据、事件和导出链路，不能作为 Docker/VM 隔离或真实漏洞复现证明。结果写入 `output/simple-closure/closure-report.json`。

结构化轨迹也可单独操作：

```powershell
python -m vulntools --db output/vulnerability-master.sqlite trajectory-smoke --output output/trajectory-smoke
python -m vulntools --db output/vulnerability-master.sqlite trajectory-status
python -m vulntools --db output/vulnerability-master.sqlite trajectory-export --output output/security-trajectories
python -m vulntools --db output/vulnerability-master.sqlite trajectory-import --input authorized-trajectories.jsonl
python -m vulntools --db output/vulnerability-master.sqlite trajectory-docker-generate `
  --count 3000 --output output/docker-trajectories-3000 --image python:3.12
python -m vulntools --db output/vulnerability-master.sqlite trajectory-split-databases `
  --output output/docker-trajectory-databases-1500-each `
  --expected-per-category 1500
```

Docker 命令只使用本地已有镜像且禁止自动拉取，以禁网、只读根文件系统、丢弃 capabilities、禁止提权和资源限制运行内置无害 canary。它生成 10 类合成授权场景的可观察轨迹，不执行任意 PoC、不接触公网目标，也不等同于独立 VM 的生产隔离验收。详细边界见 [Docker 轨迹说明](docs/docker-trajectories.md)，本机 1,500 条批次证据见 [Docker 轨迹运行报告](docs/docker-trajectory-run-2026-09-22.md)。
拆分命令输出 `technical-vulnerabilities.sqlite` 和 `business-logic-vulnerabilities.sqlite`，库内的 `structured_pentest_chains` 表直接提供可训练的七阶段结构化决策轨迹，`dataset_metadata` 表保存第（3）、（4）条的验收结果。默认拒绝覆盖已有文件，重新生成时需显式加 `--overwrite`。本机每类 1,500 条的拆分结果见 [Docker 轨迹双库拆分记录](docs/docker-trajectory-split-run-2026-09-22.md)。

轨迹只保存可观察的 observation/action/tool/input/result、阻碍、恢复策略和证据，不接收或导出模型内部思维过程；导入数据必须显式声明 `environment.authorized=true`。

沙箱 Agent 不是当前 Windows 工作站上的本地执行器。其部署清单、systemd 单元、配置样例、mTLS、证明密钥和验收步骤见 [sandbox-deployment.md](docs/sandbox-deployment.md)；特权 VM 组件必须符合 [sandbox-supervisor-contract.md](docs/sandbox-supervisor-contract.md)。没有真实 KVM 节点和通过签名的九项验收记录时，Agent 会保持失败关闭。

演示包含四类来源的 **5 条虚构记录**，合并成 3 条漏洞。CVE-2099-* 和 example.invalid 均是演示内容，不代表真实漏洞公告。重复执行不会重复导入或嵌入未变化的数据。演示请使用独立的 `output/demo.sqlite`，不要与真实库混用。

产物包含 `canonical.json`、`enrichment-plan.json`、`search.json`、`analysis/quality.json` 和 `analysis/records.csv`。

## 实际数据导入与处理

```powershell
python -m vulntools --db output/local.sqlite import --source cve --input path/to/cve.json
python -m vulntools --db output/local.sqlite import --source nvd --input path/to/nvd.json
python -m vulntools --db output/local.sqlite import --source avd --input examples/avd-exchange.json
python -m vulntools --db output/local.sqlite process --output output/local/canonical.json --plan output/local/enrichment-plan.json --alignment output/local/alignment.json
python -m vulntools --db output/local.sqlite enrich --sources cve nvd --max-records 100 --max-requests 200
python -m vulntools --db output/local.sqlite index
python -m vulntools --db output/local.sqlite search --query "path traversal" --top-k 5
python -m vulntools --db output/local.sqlite search --poc-file path/to/poc.py --weakness CWE-22 --mode hybrid
python -m vulntools --db output/local.sqlite duplicates
python -m vulntools --db output/local.sqlite import-poc --source nuclei --input path/to/nuclei-templates --commit-ref COMMIT_SHA
python -m vulntools --db output/local.sqlite import-poc --source exploitdb --input path/to/exploitdb --commit-ref COMMIT_SHA
python -m vulntools --db output/local.sqlite poc-status --output output/local/poc-status.json
python -m vulntools --db output/local.sqlite build-training-dataset --output output/vulnerability-training-v2
```

来源更新后按 `import → process → index` 顺序运行。`process` 原子更新派生记录、保留修订历史并使旧向量失效；索引重建完成前，变化记录不会使用旧向量参与检索。原始来源记录仍完整保留；来源带修订时间时会拒绝旧快照覆盖当前版本。

AVD/CNNVD 使用[交换格式](docs/exchange-format.md)，不把自定义字段结构冒充平台官方格式。详细契约见[采集说明](docs/collection.md)、[多模态处理说明](docs/processing.md)、[领域嵌入说明](docs/embedding.md)、[向量检索说明](docs/retrieval.md)、[分析说明](docs/analytics.md)和[沙箱说明](docs/sandbox.md)。

联网采集必须显式调用，离线演示不会调用：

```powershell
python -m vulntools --db output/local.sqlite collect --source cve --cve CVE-2024-3094
python -m vulntools --db output/local.sqlite collect --source nvd --cve CVE-2024-3094
python -m vulntools --db output/local.sqlite sync --source nvd --since 2026-09-01T00:00:00Z
python -m vulntools --db output/local.sqlite sync --source cve
python -m vulntools --db output/local.sqlite sync --source cve --full --baseline-dir D:/data/cvelistV5/cves
python -m vulntools --db output/local.sqlite collect-batch --source avd --input examples/source-ids.txt
python -m vulntools --db output/local.sqlite retry-collection --source avd
python -m vulntools --db output/local.sqlite collection-status
```

可通过 `NVD_API_KEY` 环境变量提供NVD密钥。NVD同步逐页保存数据和游标，默认从上次水位重叠5分钟继续；单个修改时间窗口最多120天，较长区间会自动拆分。`--full`支持从中断页恢复。

CVE首次建库使用官方 cvelistV5 仓库或发布包解压目录，按文件流式导入并保存游标；以后使用滚动 `deltaLog.json` 同步新增、修改和撤回记录。如果本地水位早于官方滚动日志覆盖范围，命令会拒绝静默跳过并要求重新导入基线。

AVD和CNNVD支持公开详情页解析、HTML文件导入、交换文件导入及批量ID任务。平台返回WAF、登录页或无法识别的页面时会记录失败，不会将验证页面保存成漏洞。工具不会绕过平台访问控制；批量生产采集应使用平台正式授权的API或数据导出。

取得正式授权后，可用 `examples/authorized-api.example.json` 定义 HTTPS 端点和严格 JSON 映射。配置只保存环境变量名称，不保存密钥；`collect`/`collect-batch` 使用 `--api-config`，`enrich` 使用 `--avd-api-config` 或 `--cnnvd-api-config` 显式启用。

## 可选能力

依赖已安装时可直接运行。需安装时建议使用本项目独立虚拟环境；离线机器应先准备依赖 wheel，再使用 `--no-index --find-links` 安装，不要求本次开发下载模型或依赖。

```powershell
# 联网准备依赖环境时可选执行
python -m venv .venv
.venv/Scripts/python -m pip install -e ".[test,charts,api]"
```

生成图表（需要 matplotlib）：

```powershell
python -m vulntools --db output/demo.sqlite analyze --output output/demo/analysis `
  --dataset-manifest examples/dataset-manifest.jsonl `
  --training-log examples/training-log.jsonl `
  --effect-log examples/knowledge-effects.jsonl `
  --baseline-report output/previous/analysis/quality.json `
  --baseline-variant baseline --charts
```

输出结构化质量报告、审核 CSV、`quality.png`、`training.png` 和 `knowledge-effects.png`。示例清单、训练日志和效果日志均为模拟数据；没有对应输入时返回 `not_connected`，不会生成虚假的模型效果数据。各字段和结论边界见[工具五说明](docs/analytics.md)。

本地模型接口（需要 semantic 可选依赖和已有模型文件）：

```powershell
python -m vulntools --db output/local.sqlite index --model-path D:/models/my-embedding-model
python -m vulntools --db output/local.sqlite search --model-path D:/models/my-embedding-model --query "漏洞描述"
```

仓库当前已配置并校验 `Qwen/Qwen3-Embedding-0.6B` 固定版本。模型使用查询侧 instruction、1,024-token 输入上限和 512 维 MRL 向量。主库可按批次续跑，重复执行只处理缺失或修订记录：

```powershell
# 默认再处理 1,000 条，适合分批运行
powershell -ExecutionPolicy Bypass -File scripts/semantic-index.ps1

# 自定义批次；全量约 9.4 万条会长时间占用 GPU
powershell -ExecutionPolicy Bypass -File scripts/semantic-index.ps1 -MaxRecords 5000
powershell -ExecutionPolicy Bypass -File scripts/semantic-index.ps1 -All

# 使用同一语义模型启动主库看板/API
powershell -ExecutionPolicy Bypass -File scripts/semantic-serve.ps1
```

模型权重保存在本机但被 `.gitignore` 排除；`models/Qwen3-Embedding-0.6B/VULNTOOLS_MODEL.json` 固定仓库提交、权重 SHA-256 和推理参数。当前实测与剩余边界见 [语义模型接入报告](docs/semantic-model-integration-2026-09-22.md)。

领域适配器训练与下游任务：

```powershell
python -m vulntools --db output/local.sqlite embedding-pairs --output output/embedding-pairs.jsonl
python -m vulntools --db output/local.sqlite fit-embedding --pairs output/embedding-pairs.jsonl --output-model output/domain-adapter.json --model-path D:/models/my-embedding-model
python -m vulntools --db output/local.sqlite index --model-path D:/models/my-embedding-model --adapter-path output/domain-adapter.json
python -m vulntools --db output/local.sqlite cluster-embeddings --model-path D:/models/my-embedding-model --adapter-path output/domain-adapter.json --clusters 8
python -m vulntools --db output/local.sqlite classify-vulnerability --model-path D:/models/my-embedding-model --adapter-path output/domain-adapter.json --text "漏洞描述"
```

模型以本地文件内容哈希区分版本，训练、索引与查询必须使用相同基础模型及预处理。详细的样本契约和效果边界见[领域嵌入说明](docs/embedding.md)。

本地 OCR 与静态代码特征：

```powershell
python -m vulntools ocr --input path/to/image.png --language chi_sim+eng --output output/ocr.json
python -m vulntools code-features --input path/to/example.py
python -m vulntools vision-encode --input path/to/image.png --model-path D:/models/local-clip --output output/vision.json
python -m vulntools --db output/local.sqlite attach-vision --source avd --id AVD-2026-001 --artifact output/vision.json
```

OCR 输出文本、置信度、位置框和文件哈希；人工核对后使用 `attach-ocr` 回流。原生视觉命令直接编码图片像素，输出模型清单、图像/向量哈希和向量；回流时严格校验后生成独立 `image_embedding` Evidence，不冒充 OCR 文本。AST 和跨语言行为规则仅静态解析，不运行 PoC。

## 本地 HTTP 接口

```powershell
python -m vulntools --db output/demo.sqlite serve --port 8765
python -m vulntools --db output/vulnerability-master.sqlite serve --model-path models/Qwen3-Embedding-0.6B --port 8765
```

浏览器访问 `http://127.0.0.1:8765/` 可打开本地验收看板。看板直接读取数据库与检索接口，不使用 Mock 数据，并明确显示尚未连接的沙箱、轨迹等能力。

服务仅监听 `127.0.0.1`。端点：`GET /health`、`GET /records`、`GET /records/{id}`、`GET /trajectories`、`GET /trajectories/{task_id}`、`GET /collection/status`、`GET /index/status`、`GET /analytics/summary`、`GET /analytics/quality`、`GET /analytics/alignment`、`POST /search`、`POST /similarity`、`POST /classify`、`POST /clusters`。列表接口使用 `limit` 和 `offset` 分页；本地接口不包含远程鉴权或真实沙箱执行，不能作为公网服务部署。

```json
{"query":"archive path", "component":"demo-archive", "version":"1.1.0", "top_k":5}
```

Python 也可直接调用 `Store`、`process`、`index_records`、`search`、`record_similarity`、`index_status` 和 `evaluate`。每条漏洞分别持久化 aggregate、description、poc、patch、component、metadata 和静态 code behavior 视图；只为存在内容的视图建索引。规范记录修订后旧向量会原子失效，再次执行 `index` 只重建变化记录。

检索支持 `hybrid`、`dense`、`sparse` 三种模式，`--offset` 稳定分页，`--min-similarity` 设置向量相似度下限，`--severity`、`--weakness`、`--source`、`--component` 和 `--version` 执行严格过滤。返回结果包含各查询通道的权重、最佳命中视图、各视图余弦分数、BM25、RRF、命中词、证据片段、来源 URL、记录修订和模型 ID，可复算和溯源。

`evaluate-search` 接受 JSON 数组或 JSONL；每条至少包含 `query`/`poc`/`component` 之一和 `relevant` 漏洞 ID 数组，可选使用与搜索相同的过滤参数。输出宏平均 Recall@K、MRR、nDCG 和逐查询排名。示例文件只验证工程链路，不是正式效果数据。

默认后端为 SQLite 持久化向量：10,000 条以内执行全量多视图精确检索；更大索引先流式扫描 aggregate 向量并保留最多 12,000 个候选，再做多视图 BM25/余弦/RRF 精排，响应中的 `index_backend` 会标记 `sqlite_two_stage`。该路径控制主库内存占用，但不承诺全量多视图精确召回；生产大规模部署应以同一模型与多视图契约接入 HNSW/Qdrant，并在固定硬件和数据集上验收 Recall@K 与 P95 延迟。疑似重复检测为二次复杂度，仅面向小规模原型。

## 验证与开发计划

```powershell
python -m pytest -q
```

测试覆盖采集分页与续传、来源修订、失败恢复、WAF识别、多模态对齐、证据补齐、OCR 回流、冲突与重复、领域适配训练、聚类/分类、严格检索、训练数据泄漏、知识注入成对比较，以及 VM 后端验收、失败关闭和销毁。测试不下载模型、不执行恶意代码。

正式开发顺序与验收边界见 [implementation-plan.md](docs/implementation-plan.md)。[早期评估](docs/tool-suite-roadmap.md)是旧项目只读评估副本，其中“在旧项目上扩展”的建议已被独立建项决定替代。
