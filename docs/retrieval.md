# 工具四：漏洞元数据向量检索

工具四消费规范记录和工具三提供的 `Encoder` 契约，不下载模型，也不执行 PoC。当前后端使用 SQLite 持久化向量并进行精确余弦检索，适合离线验收、本地服务和中小规模数据集。

## 索引契约

每条活动漏洞最多生成六个视图：

| 视图 | 内容 |
|---|---|
| aggregate | 漏洞 ID、别名及所有可用检索字段 |
| description | 标题、文本描述和已审核图片转录 |
| poc | PoC 原文 |
| patch | 补丁或修复语义 |
| component | 组件及其版本声明 |
| metadata | ID、标题、CWE、风险级别和攻击前提 |

空视图不写入。索引行同时绑定 `model_id`、规范记录 `revision` 和 `view_name`。模型清单、维度、权重或预处理变化都会形成不同的 `model_id`；规范记录变化会使旧向量失效。`index` 在单个数据库事务内验证全部新向量，任一向量维度错误或包含非有限值时整批回滚。

## 检索与解释

搜索请求可同时提供自然语言描述、PoC、组件和版本。描述查询匹配 description、metadata、patch、aggregate；PoC 查询优先匹配 poc；组件查询优先匹配 component。多个查询通道按照固定、公开的权重合成稠密和稀疏分数，再用 RRF 融合排名。

`severity`、`weakness`、`source`、`component`、`version` 和目标 `cpes` 是严格过滤条件。过滤后无结果时返回空数组，不扩大查询范围。版本比较支持 SemVer（含预发布）、Python/PEP 440、Maven、日期和纯数字规则，并支持 CVE `changes` 状态切换；PURL 可推断 npm、PyPI、Cargo、Go 和 Maven 的明确生态。无法可靠解释的厂商自定义规则返回 unknown，不能作为 affected 命中。

NVD applicability 使用三值逻辑求值 CPE 2.3 条件树的 AND、OR、negate 和版本边界。调用方使用可重复的 `--cpe` 传入完整目标环境，例如应用与操作系统 CPE；上下文缺失、CPE 非法或条件无法比较时不会猜测为受影响。

每个命中返回：最终名次、余弦/BM25/RRF 分数、各查询通道权重、最佳命中视图、所有参与视图的余弦分数、命中词、版本判断、证据片段、来源 URL、冲突字段、记录修订和模型 ID。

## 接口

CLI：

```powershell
python -m vulntools --db output/local.sqlite index
python -m vulntools --db output/local.sqlite index-status
python -m vulntools --db output/local.sqlite search --query "archive traversal" --component demo-archive --version 1.1.0 --mode hybrid
python -m vulntools --db output/local.sqlite search --query "widget" `
  --cpe "cpe:2.3:a:acme:widget:1.5:*:*:*:*:*:*:*" `
  --cpe "cpe:2.3:o:microsoft:windows_11:23h2:*:*:*:*:*:*:*"
python -m vulntools --db output/local.sqlite search --poc-file path/to/poc.py --weakness CWE-22 --source nvd
python -m vulntools --db output/local.sqlite similarity --left CVE-2024-0001 --right CVE-2024-0002 --views aggregate description poc
python -m vulntools --db output/local.sqlite evaluate-search --input examples/search-eval.jsonl --cutoffs 1 5 10
```

HTTP：

- `GET /index/status`：返回当前模型的记录覆盖率、各视图数量和缺失记录。
- `POST /search`：参数与 CLI 搜索一致；返回可解释命中列表。
- `POST /similarity`：输入 `left`、`right` 和可选 `views`，返回共同视图相似度。

Python：`index_records`、`index_status`、`search`、`record_similarity`、`evaluate`。

## 评测数据

评测文件是 JSON 数组或 JSONL。每条至少提供一种查询输入和一个非空 `relevant` 数组：

```json
{"id":"case-1","query":"archive path traversal","relevant":["CVE-2024-0001"]}
```

结果包含宏平均 Recall@K、MRR、最大 K 上的 nDCG、逐条返回顺序和检索耗时的 P50/P95/最小值/最大值。正式验收应使用冻结、人工核验、家族去重的数据集，并记录数据集版本、模型 ID、硬件和数据规模；演示标注仅验证计算链路。

## 部署边界

SQLite 精确后端一次批量加载当前模型的多视图，避免逐候选数据库查询；`index-status` 和命中结果明确报告 `sqlite_exact`，不会把精确结果冒充 ANN。精确后端不会因近似索引丢失召回，但查询时间仍随严格过滤后的候选数线性增长。超大规模部署可在保持 `model_id + revision + view_name` 契约的前提下替换为 HNSW 或外部向量库；切换后必须重新执行同一评测集和延迟验收，不能直接沿用精确后端的结果声明。
