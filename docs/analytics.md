# 工具五：训练数据分析与知识注入效果可视化

工具五把规范漏洞记录、训练数据清单、训练过程日志和知识注入对照实验汇总到同一个可复算报告。分析只读取 JSONL 和数据库中的规范记录，不加载训练样本正文、不执行 PoC，也不调用外部模型服务。

## 一次生成完整报告

```powershell
python -m vulntools --db output/demo.sqlite analyze `
  --output output/demo/analysis `
  --dataset-manifest examples/dataset-manifest.jsonl `
  --training-log examples/training-log.jsonl `
  --effect-log examples/knowledge-effects.jsonl `
  --baseline-report output/previous/analysis/quality.json `
  --baseline-variant baseline `
  --rare-share 0.05 `
  --drift-threshold 0.10 `
  --charts
```

不提供某一类输入时，对应节点返回 `status: not_connected`，不会生成推测数据。`quality.json` 使用 `vulntools/analytics/v2` 契约；为兼容旧调用，规范记录的常用质量字段仍复制到顶层。

## 训练数据清单

清单为每行一个 JSON 对象：

```json
{"sample_id":"train-001","vuln_id":"CVE-2099-1001","family_id":"archive-path-traversal","split":"train","labels":["CWE-22"],"modalities":["text","patch"],"weight":1.0}
```

必需字段为 `sample_id`、`vuln_id`、`split`、`labels` 和 `modalities`；`family_id` 用于发现同漏洞家族跨训练/验证/测试集泄漏，`weight` 默认为 1。合法划分是 `train`、`validation` 和 `test`。

分析包含：

- 样本、标签、模态及各划分分布；
- 标签和模态长尾比例、最大/最小类别比；
- 重复样本 ID、未知漏洞引用、无效权重或字段；
- 同一漏洞及同一家族跨划分泄漏。

`--rare-share` 是长尾提醒阈值，以全部标签或模态赋值次数为分母。它只用于发现待检查分布，不自动删除、重采样或更改训练权重。

## 训练过程日志

训练日志可以是单个 JSONL 文件，也可以是训练平台持续导出的 JSONL 目录；目录按文件名和行号确定稳定读取顺序。每行使用 `run_id` 和非负递增的 `step` 标识曲线。支持：

- `loss`、`eval_loss`、`learning_rate`、`grad_norm`；
- `throughput`、`gpu_memory_mb`、`gpu_util_percent`、`cpu_percent`、`cpu_memory_mb`、磁盘读写吞吐；
- `dataset_version`、`model_version`、`timestamp`、`status` 和 `exit_reason`。

每个 run 输出指标的数量、最小值、最大值、均值、中位数和 P95，同时记录最佳验证步、末段 loss 斜率、最终泛化差距和 loss 变化标准差。非有限值、负资源指标、CPU/GPU 利用率超范围、step 乱序、验证损失回退、数据或模型版本中途切换、梯度尖峰、吞吐崩塌及失败/取消会进入异常表。曲线诊断用于定位训练问题，不等同于收敛或模型效果结论。

## 分布漂移

`--baseline-report` 接受之前生成的 `quality.json`。工具对来源、风险等级、CWE、证据模态和组件分布计算 0—1 范围的 Jensen–Shannon divergence，同时比较每个核心字段的覆盖率变化。任一分布散度或覆盖率绝对变化达到 `--drift-threshold` 时，`drift.status` 为 `alert`，但这只是调查信号，不自动认定数据或模型退化。

输出保留每个类别的基线占比、当前占比和变化量，生成 `drift.csv`；启用图表时生成 `drift.png`。本地 API 的 `POST /analytics/drift` 接受历史质量报告对象和阈值，不接受任意服务器文件路径，可供后续看板安全调用。

## 知识注入效果日志

效果日志记录相同协议下的重复评测：

```json
{"variant":"knowledge-injected","task":"path-classification","metric":"macro_f1","direction":"maximize","seed":11,"dataset_version":"frozen-v1","value":0.75}
```

`direction` 使用 `maximize` 或 `minimize`。工具按 `task + metric + seed + dataset_version` 将候选方案与 `--baseline-variant` 成对，统一把正 delta 表示为优于基线。每个方案输出均值、样本标准差、描述性 95% 正态近似区间、成对差值和 `improved`、`regressed` 或 `unchanged_or_uncertain` 结果。少于两组成对观测会标为 `insufficient_pairs`。

正式结论应冻结数据集和评测协议，使用相同种子做重复实验。当前区间用于工程观察，不声称统计显著性或因果关系。

## 报告产物

始终生成：

- `quality.json`：全部结构化结果和输入连接状态；
- `records.csv`：每条漏洞的缺失及冲突字段；
- `anomalies.csv`：按 metadata、dataset、training、knowledge_effect、drift 分类的审核队列。

连接相应输入后生成 `dataset-manifest.csv`、`training.csv`、`knowledge-effects.csv` 和 `drift.csv`。启用 `--charts` 后生成：

- `quality.png`：缺失字段、风险、来源和数据划分/模态分布；
- `training.png`：六项训练及资源曲线；
- `knowledge-effects.png`：相对基线的成对改善量及区间。
- `drift.png`：各维度 Jensen–Shannon 散度和字段覆盖率变化。

CSV 使用 UTF-8 BOM，便于 Windows 表格工具直接打开。报告中的 `dataset_id` 由漏洞 ID 与规范记录修订计算，可用于确认两次分析是否基于同一版规范数据。

## Python 接口

`vulntools.analytics` 暴露以下函数：

- `quality_report`；
- `read_dataset_manifest` / `dataset_manifest_report`；
- `read_training_log` / `training_report`；
- `read_effect_log` / `effect_report`；
- `drift_report`；
- `write_report`。

本地 HTTP 的 `GET /analytics/quality` 返回规范记录质量报告，`POST /analytics/drift` 对客户端提供的历史报告执行漂移计算。训练和实验日志通过显式 CLI 文件或目录参数接入，避免服务端接受任意本地路径。
