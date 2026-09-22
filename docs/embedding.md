# 工具三：漏洞领域嵌入

工具三支持三层编码器：无需下载的特征哈希基线、已有本地 SentenceTransformer，以及在固定基础编码器上训练的领域度量适配器。所有模型都有完整 manifest；基础模型、维度或预处理不一致时拒绝加载旧适配器和索引。

## 构造领域训练对

```powershell
python -m vulntools --db output/local.sqlite embedding-pairs --output output/embedding-pairs.jsonl
```

工具从同一漏洞中构造描述到 PoC、补丁、组件和元数据的正样本；只有 CWE 集合不相交的不同漏洞才生成自动负样本。输出保留关系类型和漏洞 ID，便于人工删除不可靠负例。正式训练仍应加入人工核实的困难负例，并冻结验证/测试集。

自定义 JSONL 每行使用：

```json
{"left":"漏洞描述或代码","right":"补丁、PoC 或另一段描述","label":1,"relation":"description_to_patch"}
```

训练文件必须同时包含正样本和负样本。

## 训练领域适配器

特征基线可以直接验证工程链路：

```powershell
python -m vulntools --db output/local.sqlite fit-embedding `
  --pairs output/embedding-pairs.jsonl `
  --output-model output/domain-adapter.json `
  --dimension 512 --epochs 8
```

生产语义模型使用已经下载并审核的本地目录，不自动联网拉取模型：

```powershell
python -m vulntools --db output/local.sqlite fit-embedding `
  --pairs output/embedding-pairs.jsonl `
  --output-model output/domain-adapter.json `
  --model-path D:/models/local-sentence-model
```

本项目当前本地模型为 `Qwen/Qwen3-Embedding-0.6B`，固定提交 `97b0c614be4d77ee51c0cef4e5f07c00f9eb65b3`。`VULNTOOLS_MODEL.json` 固定权重哈希、1,024-token 输入上限和 512 维截断输出；编码器发现模型自带的 `query` prompt 后，仅在查询侧使用，文档侧保持无指令编码。推理不会联网。

适配器使用监督式对角余弦度量学习，基础编码器文件保持不变。训练工件记录目标、正负样本数、epoch、学习率、负样本 margin 和逐轮损失。以特征哈希为基础时，适配器属于领域训练后的词法度量，`semantic_model` 仍为 `false`；只有语义基础模型才可标记为语义编码器。

## 索引和下游任务

```powershell
python -m vulntools --db output/local.sqlite index --adapter-path output/domain-adapter.json --dimension 512
python -m vulntools --db output/local.sqlite search --adapter-path output/domain-adapter.json --dimension 512 --query "archive path traversal"
python -m vulntools --db output/local.sqlite cluster-embeddings --adapter-path output/domain-adapter.json --dimension 512 --clusters 8 --output output/clusters.json
python -m vulntools --db output/local.sqlite classify-vulnerability --adapter-path output/domain-adapter.json --dimension 512 --text "unescaped input in HTML" --top-k 5
```

真实主库建议分批、可续跑索引：

```powershell
powershell -ExecutionPolicy Bypass -File scripts/semantic-index.ps1 -MaxRecords 1000
python -m vulntools --db output/vulnerability-master.sqlite index-status --model-path models/Qwen3-Embedding-0.6B
```

`index --batch-size` 控制每次送入模型的视图数，`index --max-records` 控制本次最多更新的漏洞记录数。每批在 SQLite 事务中原子提交，失败或中断不会保留半批向量；下次执行会从缺失记录继续。

已有多视图索引分别表示 aggregate、description、poc、patch、component、metadata 和静态 code behavior，可用于相似漏洞检索、PoC 匹配、利用模式分析和 RAG。聚类使用确定性的球面 k-means，输出成员、medoid、CWE 分布和 cohesion。类型识别以已有 CWE 样本中心排序，返回分数、支持样本数和示例漏洞 ID，低支持度结果应进入人工审核。

本地 HTTP 增加 `POST /classify`、`POST /clusters`；`serve --adapter-path` 可让检索、相似度、聚类和分类共享同一模型契约。

## 评价边界

生成向量、训练损失下降或演示分类正确都不代表领域效果已经达标。正式验收应在家族去重、时间冻结的数据集上比较基线和领域模型，报告 Recall@K、MRR、nDCG、PoC 匹配和分类分组指标，并将工具五的重复实验日志用于比较。
