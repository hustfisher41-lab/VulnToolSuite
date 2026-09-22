# Qwen3 语义模型接入报告（2026-09-22）

## 结论

平台已接入真实本地 SentenceTransformer 语义模型，不再只具备 feature-hash 基线。演示库已经全量完成语义索引；真实主库已完成 101 条的索引与检索验收。真实主库全量索引尚未完成，因此启动语义服务时只能检索当前已索引子集。

## 固定模型契约

- 上游：`Qwen/Qwen3-Embedding-0.6B`
- 提交：`97b0c614be4d77ee51c0cef4e5f07c00f9eb65b3`
- 权重：`model.safetensors`，1,191,586,416 字节
- 权重 SHA-256：`0437e45c94563b09e13cb7a64478fc406947a93cb34a7e05870fc8dcd48e23fd`
- 本地模型哈希：`3b8855e880b50d33eda932f5fc853925dac3e18b7e26ce82fe371237d256a578`
- 向量：512 维、余弦距离、归一化
- 输入上限：1,024 tokens
- 查询：使用模型自带 `query` instruction；文档不加 instruction
- 模型 ID：`baa30e128318d6e26edab03fb91e37219f22d102fba68fe1da0921188788bf99`

模型文件位于 `models/Qwen3-Embedding-0.6B`。权重被 `.gitignore` 排除，模型来源、哈希和推理参数保存在 `VULNTOOLS_MODEL.json`。

## 机械验证

1. 全部自动化测试：139 passed。
2. 中文语义对照：查询“Windows远程代码执行漏洞”与相关文本余弦约 0.821，与无关图片格式文本约 0.199。
3. 演示库：3/3 条、11 个多视图完成索引；路径穿越查询目标排第 1，余弦约 0.802，结果标记 `semantic_model=true`。
4. 真实主库：101/94,472 条完成索引；查询 `CVE-1999-0001 BSD crafted packets` 时精确 ID 排第 1，余弦约 0.708，结果标记 `semantic_model=true`。
5. 首批 100 条（400 个视图）耗时 78.21 秒，硬件为 RTX 5060 Ti 16GB。线性外推全量约 20.5 小时；后续含 PoC/补丁视图的记录可能改变实际吞吐，因此这只是容量估算，不是完成承诺。
6. 续跑脚本再次执行时跳过已完成的 100 条并新增 1 条，证明限量续跑生效。

## 使用

```powershell
# 默认继续 1,000 条
powershell -ExecutionPolicy Bypass -File scripts/semantic-index.ps1

# 查看覆盖率
python -m vulntools --db output/vulnerability-master.sqlite index-status `
  --model-path models/Qwen3-Embedding-0.6B

# 启动真实语义模型 API/看板
powershell -ExecutionPolicy Bypass -File scripts/semantic-serve.ps1
```

索引脚本默认限量，重复执行会跳过已完成且修订未变化的记录。只有在可以持续占用 GPU 和增加数据库体积时才使用 `-All`。

## 仍未完成

- 真实主库剩余 94,371 条尚未生成 Qwen3 向量。
- SQLite 仍是向量存储；尚未接入 Qdrant/HNSW，因此全量后的检索吞吐仍需单独验收。
- 尚未建立冻结的人工相关性集合，当前结果证明工程链路与基本语义区分有效，不代表 Recall@K/MRR 已达到生产指标。
