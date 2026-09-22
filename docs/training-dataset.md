# 漏洞知识训练数据集

`build-training-dataset` 将规范漏洞记录和独立 PoC 工件导出为流式 JSONL 数据包。v2 提供知识注入、来源证据抽取 SFT、RAG 和 CVE 查询数据；自动偏好候选单独待审，尚无正式 DPO 数据。导出过程不执行 PoC，也不生成隐藏思维链。

```powershell
python -m vulntools --db output/vulnerability-master.sqlite build-training-dataset `
  --output output/vulnerability-training-v2 `
  --split-seed vuln-master-20260917
```

## 输出文件

| 文件 | 用途 |
|---|---|
| `knowledge.jsonl` | 规范漏洞知识注入；保留来源、字段状态、冲突和 PoC 摘要 |
| `sft.jsonl` | Chat messages 格式的来源字段抽取、上游 PoC 关联声明抽取；不是独立分类基准 |
| `preference.jsonl` | 正式人工审核偏好数据预留文件；当前为空，不可直接开展 DPO |
| `preference-candidates.jsonl` | `prompt/chosen/rejected` 自动候选，`training_eligible=false`，不进入正式样本清单 |
| `rag-corpus.jsonl` | 漏洞描述与分块 PoC 代码文档 |
| `retrieval.jsonl` | 模板化 CVE 查询、正文档与待审核难负例；不是语义检索基准 |
| `dataset-manifest.jsonl` | SFT 和检索样本的 CVE、家族、split、标签、模态和权重；不含偏好候选 |
| `manifest.json` | 参数、计数、过滤原因、SHA-256、质量边界与结构验证结果 |

## 防止数据泄漏

划分单位不是单条样本，而是共享 PoC、规范化重复代码、重复代码块及重复描述连接形成的 CVE 家族。相连的所有 CVE 固定进入同一 split；未相连漏洞以自身 CVE 作为家族。split 由 `split_seed + family_id` 的稳定哈希生成，目标比例为 80%/10%/10%，按记录计数可能受家族大小影响。防泄漏仅覆盖这些可检测的重复关系，不承诺消除语义近似、相同补丁等未知关联。

结构验证检查：

- `sample_id` 是否重复；
- 同一 CVE 是否跨 split；
- 同一 PoC 家族是否跨 split；
- 检索文档引用是否存在、是否与查询处于同一 split；
- JSONL 文件行数、字节数和 SHA-256；
- SFT 文本与 PoC 代码内容哈希去重；
- 缺描述、代码过长、无主库记录和无可用负例的过滤计数。

## 标签和偏好边界

- CVE/CWE/CVSS/组件标签来自规范来源断言，不等于人工验证真值。
- 字段抽取 SFT 的输入显式提供 `source_assertions`；未知、冲突严重性不作为标签，`n/a` 等产品占位符和非 CWE 编号被排除。不能用这些样本声称模型能够仅凭描述准确分类。
- PoC 关联默认仍为 `candidate`；输出 `upstream_claimed_association=true` 与 `replay_verified=false`，不会把上游关联声明说成成功复现。`human_verified` 也不自动等同于沙箱复现。
- 偏好候选由同 split、不同家族、同 PoC 类型和语言自动选择，标记为 `synthetic_hard_negative_same_type_language`、`requires_human_review=true`、`training_eligible=false`。未记录 CVE 关联并不证明不匹配；正式文件保持为空。
- 检索难负例不使用缺失/unknown 标签匹配，并排除同家族，但仍需人工审核相关性；当前查询包含 CVE 编号，只适合编号查询验证，不能冒充自然语言语义检索效果。
- 修复建议样本只应在后续取得补丁或厂商修复证据后生成；当前不会根据漏洞描述臆造修复代码。
- 尚缺独立分类、语义查询评测、真实修复建议、攻击路径、人工偏好标签和许可证审核；`requirements_fully_met=false`。

## 使用和版本边界

按每行 `split` 分别选择 train/validation/test，不能把一个完整 JSONL 当作训练集并同时用于评测。数据包 ID 不依赖输出目录；文件路径只保存在清单中。SHA-256 证明快照一致性，不证明漏洞描述或 PoC 关联真实性。

v1 是历史导出：包含缺少输入依据的部分 SFT 标签、自动偏好以及描述自匹配查询，不建议直接训练或报告效果。v2 单独输出保留 v1，不覆盖原始主库记录。代码许可证缺失时标记 `license_review_required`，即使有许可证字段也需要确认训练与再分发许可。

可独立复核文件哈希、行数、目标标签依据、文档引用和规范化 RAG 文本的跨分区重复：

```powershell
python scripts/validate_training_dataset.py output/vulnerability-training-v2
```

当前主库 v2 快照：94400 条知识、38778 条 SFT（17980 条字段抽取、20798 条上游 PoC 声明抽取）、125826 条 RAG 文档、94400 条 CVE 查询、20795 条偏好待审候选、0 条正式偏好。缺少有效标签的 76420 条记录不再生成字段抽取 SFT，仍保留知识和描述文档。独立校验通过，检测到的 CVE/家族/规范化文档跨分区泄漏与失效引用均为 0。

## 代码分块

PoC 代码默认每块 4000 字符，重叠 200 字符，尽量在换行处切分。超过 200000 字符的单工件默认过滤。可以通过 `--chunk-chars`、`--chunk-overlap` 和 `--max-code-chars`调整；使用 `--no-code`可以只导出元数据训练集。
