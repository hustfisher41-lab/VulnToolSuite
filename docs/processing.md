# 工具二：漏洞元数据处理与多模态对齐

工具二把来源记录合并为可追溯的规范漏洞记录。身份只按明确 CVE 别名统一；文本相似、共享链接或相同组件只产生审核候选，不会自动把两个漏洞合并。

## 处理与统一表征

```powershell
python -m vulntools --db output/local.sqlite process `
  --output output/local/canonical.json `
  --plan output/local/enrichment-plan.json `
  --alignment output/local/alignment.json
```

每项 Evidence 保存来源、来源 ID、URL、字段、原始位置、抽取方法、置信度以及 `aligned/v1` 表征。处理器支持：

- 普通文本与补丁文本；
- Markdown 围栏代码和 HTML `pre/code` 代码；
- Markdown 图片引用；
- PoC 字段和经审核的 OCR 图片转录；
- 本地原生视觉模型直接从图片像素生成的版本化向量工件；
- Python AST 调用/导入特征，以及跨语言的网络、进程、文件、命令执行、编码、数据库和内存行为提示。

静态特征只用于统一表征，不执行代码，也不把关键词命中解释为漏洞成立。`alignment.json` 汇总模态、抽取方式、代码行为和待复核证据。

## OCR 回流

先调用本地 Tesseract，再将人工检查过的工件附到指定来源记录：

```powershell
python -m vulntools ocr --input path/to/image.png --language chi_sim+eng --output output/ocr.json
python -m vulntools --db output/local.sqlite attach-ocr --source avd --id AVD-2026-001 --artifact output/ocr.json
```

回流会保存图片内容哈希、抽取器、语言和路径摘要，并重建规范记录与 Evidence。已有不同 `image_text` 时默认拒绝覆盖，人工确认后才可传 `--replace-existing`。

## 原生视觉向量回流

```powershell
python -m vulntools vision-encode --input path/to/image.png `
  --model-path D:/models/local-clip --output output/vision.json
python -m vulntools --db output/local.sqlite attach-vision `
  --source avd --id AVD-2026-001 --artifact output/vision.json
```

模型必须是已经存在于本机、可直接接受图片的 SentenceTransformer 兼容目录；命令不会下载模型。工件绑定模型文件哈希、维度、图片 SHA-256、向量 SHA-256 和有限值向量。回流会复算并核对这些契约，按“图片哈希 + 模型 ID”幂等保存，生成 `image_embedding` Evidence。视觉向量与文本向量空间不同，因此不会未经对齐训练就混入文本余弦索引。

## 缺失字段联网补齐

`enrich` 是显式联网命令，默认查询 CVE 官方记录和 NVD，并把成功解析的来源记录写入来源历史后重新处理：

```powershell
python -m vulntools --db output/local.sqlite enrich --sources cve nvd --max-records 100 --max-requests 200
```

使用 `--dry-run` 可获取候选而不写库。AVD/CNNVD 只有在具备合法可访问页面或授权接口模板时使用：

```powershell
python -m vulntools --db output/local.sqlite enrich --sources avd `
  --avd-url-template "https://authorized.example/vuln/{id}" --dry-run
```

报告逐漏洞给出 `missing_before`、`filled_fields`、`new_conflicts` 和 `missing_after`。只有经过来源适配器完整解析并保留出处的字段才能补齐；搜索摘要不会直接成为字段值。失败进入采集失败队列，网络请求同时受记录数和请求数上限约束。

## 重复发现与统一边界

同一 CVE 的 CVE、NVD、AVD、CNNVD 断言自动归入同一规范记录，字段冲突完整保留。`duplicates` 对缺少共同身份的记录计算描述词集合相似度并返回 `needs_review`，不会自动改写身份。这样可以量化疑似重复，同时避免相似漏洞被误合并。

组件实体先按去版本的 PURL 坐标匹配，再按 CPE 厂商/产品坐标匹配，最后才使用规范化后的“厂商 + 产品名”。同名但同类强标识冲突的断言不会合并，而是在规范记录的 `entity_review` 中产生 `conflicting_component_identifiers`；缺少稳定标识和厂商名的组件使用低置信身份并进入复核。合并实体保留原始别名、来源、全部版本断言和默认状态冲突。
