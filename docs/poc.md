# PoC 工件采集与覆盖统计

PoC 子系统只做静态采集、版本固化和关联，不在本机执行代码。检测模板、利用代码、复现代码和扫描模块分别统计，不能用检测模板冒充可利用 PoC。

## 数据结构

- `poc_artifacts`：来源内的稳定工件身份、类型、出处、上游提交、语言、许可证和审核状态。
- `poc_artifact_versions`：每个工件的不可变代码文本、SHA-256、字节数和采集时间。
- `poc_vulnerability_links`：工件与 CVE 的多对多关系、关系类型、置信度及关联证据。

同一工件内容发生变化时保留旧版本。`candidate` 只表示上游声称与 CVE 有关；只有后续完成静态复核、沙箱复现或人工确认后，才能提升为对应审核状态。

## 当前导入器

### Nuclei

递归读取 YAML，只导入包含 CVE 编号的文件，统一标记为 `detection_template`。保存模板原文，但不调用 Nuclei 执行。应使用固定提交的官方快照：

```powershell
python -m vulntools --db output/vulnerability-master.sqlite import-poc `
  --source nuclei --input path/to/nuclei-templates `
  --commit-ref <commit-sha> --license MIT
```

### Exploit-DB

以官方 `files_exploits.csv` 为索引，只导入 `codes`、`aliases` 或描述中明确包含 CVE 的代码文件，统一标记为 `exploit_code`。代码是否真实可复现仍需后续审核：

```powershell
python -m vulntools --db output/vulnerability-master.sqlite import-poc `
  --source exploitdb --input path/to/exploitdb `
  --commit-ref <commit-sha>
```

## 安全与质量边界

- 不执行脚本，不调用解释器，不自动安装依赖。
- 默认拒绝二进制文件和超过 2 MB 的单文件。
- 操作系统安全软件阻断的文件记为 `blocked_or_unreadable`，不关闭防护绕过。
- 上游索引中的 CVE 声明只是候选关联，不等于真实性验证。
- `source_url`、固定提交、内容 SHA-256 和不可变版本共同构成来源证据。
- 正式交付应分开报告工件数量、唯一 CVE 数、已进入主库的 CVE 数和各审核状态数量。

## 查看覆盖率

```powershell
python -m vulntools --db output/vulnerability-master.sqlite poc-status `
  --output output/vulnerability-master/poc-status.json
```

