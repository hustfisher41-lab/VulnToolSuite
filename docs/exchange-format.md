# AVD / CNNVD 本地交换格式 v1

这是 VulnToolSuite 定义的导入格式，不是AVD或CNNVD官方API格式。工具一可以解析公开详情页并按已知编号执行批量任务；如果平台返回WAF、登录验证或没有稳定公开API，应使用平台授权导出并映射为此结构，不得将访问验证页面当作漏洞数据。

支持单对象、JSON 数组和 JSONL。每个对象对应一条来源记录：

```json
{
  "source_id": "AVD-DEMO-1001",
  "url": "https://example.invalid/advisory/1001",
  "aliases": ["CVE-2099-1001"],
  "status": "active",
  "fields": {
    "title": "Synthetic demonstration",
    "description": "Source description, including any Markdown code blocks",
    "components": [{
      "vendor": "DemoVendor",
      "name": "demo-archive",
      "default_status": "unaffected",
      "versions": [{"version": "1.0.0", "lessThan": "1.2.0", "versionType": "semver", "status": "affected"}]
    }],
    "weaknesses": ["CWE-22"],
    "severity": "high",
    "attack_preconditions": "As stated in source evidence",
    "patch": "Source patch excerpt or patch summary",
    "image_text": "Optional reviewed image transcription"
  },
  "references": ["https://example.invalid/patch/1001"]
}
```

`source_id`、`url`、`fields` 必填；来源由 CLI 的 `--source avd` 或 `--source cnnvd` 指定。未知字段省略或填 null，不得用占位文本假装已补齐。`status` 仅允许 active/rejected。CVE 别名最多一个，不应把公告中提及的所有 CVE 都当作当前记录的身份。

字段合并优先级为 CVE、NVD、AVD、CNNVD，这是首版可复现规则，不代表来源内容总是更正确。不同候选值完整保留，展示值不等于已裁决事实。

### 训练日志

每行包括 run_id、step，以及可选 loss、eval_loss、learning_rate、grad_norm。step 必须为非负有限数值。同一 run_id 的 step 不递增、指标非有限值、负学习率或负梯度范数会记录异常。缺失指标不插值或伪造。

### 沙箱事件

每行必须包括 run_id、timestamp、type；type=syscall 时还要求 name、整数 pid，可提供 return_code。负返回值、signal、timeout、oom、policy_violation、monitor_lost 进入异常摘要。异常返回不自动等于恶意行为，也不证明监控日志完整可信。
