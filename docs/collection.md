# 工具一：漏洞元数据采集

工具一负责获取原始来源证据并转换为统一 `SourceRecord`。采集结果保存来源、来源编号、别名、字段、引用、原始响应、采集时间和来源更新时间；它不直接覆盖规范漏洞记录。运行 `process` 后才执行跨来源合并。

## 来源能力

| 来源 | 单条 | 增量/全量 | 输入格式 |
|---|---|---|---|
| CVE | 官方 cvelistV5 JSON记录 | 滚动 `deltaLog.json` 增量；官方仓库/发布包目录基线续传 | CVE Record Format 5.x JSON、JSONL、目录 |
| NVD | CVE API 2.0 | 修改时间窗口分页；超过120天自动拆分；支持全量分页续传 | NVD API 2.x JSON、JSONL |
| AVD | 公开详情页或配置化授权 JSON API | 已知ID批量任务 | 公开HTML、项目交换JSON/JSONL、授权响应映射 |
| CNNVD | 公开搜索/详情页或配置化授权 JSON API | 已知ID批量任务 | 公开HTML、项目交换JSON/JSONL、授权响应映射 |

CVE官方仓库当前包含CNA容器、CVE Program容器和可选ADP容器。解析器汇总各容器的描述、受影响产品、CWE、引用、CVSS与SSVC，同时保留完整原始JSON。NVD解析器保留CPE适用性树、CVSS、CWE、引用、发布时间、修改时间和新增的affected结构。

## 可靠性约束

- 每个HTTP请求仅允许HTTPS和明确列出的官方主机，响应体有大小上限，重定向后再次校验主机。
- 429和临时5xx按 `Retry-After` 或指数退避重试；请求按来源间隔执行。
- NVD每页落库后立即保存页游标。CVE基线每批落库后保存文件游标。
- 增量窗口默认与上次水位重叠5分钟，再通过来源编号和内容哈希幂等去重。
- 带来源更新时间的旧快照和无时间快照不能覆盖已有的新快照。
- 批量任务按条继续；错误写入 `collection_failures`，成功重试后标记解决。
- CVE滚动日志无法覆盖已有水位时直接失败，防止数据缺口被误报为同步成功。
- AVD/CNNVD返回WAF、安全验证、登录页或字段不可识别时直接失败，不绕过验证，也不把页面当成空漏洞覆盖现有数据。

## 使用

```powershell
# 单条
python -m vulntools --db output/local.sqlite collect --source cve --id CVE-2024-3094
python -m vulntools --db output/local.sqlite collect --source nvd --id CVE-2024-3094
python -m vulntools --db output/local.sqlite collect --source avd --id AVD-2024-3094

# 取得正式授权后；密钥只通过配置中 token_env 指向的环境变量读取
python -m vulntools --db output/local.sqlite collect --source avd --id AVD-2024-3094 `
  --api-config examples/authorized-api.example.json

# NVD增量、指定区间和全量
python -m vulntools --db output/local.sqlite sync --source nvd
python -m vulntools --db output/local.sqlite sync --source nvd --since 2026-09-01T00:00:00Z --until 2026-09-14T00:00:00Z
python -m vulntools --db output/local.sqlite sync --source nvd --full --page-size 2000

# CVE首次基线和后续增量
python -m vulntools --db output/local.sqlite sync --source cve --full --baseline-dir D:/data/cvelistV5/cves --page-size 500
python -m vulntools --db output/local.sqlite sync --source cve

# 批量、失败恢复和状态
python -m vulntools --db output/local.sqlite collect-batch --source cnnvd --input path/to/cnnvd-ids.txt
python -m vulntools --db output/local.sqlite retry-collection --source cnnvd
python -m vulntools --db output/local.sqlite collection-status
```

批量输入可以是每行一个编号、JSON字符串数组或 `{"ids":[...]}`。AVD/CNNVD页面路径变化时可以提供包含 `{id}` 的 `--url-template`，但主机仍必须是对应官方允许主机。

## 授权 API 契约

授权配置使用 `vulntools/authorized-api/v1`。端点必须为不含用户名、密码的 HTTPS URL，并且只允许一个 `{id}` 占位符。认证值只从 `auth.token_env` 指定的环境变量读取；配置中的明文 token、password、API key，以及静态 `Authorization`/`X-Api-Key` 均会被拒绝。HTTP 客户端把配置端点主机作为唯一允许主机，重定向后再次检查。

响应可以直接采用本项目交换格式，也可以用 JSON Pointer 映射 `source_id`、出处、别名、更新时间和字段。缺失指针、错误类型、返回编号不匹配、非法状态或时间都会使本条失败并进入失败队列，不会以空字段覆盖已有数据。示例配置只展示契约，`example.invalid` 不是实际接口。

本地导入支持单个JSON、JSON数组、JSONL、AVD/CNNVD HTML详情页，以及CVE JSON目录。来源更新后运行：

公开详情页被验证机制阻断时，可以从仍可直接访问的官方目录页或官方报告构造带证据的交换文件：

```powershell
python scripts/build_public_catalog_exchange.py `
  --avd-page "https://avd.aliyun.com/product?prod=php7.4&page=1" `
  --output output/source-imports/avd-public-catalog.jsonl

python scripts/build_public_catalog_exchange.py `
  --cnnvd-pdf tmp/pdfs/cnnvd-report.pdf `
  --cnnvd-url "https://www.cnnvd.org.cn/path/to/report.pdf" `
  --output output/source-imports/cnnvd-public-report.jsonl

python -m vulntools --db output/local.sqlite import --source avd `
  --input output/source-imports/avd-public-catalog.jsonl
python -m vulntools --db output/local.sqlite import --source cnnvd `
  --input output/source-imports/cnnvd-public-report.jsonl
```

该脚本仅接受官方 HTTPS 主机，记录页面/报告 SHA-256、页码和原始证据片段。目录行不等同于漏洞详情页，因此不会虚构描述、利用代码或修复信息；遇到 WAF 仍会失败，不会尝试绕过。

```powershell
python -m vulntools --db output/local.sqlite process
python -m vulntools --db output/local.sqlite index
```

## 公开数据依据

- CVE Program：[CVE List Downloads](https://www.cve.org/Downloads)与官方[cvelistV5](https://github.com/CVEProject/cvelistV5)。
- NVD：[Vulnerabilities API](https://nvd.nist.gov/developers/vulnerabilities)。
- AVD：[阿里云漏洞库](https://avd.aliyun.com/)。
- CNNVD：[国家信息安全漏洞库](https://www.cnnvd.org.cn/)。

AVD和CNNVD当前没有在上述公开页面提供稳定、免登录、可供本项目声明支持的批量API。项目已提供授权 API 适配契约，但生产部署仍必须填入机构实际获准使用的端点和字段映射并完成联网验收，不能假设未公开接口长期稳定。
