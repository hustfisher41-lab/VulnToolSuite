"""Dependency-free local acceptance dashboard served by the FastAPI process."""

DASHBOARD_HTML = r"""<!doctype html>
<html lang="zh-CN">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>VulnToolSuite 验收台</title>
  <style>
    :root {
      color-scheme: light;
      --ink: #14211f;
      --muted: #61706c;
      --paper: #eef1e9;
      --panel: #f8faf4;
      --line: #c6cec4;
      --deep: #173b36;
      --signal: #ef5a37;
      --good: #1c7b5a;
      --warn: #a66516;
      --bad: #a93831;
      --shadow: 0 16px 40px rgba(32, 49, 45, .10);
    }
    * { box-sizing: border-box; }
    body {
      margin: 0;
      min-height: 100vh;
      color: var(--ink);
      background:
        linear-gradient(rgba(23, 59, 54, .035) 1px, transparent 1px),
        linear-gradient(90deg, rgba(23, 59, 54, .035) 1px, transparent 1px),
        var(--paper);
      background-size: 30px 30px;
      font-family: "Aptos", "Microsoft YaHei UI", sans-serif;
    }
    button, input, select { font: inherit; }
    a { color: inherit; }
    .shell { width: min(1480px, calc(100% - 32px)); margin: 0 auto; padding: 30px 0 56px; }
    header { display: grid; grid-template-columns: 1fr auto; gap: 24px; align-items: end; margin-bottom: 26px; }
    .eyebrow { margin: 0 0 8px; color: var(--signal); font: 700 11px/1.2 Consolas, monospace; letter-spacing: .18em; text-transform: uppercase; }
    h1 { margin: 0; max-width: 820px; font: 700 clamp(28px, 4.8vw, 62px)/.98 Bahnschrift, "Microsoft YaHei UI", sans-serif; letter-spacing: -.045em; }
    .subtitle { max-width: 720px; margin: 14px 0 0; color: var(--muted); line-height: 1.7; }
    .stamp { text-align: right; color: var(--muted); font: 12px/1.6 Consolas, monospace; }
    .status-rail { display: grid; grid-template-columns: repeat(3, 1fr); border: 1px solid var(--line); background: var(--panel); box-shadow: var(--shadow); }
    .status { min-height: 74px; padding: 15px 18px; border-right: 1px solid var(--line); }
    .status:last-child { border-right: 0; }
    .status small { display: block; margin-bottom: 8px; color: var(--muted); font: 700 10px Consolas, monospace; letter-spacing: .12em; text-transform: uppercase; }
    .status strong { display: flex; gap: 9px; align-items: center; font-size: 14px; }
    .dot { width: 9px; height: 9px; border-radius: 50%; background: var(--muted); box-shadow: 0 0 0 4px rgba(97,112,108,.12); }
    .dot.good { background: var(--good); box-shadow: 0 0 0 4px rgba(28,123,90,.12); }
    .dot.warn { background: var(--warn); box-shadow: 0 0 0 4px rgba(166,101,22,.12); }
    .dot.bad { background: var(--bad); box-shadow: 0 0 0 4px rgba(169,56,49,.12); }
    .metrics { display: grid; grid-template-columns: repeat(6, minmax(0, 1fr)); gap: 10px; margin: 10px 0 26px; }
    .metric { min-height: 114px; padding: 17px; border: 1px solid var(--line); background: rgba(248,250,244,.78); }
    .metric .label { min-height: 30px; color: var(--muted); font-size: 11px; letter-spacing: .06em; text-transform: uppercase; }
    .metric .value { margin-top: 9px; font: 700 clamp(22px, 2.5vw, 34px)/1 Bahnschrift, sans-serif; letter-spacing: -.04em; }
    .metric .note { margin-top: 8px; color: var(--muted); font: 11px Consolas, monospace; }
    .grid { display: grid; grid-template-columns: minmax(0, 1.45fr) minmax(360px, .85fr); gap: 14px; }
    .panel { border: 1px solid var(--line); background: var(--panel); box-shadow: 0 9px 26px rgba(32,49,45,.06); }
    .panel-head { display: flex; justify-content: space-between; gap: 18px; align-items: baseline; padding: 17px 19px; border-bottom: 1px solid var(--line); }
    .panel-head h2 { margin: 0; font: 700 15px Bahnschrift, sans-serif; letter-spacing: .02em; }
    .panel-head span { color: var(--muted); font-size: 11px; }
    .panel-body { padding: 19px; }
    .search-form { display: grid; grid-template-columns: 1fr 140px 110px auto; gap: 8px; }
    .control { min-width: 0; height: 44px; padding: 0 12px; border: 1px solid var(--line); color: var(--ink); background: #fff; outline: none; }
    .control:focus { border-color: var(--deep); box-shadow: 0 0 0 3px rgba(23,59,54,.10); }
    .primary { border: 1px solid var(--deep); padding: 0 18px; color: #fff; background: var(--deep); cursor: pointer; font-weight: 700; }
    .primary:hover { background: #0e2925; }
    .primary:disabled { opacity: .55; cursor: wait; }
    .query-note { margin: 10px 0 0; color: var(--muted); font-size: 11px; }
    .results { display: grid; gap: 8px; margin-top: 16px; }
    .result { padding: 14px 15px; border: 1px solid var(--line); background: #fff; animation: rise .32s ease both; }
    .result-top { display: flex; justify-content: space-between; gap: 16px; }
    .result-id { color: var(--deep); font: 700 13px Consolas, monospace; }
    .badge { display: inline-flex; align-items: center; min-height: 22px; padding: 2px 7px; border: 1px solid currentColor; font: 700 10px Consolas, monospace; text-transform: uppercase; }
    .badge.critical { color: #9d2624; background: #fae3df; }
    .badge.high { color: #a94c21; background: #f8e9df; }
    .badge.medium { color: #8b6719; background: #f5efd9; }
    .badge.low { color: var(--good); background: #e2f2e9; }
    .result-title { margin: 8px 0 0; font-size: 14px; font-weight: 650; }
    .scores { display: flex; flex-wrap: wrap; gap: 12px; margin-top: 10px; color: var(--muted); font: 11px Consolas, monospace; }
    .source-links { display: flex; flex-wrap: wrap; gap: 7px; margin-top: 10px; }
    .source-links a { max-width: 270px; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; color: var(--deep); font-size: 11px; }
    .chart-list { display: grid; gap: 12px; }
    .bar-row { display: grid; grid-template-columns: minmax(86px, 130px) 1fr 70px; gap: 10px; align-items: center; font-size: 12px; }
    .bar-name { overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
    .track { height: 8px; overflow: hidden; background: #dde3da; }
    .fill { height: 100%; width: 0; background: var(--deep); transition: width .65s cubic-bezier(.2,.7,.2,1); }
    .fill.signal { background: var(--signal); }
    .bar-value { text-align: right; color: var(--muted); font: 11px Consolas, monospace; }
    .stack { display: grid; gap: 14px; }
    .fact { padding: 13px 14px; border-left: 3px solid var(--deep); background: #edf2e9; }
    .fact.warn { border-color: var(--warn); background: #f7f0e1; }
    .fact.bad { border-color: var(--bad); background: #f7e8e5; }
    .fact strong { display: block; font-size: 12px; }
    .fact span { display: block; margin-top: 5px; color: var(--muted); font-size: 11px; line-height: 1.55; }
    .empty { padding: 24px; border: 1px dashed var(--line); color: var(--muted); text-align: center; font-size: 12px; }
    .error { color: var(--bad); }
    .foot { margin-top: 20px; color: var(--muted); font: 11px/1.7 Consolas, monospace; }
    .span-2 { grid-column: 1 / -1; }
    @keyframes rise { from { opacity: 0; transform: translateY(5px); } to { opacity: 1; transform: none; } }
    @media (max-width: 1100px) {
      .metrics { grid-template-columns: repeat(3, 1fr); }
      .grid { grid-template-columns: 1fr; }
    }
    @media (max-width: 720px) {
      .shell { width: min(100% - 20px, 1480px); padding-top: 20px; }
      header { grid-template-columns: 1fr; }
      .stamp { text-align: left; }
      .status-rail { grid-template-columns: 1fr; }
      .status { border-right: 0; border-bottom: 1px solid var(--line); }
      .status:last-child { border-bottom: 0; }
      .metrics { grid-template-columns: repeat(2, 1fr); }
      .search-form { grid-template-columns: 1fr 1fr; }
      .search-form input { grid-column: 1 / -1; }
      .bar-row { grid-template-columns: 90px 1fr 62px; }
    }
  </style>
</head>
<body>
  <main class="shell">
    <header>
      <div>
        <p class="eyebrow">local acceptance console / v0.2</p>
        <h1>漏洞知识与安全测试平台</h1>
        <p class="subtitle">用真实数据库状态回答“能不能用”。这里不把占位数据、模拟沙箱或未建立的向量索引显示成已完成能力。</p>
      </div>
      <div class="stamp"><div id="generated">正在读取状态…</div><div>仅监听 127.0.0.1</div></div>
    </header>

    <section class="status-rail" aria-label="核心状态">
      <div class="status"><small>Database</small><strong><i id="db-dot" class="dot"></i><span id="db-state">连接中</span></strong></div>
      <div class="status"><small>Vector index</small><strong><i id="index-dot" class="dot"></i><span id="index-state">检查中</span></strong></div>
      <div class="status"><small>Sandbox</small><strong><i id="sandbox-dot" class="dot"></i><span id="sandbox-state">检查中</span></strong></div>
    </section>

    <section class="metrics" aria-label="关键指标">
      <article class="metric"><div class="label">规范漏洞</div><div id="m-records" class="value">—</div><div id="m-active" class="note">—</div></article>
      <article class="metric"><div class="label">来源记录</div><div id="m-sources" class="value">—</div><div class="note">CVE / NVD / AVD / CNNVD</div></article>
      <article class="metric"><div class="label">已建立索引</div><div id="m-indexed" class="value">—</div><div id="m-index-note" class="note">—</div></article>
      <article class="metric"><div class="label">PoC 工件</div><div id="m-poc" class="value">—</div><div id="m-poc-note" class="note">—</div></article>
      <article class="metric"><div class="label">SFT 样本</div><div id="m-sft" class="value">—</div><div class="note">结构化校验后的导出</div></article>
      <article class="metric"><div class="label">安全轨迹</div><div id="m-trajectories" class="value">—</div><div id="m-trajectory-note" class="note">—</div></article>
    </section>

    <section class="grid">
      <article class="panel">
        <div class="panel-head"><h2>混合检索</h2><span>向量余弦 + BM25 + RRF</span></div>
        <div class="panel-body">
          <form id="search-form" class="search-form">
            <input id="query" class="control" type="search" required placeholder="例如：xz liblzma 后门，或 archive path traversal" aria-label="检索内容">
            <input id="weakness" class="control" placeholder="CWE-79" aria-label="CWE 过滤">
            <select id="severity" class="control" aria-label="严重性过滤">
              <option value="">全部等级</option><option>critical</option><option>high</option><option>medium</option><option>low</option>
            </select>
            <button id="search-button" class="primary" type="submit">检索</button>
          </form>
          <p id="query-note" class="query-note">结果包含各检索通道分数、证据与来源链接。</p>
          <div id="results" class="results"><div class="empty">输入自然语言描述开始检索</div></div>
        </div>
      </article>

      <div class="stack">
        <article class="panel">
          <div class="panel-head"><h2>验收边界</h2><span>实时状态</span></div>
          <div id="facts" class="panel-body stack"></div>
        </article>
        <article class="panel">
          <div class="panel-head"><h2>数据来源</h2><span>原始记录数</span></div>
          <div id="sources" class="panel-body chart-list"></div>
        </article>
      </div>

      <article class="panel">
        <div class="panel-head"><h2>严重性分布</h2><span>有效漏洞</span></div>
        <div id="severity-chart" class="panel-body chart-list"></div>
      </article>
      <article class="panel">
        <div class="panel-head"><h2>核心字段缺失</h2><span>有效漏洞</span></div>
        <div id="missing-chart" class="panel-body chart-list"></div>
      </article>
      <article class="panel">
        <div class="panel-head"><h2>安全测试闭环</h2><span>可观察动作与证据</span></div>
        <div id="trajectory-facts" class="panel-body stack"></div>
      </article>
    </section>
    <p class="foot">后端：本地 FastAPI · 数据库：SQLite · 索引：小库精确检索 / 大库流式候选 + 多视图精排。未配置的外部服务会明确显示为未连接。</p>
  </main>
  <script>
    const fmt = new Intl.NumberFormat('zh-CN');
    const pct = (value, total) => total ? `${(value / total * 100).toFixed(1)}%` : '0.0%';
    const text = (id, value) => { document.getElementById(id).textContent = value; };
    function setState(prefix, label, state) {
      text(`${prefix}-state`, label);
      document.getElementById(`${prefix}-dot`).className = `dot ${state}`;
    }
    function bars(target, data, total, signal=false) {
      const root = document.getElementById(target); root.replaceChildren();
      const entries = Object.entries(data).sort((a,b) => b[1]-a[1]);
      if (!entries.length) { root.innerHTML = '<div class="empty">暂无数据</div>'; return; }
      const max = Math.max(...entries.map(([,v]) => v), 1);
      entries.forEach(([name, value]) => {
        const row = document.createElement('div'); row.className = 'bar-row';
        const label = document.createElement('div'); label.className = 'bar-name'; label.textContent = name;
        const track = document.createElement('div'); track.className = 'track';
        const fill = document.createElement('div'); fill.className = `fill ${signal ? 'signal' : ''}`; track.append(fill);
        const number = document.createElement('div'); number.className = 'bar-value'; number.textContent = `${fmt.format(value)} · ${pct(value,total)}`;
        row.append(label, track, number); root.append(row);
        requestAnimationFrame(() => fill.style.width = `${Math.max(1.5, value/max*100)}%`);
      });
    }
    function fact(root, title, body, tone='') {
      const item = document.createElement('div'); item.className = `fact ${tone}`;
      const strong = document.createElement('strong'); strong.textContent = title;
      const span = document.createElement('span'); span.textContent = body;
      item.append(strong, span); root.append(item);
    }
    async function loadSummary() {
      const response = await fetch('/analytics/summary');
      if (!response.ok) throw new Error(`HTTP ${response.status}`);
      const data = await response.json(), db = data.database, index = data.index, trajectories = data.trajectories;
      text('generated', new Date(data.generated_at).toLocaleString('zh-CN'));
      setState('db', `${fmt.format(db.active)} 条有效记录`, 'good');
      setState('index', index.ready ? '索引完整，可检索' : `缺少 ${fmt.format(index.missing_records)} 条`, index.ready ? 'good' : 'warn');
      setState('sandbox', data.sandbox.execution_ready ? '执行后端已验收' : '真实执行未配置', data.sandbox.execution_ready ? 'good' : 'bad');
      text('m-records', fmt.format(db.records)); text('m-active', `${fmt.format(db.active)} active · ${fmt.format(db.rejected)} rejected`);
      text('m-sources', fmt.format(Object.values(db.sources).reduce((a,b)=>a+b,0)));
      text('m-indexed', fmt.format(index.indexed_records)); text('m-index-note', `${fmt.format(index.vector_views)} 个多视图向量`);
      text('m-poc', fmt.format(db.poc_artifacts)); text('m-poc-note', `${fmt.format(db.poc_linked_records)} 个有效漏洞有关联`);
      const counts = data.dataset.counts || {}; text('m-sft', fmt.format((counts.sft_classification||0)+(counts.sft_poc_association||0)));
      text('m-trajectories', fmt.format(trajectories.total));
      text('m-trajectory-note', `${fmt.format(trajectories.real_executions)} 真实 · ${fmt.format(trajectories.simulated)} fixture`);
      bars('sources', db.sources, Object.values(db.sources).reduce((a,b)=>a+b,0));
      bars('severity-chart', db.severity, db.active);
      bars('missing-chart', db.missing_fields, db.active, true);
      const facts = document.getElementById('facts'); facts.replaceChildren();
      fact(facts, index.encoder.semantic_model ? '语义模型已启用' : '当前不是语义模型', index.encoder.semantic_model ? index.encoder.provider : '当前索引使用 feature-hash 词法向量，能够执行余弦检索，但不能宣称深层语义理解。', index.encoder.semantic_model ? '' : 'warn');
      fact(facts, 'AVD / CNNVD', db.sources.avd || db.sources.cnnvd ? '数据库中已有对应来源记录。' : '当前主库没有 AVD/CNNVD 数据；公开页面受 WAF 或页面结构限制，需要正式授权导出/API。', db.sources.avd || db.sources.cnnvd ? '' : 'warn');
      fact(facts, '安全执行', data.sandbox.note, data.sandbox.execution_ready ? '' : 'bad');
      fact(facts, '训练数据', data.dataset.status === 'available' ? `结构校验：${data.dataset.validation.status || 'unknown'}；正式偏好数据 ${fmt.format(counts.preference||0)} 条。` : '训练数据清单未连接。', data.dataset.status === 'available' ? '' : 'warn');
      const trajectoryFacts = document.getElementById('trajectory-facts'); trajectoryFacts.replaceChildren();
      fact(trajectoryFacts, '轨迹持久化', trajectories.total ? `${fmt.format(trajectories.total)} 个任务、${fmt.format(trajectories.steps)} 个步骤、${fmt.format(trajectories.runtime_events)} 个运行事件。` : '尚无轨迹；运行 trajectory-smoke 可生成显式标注的 fixture 闭环。', trajectories.total ? '' : 'warn');
      fact(trajectoryFacts, '真实执行', trajectories.real_executions ? `${fmt.format(trajectories.real_executions)} 个任务来自已验收执行后端。` : '0 个；fixture 不能作为隔离或真实漏洞证明。', trajectories.real_executions ? '' : 'bad');
      fact(trajectoryFacts, '异常事件', `${fmt.format(trajectories.abnormal_events)} 个 timeout / OOM / policy violation / monitor lost 事件。`, trajectories.abnormal_events ? 'warn' : '');
      fact(trajectoryFacts, '训练导出', '轨迹可导出为 JSONL 与 observable-action SFT；不会保存模型内部思维过程。');
    }
    function addResult(hit, index) {
      const card = document.createElement('article'); card.className = 'result'; card.style.animationDelay = `${index*35}ms`;
      const top = document.createElement('div'); top.className = 'result-top';
      const id = document.createElement('a'); id.className = 'result-id'; id.href = `/records/${encodeURIComponent(hit.vuln_id)}`; id.target = '_blank'; id.rel='noopener'; id.textContent = hit.vuln_id;
      const badge = document.createElement('span'); badge.className = `badge ${String(hit.severity||'').toLowerCase()}`; badge.textContent = hit.severity || 'unknown';
      top.append(id,badge); card.append(top);
      const title = document.createElement('p'); title.className='result-title'; title.textContent=hit.title || '无标题'; card.append(title);
      const scores = document.createElement('div'); scores.className='scores';
      scores.textContent = `RANK ${hit.rank}  ·  COS ${Number(hit.scores.cosine||0).toFixed(4)}  ·  BM25 ${Number(hit.scores.bm25||0).toFixed(4)}  ·  ${hit.index_backend}`; card.append(scores);
      const links = document.createElement('div'); links.className='source-links';
      (hit.source_urls||[]).slice(0,4).forEach((url) => { try { const parsed=new URL(url); if(!['http:','https:'].includes(parsed.protocol)) return; const a=document.createElement('a'); a.href=url; a.target='_blank'; a.rel='noopener noreferrer'; a.textContent=parsed.hostname; links.append(a); } catch {} });
      card.append(links); document.getElementById('results').append(card);
    }
    document.getElementById('search-form').addEventListener('submit', async (event) => {
      event.preventDefault(); const button=document.getElementById('search-button'), results=document.getElementById('results');
      const body={query:document.getElementById('query').value.trim(), weakness:document.getElementById('weakness').value.trim()||null, severity:document.getElementById('severity').value||null, top_k:10, mode:'hybrid'};
      button.disabled=true; text('query-note','正在执行实际索引检索…'); results.innerHTML='<div class="empty">查询中</div>';
      try { const response=await fetch('/search',{method:'POST',headers:{'content-type':'application/json'},body:JSON.stringify(body)}); const data=await response.json(); if(!response.ok) throw new Error(data.detail||`HTTP ${response.status}`); results.replaceChildren(); (data.hits||[]).forEach(addResult); if(!data.hits?.length) results.innerHTML='<div class="empty">没有命中；过滤条件不会被自动放宽。</div>'; text('query-note',`返回 ${data.hits?.length||0} 条真实结果。`); }
      catch(error) { results.innerHTML=`<div class="empty error"></div>`; results.firstElementChild.textContent=`检索失败：${error.message}`; text('query-note','检索接口未通过。'); }
      finally { button.disabled=false; }
    });
    loadSummary().catch(error => { setState('db',`状态读取失败：${error.message}`,'bad'); });
  </script>
</body>
</html>"""
