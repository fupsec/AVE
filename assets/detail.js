const GH = {
  owner: "adysec",
  repo: "AVE",
  branch: "main",
};

function setStatus(text) {
  const el = document.getElementById("status");
  if (el) el.textContent = text;
}

function q(name) {
  return new URLSearchParams(location.search).get(name) || "";
}

function linksFromToml(text, key) {
  const arrRe = new RegExp(`^${key}\\s*=\\s*\\[(.*?)\\]`, "ms");
  const oneRe = new RegExp(`^${key}\\s*=\\s*\"([^\"]+)\"`, "m");
  const one = text.match(oneRe);
  if (one?.[1]) return [one[1]];
  const arr = text.match(arrRe);
  if (!arr?.[1]) return [];
  const out = [];
  const strRe = /"([^"]+)"/g;
  let m;
  while ((m = strRe.exec(arr[1])) !== null) out.push(m[1]);
  return out;
}

function textField(text, key, fallback = "") {
  const one = text.match(new RegExp(`^${key}\\s*=\\s*\"([^\"]*)\"`, "m"));
  if (one?.[1] !== undefined) return one[1];
  const multi = text.match(new RegExp(`^${key}\\s*=\\s*\"\"\"([\\s\\S]*?)\"\"\"`, "m"));
  if (multi?.[1] !== undefined) return multi[1].trim();
  return fallback;
}

function numField(text, key, fallback = 0) {
  const m = text.match(new RegExp(`^${key}\\s*=\\s*([0-9]+(?:\\.[0-9]+)?)`, "m"));
  return m ? Number(m[1]) : fallback;
}

function addLinks(el, arr) {
  el.innerHTML = "";
  if (!arr.length) {
    const p = document.createElement("p");
    p.textContent = "（无）";
    el.appendChild(p);
    return;
  }
  for (const u of arr) {
    const a = document.createElement("a");
    a.href = u;
    a.target = "_blank";
    a.rel = "noopener noreferrer";
    a.textContent = u;
    el.appendChild(a);
  }
}

function severityClass(sev) {
  const s = (sev || "UNKNOWN").toUpperCase();
  return ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO", "UNKNOWN"].includes(s) ? s : "UNKNOWN";
}

function listField(text, key) {
  return linksFromToml(text, key);
}

function extractAveId(value) {
  const m = String(value || "").match(/AVE-\d{4}-\d+/i);
  return m ? m[0].toUpperCase() : "";
}

async function loadAssetIndex() {
  const tree = await fetch(`https://api.github.com/repos/${GH.owner}/${GH.repo}/git/trees/${GH.branch}?recursive=1`, {
    headers: { Accept: "application/vnd.github+json" },
  });
  if (!tree.ok) throw new Error(`获取仓库文件索引失败：HTTP ${tree.status}`);
  const data = await tree.json();

  const pocUrlsByAve = new Map();
  const expUrlsByAve = new Map();

  for (const node of data.tree || []) {
    if (node.type !== "blob" || !node.path) continue;
    if (!node.path.startsWith("pocs/") && !node.path.startsWith("exploits/")) continue;

    const ave = extractAveId(node.path.split("/").pop());
    if (!ave) continue;
    const raw = `https://raw.githubusercontent.com/${GH.owner}/${GH.repo}/${GH.branch}/${node.path}`;

    if (node.path.startsWith("pocs/")) {
      const arr = pocUrlsByAve.get(ave) || [];
      arr.push(raw);
      pocUrlsByAve.set(ave, arr);
    } else {
      const arr = expUrlsByAve.get(ave) || [];
      arr.push(raw);
      expUrlsByAve.set(ave, arr);
    }
  }

  return { pocUrlsByAve, expUrlsByAve };
}

async function loadToml(fileName) {
  const safeName = fileName.endsWith(".toml") ? fileName : `${fileName}.toml`;
  const raw = `https://raw.githubusercontent.com/${GH.owner}/${GH.repo}/${GH.branch}/vulns/${safeName}`;
  const html = `https://github.com/${GH.owner}/${GH.repo}/blob/${GH.branch}/vulns/${safeName}`;
  const res = await fetch(raw, { cache: "no-cache" });
  if (!res.ok) throw new Error(`获取 TOML 失败：HTTP ${res.status}`);
  const text = await res.text();
  return { text, raw, html, safeName };
}

function render(toml, fileName, rawUrl, htmlUrl, assetIndex) {
  const ave = textField(toml, "ave_id", fileName.replace(/\.toml$/i, ""));
  const cve = textField(toml, "cve_id", "无");
  const title = textField(toml, "title", ave);
  const desc = textField(toml, "description", "");
  const sev = severityClass(textField(toml, "severity", "UNKNOWN"));
  const score = numField(toml, "score", 0);
  const aliases = listField(toml, "aliases");
  const sources = listField(toml, "sources");
  const published = textField(toml, "published", "");
  const updated = textField(toml, "updated", "");
  const remediation = textField(toml, "remediation", "");
  const status = textField(toml, "status", "");
  const collectedAt = textField(toml, "collected_at", "");

  const refs = linksFromToml(toml, "urls");
  const pocs = assetIndex.pocUrlsByAve.get(ave) || [];
  const exps = assetIndex.expUrlsByAve.get(ave) || [];

  document.getElementById("detail-subtitle").textContent = `${ave} / ${cve}`;
  document.getElementById("d-ave").textContent = ave;
  const sevEl = document.getElementById("d-sev");
  sevEl.textContent = sev;
  sevEl.classList.add(sev);
  document.getElementById("d-title").textContent = title;
  document.getElementById("d-desc").textContent = desc;
  document.getElementById("d-meta").textContent = `CVE: ${cve} | 评分: ${score}`;

  const extra = document.getElementById("d-extra");
  extra.innerHTML = "";
  const pairs = [
    ["别名", aliases.join(", ") || "无"],
    ["来源", sources.join(", ") || "无"],
    ["发布时间", published || "无"],
    ["更新时间", updated || "无"],
    ["采集状态", status || "无"],
    ["采集时间", collectedAt || "无"],
  ];
  for (const [k, v] of pairs) {
    const p = document.createElement("p");
    const s = document.createElement("strong");
    s.textContent = `${k}: `;
    p.appendChild(s);
    p.append(document.createTextNode(v));
    extra.appendChild(p);
  }

  const rem = document.getElementById("d-remediation");
  rem.textContent = remediation ? `修复建议: ${remediation}` : "";

  const pocFlag = document.getElementById("d-poc");
  const expFlag = document.getElementById("d-exp");
  pocFlag.textContent = `PoC：${pocs.length ? "有" : "无"}`;
  expFlag.textContent = `EXP：${exps.length ? "有" : "无"}`;
  if (pocs.length) pocFlag.classList.add("yes");
  if (exps.length) expFlag.classList.add("yes");

  addLinks(document.getElementById("d-refs"), refs);
  addLinks(document.getElementById("d-pocs"), pocs);
  addLinks(document.getElementById("d-exps"), exps);

  const rawLink = document.getElementById("d-raw");
  rawLink.href = htmlUrl;
  rawLink.dataset.raw = rawUrl;

  document.getElementById("detail-card").style.display = "block";
}

async function boot() {
  const file = q("file").trim();
  if (!file) {
    setStatus("缺少参数：file");
    return;
  }

  setStatus("正在拉取并解析 TOML ...");
  try {
    const assetIndex = await loadAssetIndex();
    const { text, raw, html, safeName } = await loadToml(file);
    render(text, safeName, raw, html, assetIndex);
    setStatus("已完成 TOML 解析。")
  } catch (e) {
    setStatus(`加载失败：${e.message}`);
  }
}

boot();
