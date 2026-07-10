const GH = {
  owner: "adysec",
  repo: "AVE",
  branch: "main",
};

const PAGE_SIZE = 30;
const state = {
  page: 1,
  total: 0,
  totalPages: 1,
  mode: "search", // search | tree
  keyword: "",
  severity: "",
  treeCache: null,
};

let loadToken = 0;

function enc(s) {
  return encodeURIComponent(s);
}

function severityFromToml(text) {
  const m = text.match(/^severity\s*=\s*"([A-Za-z]+)"/m);
  return (m?.[1] || "UNKNOWN").toUpperCase();
}

function scoreFromToml(text) {
  const m = text.match(/^score\s*=\s*([0-9]+(?:\.[0-9]+)?)/m);
  return m ? Number(m[1]) : 0;
}

function titleFromToml(text, fallback) {
  const m = text.match(/^title\s*=\s*"([^"]*)"/m);
  return m?.[1] || fallback;
}

function descFromToml(text) {
  const m = text.match(/^description\s*=\s*"([^"]*)"/m);
  if (m?.[1]) return m[1];
  const ml = text.match(/^description\s*=\s*"""([\s\S]*?)"""/m);
  return ml?.[1]?.trim() || "";
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

async function gh(url) {
  const res = await fetch(url, { headers: { Accept: "application/vnd.github+json" } });
  if (!res.ok) throw new Error(`GitHub API ${res.status}: ${url}`);
  return res.json();
}

async function fetchText(item) {
  return (await fetch(item.download_url, { cache: "no-cache" })).text();
}

function toCard(item, text) {
  const ave = item.name.replace(/\.toml$/i, "");
  const cve = text.match(/^cve_id\s*=\s*"([^"]+)"/m)?.[1] || "无";
  const pocs = linksFromToml(text, "poc_urls");
  const exps = linksFromToml(text, "exp_urls");

  return {
    ave_id: ave,
    file_name: item.name,
    cve_id: cve,
    title: titleFromToml(text, ave),
    description: descFromToml(text),
    severity: severityFromToml(text),
    score: scoreFromToml(text),
    references: linksFromToml(text, "urls"),
    poc_urls: pocs,
    exp_urls: exps,
    has_poc: pocs.length > 0,
    has_exp: exps.length > 0,
    raw_url: item.html_url,
  };
}

function sevClass(s) {
  return ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO", "UNKNOWN"].includes(s) ? s : "UNKNOWN";
}

function setStatus(t) {
  const el = document.getElementById("status");
  if (el) el.textContent = t;
}

function renderPager() {
  document.getElementById("page-info").textContent = `第 ${state.page} / ${state.totalPages} 页（共 ${state.total} 条）`;
  document.getElementById("prev-page").disabled = state.page <= 1;
  document.getElementById("next-page").disabled = state.page >= state.totalPages;
}

function renderList(cards) {
  const list = document.getElementById("list");
  const tpl = document.getElementById("card-template");
  list.innerHTML = "";

  for (const c of cards) {
    const n = tpl.content.firstElementChild.cloneNode(true);
    n.querySelector(".id").textContent = c.ave_id;
    const s = n.querySelector(".severity");
    s.textContent = c.severity;
    s.classList.add(sevClass(c.severity));
    n.querySelector(".title").textContent = c.title || c.cve_id;
    n.querySelector(".description").textContent = c.description;
    n.querySelector(".meta").textContent = `CVE: ${c.cve_id} | 评分: ${c.score}`;

    const detailLink = n.querySelector(".detail-link");
    detailLink.href = `detail.html?file=${encodeURIComponent(c.file_name)}`;

    const pocFlag = n.querySelector(".poc-flag");
    const expFlag = n.querySelector(".exp-flag");
    pocFlag.textContent = `PoC：${c.has_poc ? "有" : "无"}`;
    expFlag.textContent = `EXP：${c.has_exp ? "有" : "无"}`;
    if (c.has_poc) pocFlag.classList.add("yes");
    if (c.has_exp) expFlag.classList.add("yes");

    const links = n.querySelector(".links");
    const groups = [
      ["参考链接", c.references],
      ["PoC", c.poc_urls],
      ["EXP", c.exp_urls],
      ["原始 TOML", [c.raw_url]],
    ];

    for (const [label, arr] of groups) {
      const h = document.createElement("strong");
      h.textContent = label;
      links.appendChild(h);
      if (!arr.length) {
        const p = document.createElement("p");
        p.textContent = "（无）";
        links.appendChild(p);
      } else {
        for (const u of arr) {
          const a = document.createElement("a");
          a.href = u;
          a.target = "_blank";
          a.rel = "noopener noreferrer";
          a.textContent = u;
          links.appendChild(a);
        }
      }
    }
    list.appendChild(n);
  }
}

function filterBySeverity(cards) {
  if (!state.severity) return cards;
  return cards.filter((c) => c.severity === state.severity);
}

async function searchViaCodeApi(keyword, page) {
  let q = `repo:${GH.owner}/${GH.repo} path:vulns extension:toml`;
  if (keyword && keyword.trim()) q += ` ${keyword.trim()}`;
  const data = await gh(`https://api.github.com/search/code?q=${enc(q)}&per_page=${PAGE_SIZE}&page=${page}`);
  state.mode = "search";
  state.total = Math.min(data.total_count || 0, 1000);
  state.totalPages = Math.max(1, Math.ceil(state.total / PAGE_SIZE));
  return data.items || [];
}

async function ensureTreeCache() {
  if (state.treeCache) return state.treeCache;
  const tree = await gh(`https://api.github.com/repos/${GH.owner}/${GH.repo}/git/trees/${GH.branch}?recursive=1`);
  const all = (tree.tree || [])
    .filter((n) => n.type === "blob")
    .filter((n) => n.path && n.path.startsWith("vulns/") && n.path.endsWith(".toml"))
    .map((n) => {
      const name = n.path.split("/").pop();
      const stem = name.replace(/\.toml$/i, "");
      return {
        name,
        stem,
        html_url: `https://github.com/${GH.owner}/${GH.repo}/blob/${GH.branch}/${n.path}`,
        download_url: `https://raw.githubusercontent.com/${GH.owner}/${GH.repo}/${GH.branch}/${n.path}`,
      };
    })
    .sort((a, b) => a.name.localeCompare(b.name));
  state.treeCache = all;
  return all;
}

async function searchViaTreeFallback(keyword, page) {
  const all = await ensureTreeCache();
  const kw = (keyword || "").trim().toLowerCase();
  const filtered = kw
    ? all.filter((i) => i.name.toLowerCase().includes(kw) || i.stem.toLowerCase().includes(kw))
    : all;

  state.mode = "tree";
  state.total = filtered.length;
  state.totalPages = Math.max(1, Math.ceil(state.total / PAGE_SIZE));

  const start = (page - 1) * PAGE_SIZE;
  return filtered.slice(start, start + PAGE_SIZE);
}

async function fetchListPage(keyword, page) {
  try {
    return await searchViaCodeApi(keyword, page);
  } catch (_e) {
    return await searchViaTreeFallback(keyword, page);
  }
}

async function runPage(page) {
  const token = ++loadToken;
  state.page = Math.max(1, page);
  setStatus("正在调用 GitHub API 搜索...");

  const rawList = await fetchListPage(state.keyword, state.page);
  if (token !== loadToken) return;

  const cards = [];
  for (const item of rawList) {
    const text = await fetchText(item);
    cards.push(toCard(item, text));
  }
  if (token !== loadToken) return;

  cards.sort((a, b) => a.ave_id.localeCompare(b.ave_id));
  const finalCards = filterBySeverity(cards);
  renderList(finalCards);
  renderPager();
  setStatus(`已显示第 ${state.page} 页，当前模式：${state.mode === "search" ? "Code Search" : "Tree Fallback"}。`);
}

function debounce(fn, wait) {
  let timer = null;
  return (...args) => {
    if (timer) clearTimeout(timer);
    timer = setTimeout(() => fn(...args), wait);
  };
}

async function boot() {
  setStatus("正在加载首批漏洞数据...");

  const searchInput = document.getElementById("search");
  const severityInput = document.getElementById("severity");
  const prev = document.getElementById("prev-page");
  const next = document.getElementById("next-page");

  const rerun = debounce(() => {
    state.keyword = searchInput.value || "";
    state.severity = severityInput.value || "";
    runPage(1).catch((e) => setStatus(`搜索失败：${e.message}`));
  }, 450);

  searchInput.addEventListener("input", rerun);
  severityInput.addEventListener("change", rerun);
  prev.addEventListener("click", () => runPage(state.page - 1).catch((e) => setStatus(`翻页失败：${e.message}`)));
  next.addEventListener("click", () => runPage(state.page + 1).catch((e) => setStatus(`翻页失败：${e.message}`)));

  try {
    await runPage(1);
  } catch (e) {
    setStatus(`加载失败：${e.message}`);
  }
}

boot();
