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
  loaded: false,
  keyword: "",
  severity: "",
  treeCache: null,
  treeCacheFailed: false,
  assetIndex: null,
  assetIndexFailed: false,
  lastCards: [],
  sortKey: "ave_id",
  sortDir: "asc",
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

function textField(text, key, fallback = "") {
  const one = text.match(new RegExp(`^${key}\\s*=\\s*\"([^\"]*)\"`, "m"));
  if (one?.[1] !== undefined) return one[1];
  const multi = text.match(new RegExp(`^${key}\\s*=\\s*\"\"\"([\\s\\S]*?)\"\"\"`, "m"));
  if (multi?.[1] !== undefined) return multi[1].trim();
  return fallback;
}

function listField(text, key) {
  return linksFromToml(text, key);
}

async function gh(url) {
  const res = await fetch(url, { headers: { Accept: "application/vnd.github+json" } });
  if (!res.ok) {
    let msg = `GitHub API ${res.status}`;
    if (res.status === 403) {
      const remaining = res.headers.get("X-RateLimit-Remaining");
      const reset = res.headers.get("X-RateLimit-Reset");
      if (remaining === "0" && reset) {
        const wait = Math.max(0, Math.ceil((Number(reset) * 1000 - Date.now()) / 60000));
        msg += `：API 速率限制已达，约 ${wait} 分钟后恢复。`;
      } else {
        msg += "：权限不足或访问被拒绝。";
      }
    } else {
      msg += `: ${url}`;
    }
    const err = new Error(msg);
    err.status = res.status;
    throw err;
  }
  return res.json();
}

async function fetchText(item) {
  return (await fetch(item.download_url, { cache: "no-cache" })).text();
}

function extractAveId(value) {
  const m = String(value || "").match(/AVE-\d{4}-\d+/i);
  return m ? m[0].toUpperCase() : "";
}

function getRepoAssetUrls(index, aveId, type) {
  if (!index || !aveId) return [];
  if (type === "poc") return index.pocUrlsByAve.get(aveId) || [];
  if (type === "exp") return index.expUrlsByAve.get(aveId) || [];
  return [];
}

async function ensureAssetIndex() {
  if (state.assetIndex) return state.assetIndex;
  if (state.assetIndexFailed) return null;

  try {
    const tree = await gh(`https://api.github.com/repos/${GH.owner}/${GH.repo}/git/trees/${GH.branch}?recursive=1`);
    const pocUrlsByAve = new Map();
    const expUrlsByAve = new Map();

    for (const node of tree.tree || []) {
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

    state.assetIndex = { pocUrlsByAve, expUrlsByAve };
    return state.assetIndex;
  } catch (e) {
    state.assetIndexFailed = true;
    if (e.status === 403) {
      setStatus("⚠ PoC/EXP 资产索引因 API 限流暂时不可用，列表仍可正常浏览。");
    }
    return null;
  }
}

function toCard(item, text, assetIndex) {
  const ave = item.name.replace(/\.toml$/i, "");
  const cve = textField(text, "cve_id", "无");
  const pocs = linksFromToml(text, "poc_urls");
  const exps = linksFromToml(text, "exp_urls");
  const repoPocs = getRepoAssetUrls(assetIndex, ave, "poc");
  const repoExps = getRepoAssetUrls(assetIndex, ave, "exp");

  return {
    ave_id: ave,
    file_name: item.name,
    cve_id: cve,
    title: titleFromToml(text, ave),
    description: descFromToml(text),
    severity: severityFromToml(text),
    score: scoreFromToml(text),
    aliases: listField(text, "aliases"),
    sources: listField(text, "sources"),
    published: textField(text, "published", ""),
    updated: textField(text, "updated", ""),
    remediation: textField(text, "remediation", ""),
    status: textField(text, "status", ""),
    collected_at: textField(text, "collected_at", ""),
    references: linksFromToml(text, "urls"),
    poc_urls: pocs,
    exp_urls: exps,
    repo_poc_urls: repoPocs,
    repo_exp_urls: repoExps,
    has_poc: repoPocs.length > 0,
    has_exp: repoExps.length > 0,
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

function showLoading(on) {
  const el = document.getElementById("spinner");
  if (el) el.style.display = on ? "inline-block" : "none";
}

function saveUrlState() {
  const params = new URLSearchParams();
  if (state.keyword) params.set("q", state.keyword);
  if (state.severity) params.set("sev", state.severity);
  if (state.page > 1) params.set("p", String(state.page));
  const str = params.toString();
  const url = str ? `?${str}` : window.location.pathname;
  history.replaceState(null, "", url);
}

function restoreUrlState() {
  const params = new URLSearchParams(location.search);
  return {
    keyword: params.get("q") || "",
    severity: params.get("sev") || "",
    page: parseInt(params.get("p") || "1", 10),
  };
}

function updateSortIndicators() {
  document.querySelectorAll("[data-sort-key]").forEach((th) => {
    const arrow = th.querySelector(".sort-arrow");
    if (arrow) {
      arrow.textContent =
        th.dataset.sortKey === state.sortKey
          ? state.sortDir === "asc" ? " ▲" : " ▼"
          : "";
    }
  });
}

function sortCards(cards) {
  const key = state.sortKey;
  const dir = state.sortDir === "asc" ? 1 : -1;
  return [...cards].sort((a, b) => {
    let va = a[key], vb = b[key];
    if (va == null) va = "";
    if (vb == null) vb = "";
    if (typeof va === "string") va = va.toLowerCase();
    if (typeof vb === "string") vb = vb.toLowerCase();
    if (va < vb) return -1 * dir;
    if (va > vb) return 1 * dir;
    return 0;
  });
}

function renderError(msg) {
  const tbody = document.getElementById("list-body");
  if (tbody) tbody.innerHTML = "";
  const tr = document.createElement("tr");
  const td = document.createElement("td");
  td.colSpan = 8;
  td.className = "table-empty";
  td.style.color = "#fca5a5";
  td.textContent = msg;
  tr.appendChild(td);
  if (tbody) tbody.appendChild(tr);
  document.getElementById("page-info").textContent = "第 0 / 0 页（共 0 条）";
  document.getElementById("prev-page").disabled = true;
  document.getElementById("next-page").disabled = true;
}

function renderPager() {
  document.getElementById("page-info").textContent = `第 ${state.page} / ${state.totalPages} 页（共 ${state.total} 条）`;
  document.getElementById("prev-page").disabled = state.page <= 1;
  document.getElementById("next-page").disabled = state.page >= state.totalPages;
}

function renderList(cards) {
  const tbody = document.getElementById("list-body");
  tbody.innerHTML = "";

  if (!cards.length) {
    const tr = document.createElement("tr");
    const td = document.createElement("td");
    td.colSpan = 8;
    td.className = "table-empty";
    td.textContent = "当前条件下没有结果";
    tr.appendChild(td);
    tbody.appendChild(tr);
    return;
  }

  for (const c of cards) {
    const tr = document.createElement("tr");

    const aveTd = document.createElement("td");
    aveTd.textContent = c.ave_id;

    const cveTd = document.createElement("td");
    cveTd.className = "table-cve";
    cveTd.textContent = c.cve_id || "无";

    const titleTd = document.createElement("td");
    titleTd.className = "table-title";
    titleTd.title = c.title || "";
    titleTd.textContent = c.title || c.cve_id || c.ave_id;

    const sevTd = document.createElement("td");
    const sev = document.createElement("span");
    sev.className = `severity ${sevClass(c.severity)}`;
    sev.textContent = c.severity;
    sevTd.appendChild(sev);

    const scoreTd = document.createElement("td");
    scoreTd.textContent = String(c.score ?? 0);

    const pocTd = document.createElement("td");
    const pocFlag = document.createElement("span");
    pocFlag.className = "flag";
    pocFlag.textContent = c.has_poc ? "有" : "无";
    if (c.has_poc) pocFlag.classList.add("yes");
    pocTd.appendChild(pocFlag);

    const expTd = document.createElement("td");
    const expFlag = document.createElement("span");
    expFlag.className = "flag";
    expFlag.textContent = c.has_exp ? "有" : "无";
    if (c.has_exp) expFlag.classList.add("yes");
    expTd.appendChild(expFlag);

    const actionTd = document.createElement("td");
    actionTd.className = "table-action";
    const detailLink = document.createElement("a");
    detailLink.className = "detail-link";
    detailLink.href = `detail.html?file=${encodeURIComponent(c.file_name)}`;
    detailLink.target = "_blank";
    detailLink.rel = "noopener noreferrer";
    detailLink.textContent = "查看详情";
    actionTd.appendChild(detailLink);

    tr.append(aveTd, cveTd, titleTd, sevTd, scoreTd, pocTd, expTd, actionTd);
    tbody.appendChild(tr);
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
  if (state.treeCacheFailed) return [];

  try {
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
  } catch (e) {
    state.treeCacheFailed = true;
    throw e;
  }
}

async function searchViaTreeFallback(keyword, page) {
  if (state.treeCacheFailed) {
    throw new Error("GitHub API 速率限制已达，无法获取列表数据。请稍后再试。");
  }
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
  // Try code search first; fall back to local tree filtering
  let lastErr = null;
  try {
    return await searchViaCodeApi(keyword, page);
  } catch (e) {
    lastErr = e;
  }
  // If code search fails, try tree fallback
  try {
    return await searchViaTreeFallback(keyword, page);
  } catch (e2) {
    // Both failed — throw the more informative error
    throw lastErr && lastErr.message.includes("API 速率限制")
      ? lastErr
      : e2;
  }
}

async function runPage(page) {
  const token = ++loadToken;
  state.page = Math.max(1, page);
  state.loaded = false;
  showLoading(true);
  setStatus("正在调用 GitHub API 搜索...");

  let rawList, assetIndex;
  try {
    rawList = await fetchListPage(state.keyword, state.page);
    if (token !== loadToken) return;
    assetIndex = await ensureAssetIndex();
    if (token !== loadToken) return;
  } catch (e) {
    showLoading(false);
    renderError(`⚠ ${e.message}`);
    setStatus(`搜索失败：${e.message}`);
    return;
  }

  const cards = [];
  for (const item of rawList) {
    let text;
    try {
      text = await fetchText(item);
    } catch {
      continue;
    }
    cards.push(toCard(item, text, assetIndex));
  }
  if (token !== loadToken) return;

  // Severity filtering is always done client-side (GitHub code search cannot filter by TOML content)
  state.lastCards = sortCards(cards);
  const finalCards = filterBySeverity(state.lastCards);
  state.loaded = true;
  renderList(finalCards);
  renderPager();
  updateSortIndicators();
  saveUrlState();
  showLoading(false);
  setStatus(`已显示第 ${state.page} 页（共 ${state.total} 条），当前模式：${state.mode === "search" ? "Code Search" : "Tree Fallback"}。`);
}

function debounce(fn, wait) {
  let timer = null;
  return (...args) => {
    if (timer) clearTimeout(timer);
    timer = setTimeout(() => fn(...args), wait);
  };
}

async function boot() {
  // ── Restore URL state ──
  const urlState = restoreUrlState();
  state.keyword = urlState.keyword;
  state.severity = urlState.severity;

  setStatus("等待加载");

  const searchInput = document.getElementById("search");
  const severityInput = document.getElementById("severity");
  const loadFirst = document.getElementById("load-first");
  const searchBtn = document.getElementById("search-btn");
  const intro = document.getElementById("project-intro");
  const prev = document.getElementById("prev-page");
  const next = document.getElementById("next-page");

  // Restore input values from URL
  if (urlState.keyword) searchInput.value = urlState.keyword;
  if (urlState.severity) severityInput.value = urlState.severity;

  const rerun = debounce(() => {
    state.keyword = searchInput.value || "";
    state.severity = severityInput.value || "";
    runPage(1).then(() => {
      if (intro) intro.style.display = "none";
    });
  }, 300);

  searchBtn.addEventListener("click", rerun);
  loadFirst.addEventListener("click", () => {
    if (state.loaded) {
      setStatus("列表已加载，可直接搜索或翻页。");
      return;
    }
    state.keyword = "";
    state.severity = "";
    searchInput.value = "";
    severityInput.value = "";
    runPage(1).then(() => {
      if (intro) intro.style.display = "none";
    });
  });
  searchInput.addEventListener("keydown", (e) => {
    if (e.key === "Enter") rerun();
  });

  // ── Severity triggers new search (not just local filter) ──
  severityInput.addEventListener("change", () => {
    if (!state.loaded) {
      setStatus("尚未加载列表，请先点击“开始加载”或“搜索”。");
      return;
    }
    rerun();
  });

  // ── Sort on header click ──
  document.querySelectorAll("[data-sort-key]").forEach((th) => {
    th.addEventListener("click", () => {
      const key = th.dataset.sortKey;
      if (state.sortKey === key) {
        state.sortDir = state.sortDir === "asc" ? "desc" : "asc";
      } else {
        state.sortKey = key;
        state.sortDir = "asc";
      }
      updateSortIndicators();
      if (state.loaded && state.lastCards.length) {
        state.lastCards = sortCards(state.lastCards);
        renderList(filterBySeverity(state.lastCards));
      }
    });
  });

  prev.addEventListener("click", () => {
    if (!state.loaded) {
      setStatus("尚未加载列表，请先点击“开始加载”。");
      return;
    }
    runPage(state.page - 1);
  });
  next.addEventListener("click", () => {
    if (!state.loaded) {
      setStatus("尚未加载列表，请先点击“开始加载”。");
      return;
    }
    runPage(state.page + 1);
  });
  renderPager();
  updateSortIndicators();

  // ── Auto-load if URL has search params ──
  if (urlState.keyword || urlState.severity) {
    runPage(urlState.page).then(() => {
      if (intro) intro.style.display = "none";
    });
  }
}

boot();
