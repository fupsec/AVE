const GH = {
  owner: "adysec",
  repo: "AVE",
  branch: "main",
};

const PAGE_SIZE = 10;

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

async function fetchTomlList() {
  return searchTomlList("");
}

async function searchTomlList(keyword) {
  let q = `repo:${GH.owner}/${GH.repo} path:vulns extension:toml`;
  if (keyword && keyword.trim()) {
    q += ` ${keyword.trim()}`;
  }
  try {
    const data = await gh(`https://api.github.com/search/code?q=${enc(q)}&per_page=${PAGE_SIZE}`);
    return data.items || [];
  } catch (e) {
    // Anonymous Code Search may return 401/403. Fallback to tree listing.
    const tree = await gh(`https://api.github.com/repos/${GH.owner}/${GH.repo}/git/trees/${GH.branch || "main"}?recursive=1`);
    const all = (tree.tree || [])
      .filter((n) => n.type === "blob")
      .filter((n) => n.path && n.path.startsWith("vulns/") && n.path.endsWith(".toml"))
      .map((n) => {
        const name = n.path.split("/").pop();
        const stem = name.replace(/\.toml$/i, "");
        return {
          name,
          path: n.path,
          html_url: `https://github.com/${GH.owner}/${GH.repo}/blob/main/${n.path}`,
          download_url: `https://raw.githubusercontent.com/${GH.owner}/${GH.repo}/main/${n.path}`,
          stem,
        };
      });

    const kw = (keyword || "").trim().toLowerCase();
    const filtered = kw
      ? all.filter((i) => i.name.toLowerCase().includes(kw) || i.stem.toLowerCase().includes(kw))
      : all;

    filtered.sort((a, b) => a.name.localeCompare(b.name));
    return filtered.slice(0, PAGE_SIZE);
  }
}

async function fetchText(item) {
  return (await fetch(item.download_url, { cache: "no-cache" })).text();
}

function toCard(item, text) {
  const ave = item.name.replace(/\.toml$/i, "");
  const cve = (text.match(/^cve_id\s*=\s*"([^"]+)"/m)?.[1]) || "无";
  return {
    ave_id: ave,
    cve_id: cve,
    title: titleFromToml(text, ave),
    description: descFromToml(text),
    severity: severityFromToml(text),
    score: scoreFromToml(text),
    references: linksFromToml(text, "urls"),
    poc_urls: linksFromToml(text, "poc_urls"),
    exp_urls: linksFromToml(text, "exp_urls"),
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

function filtered(cards) {
  const kw = document.getElementById("search").value.trim().toLowerCase();
  const sev = document.getElementById("severity").value;
  return cards.filter((c) => {
    if (sev && c.severity !== sev) return false;
    if (!kw) return true;
    const hay = `${c.ave_id} ${c.cve_id} ${c.title} ${c.description}`.toLowerCase();
    return hay.includes(kw);
  });
}

function debounce(fn, wait) {
  let timer = null;
  return (...args) => {
    if (timer) clearTimeout(timer);
    timer = setTimeout(() => fn(...args), wait);
  };
}

async function runRemoteSearch(keyword) {
  const severity = document.getElementById("severity").value;
  setStatus("正在调用 GitHub API 搜索...");
  const rawList = await searchTomlList(keyword);
  const cards = [];
  for (const item of rawList) {
    const text = await fetchText(item);
    cards.push(toCard(item, text));
  }

  cards.sort((a, b) => a.ave_id.localeCompare(b.ave_id));
  const finalCards = severity ? cards.filter((c) => c.severity === severity) : cards;
  renderList(finalCards);
  setStatus(`已显示 ${finalCards.length} 条（GitHub API 返回最多 ${PAGE_SIZE} 条）。`);
}

async function boot() {
  setStatus("正在加载首批漏洞数据...");
  try {
    const rawList = await fetchTomlList();
    setStatus(`正在解析首批 ${rawList.length} 条漏洞...`);

    const cards = [];
    for (const item of rawList) {
      const text = await fetchText(item);
      cards.push(toCard(item, text));
    }

    cards.sort((a, b) => a.ave_id.localeCompare(b.ave_id));
    renderList(cards);
    setStatus(`已默认显示 ${cards.length} 条漏洞。输入关键词将实时调用 GitHub API 搜索。`);

    const searchInput = document.getElementById("search");
    const severityInput = document.getElementById("severity");
    const onSearch = debounce(() => {
      runRemoteSearch(searchInput.value).catch((e) => setStatus(`搜索失败：${e.message}`));
    }, 450);

    searchInput.addEventListener("input", onSearch);
    severityInput.addEventListener("change", onSearch);
  } catch (e) {
    setStatus(`加载失败：${e.message}`);
  }
}

boot();
