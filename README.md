# AVE 多源漏洞聚合引擎

> **AVE** 的多重含义：

| 含义 | 中文 | 说明 |
|------|------|------|
| AdySec Vulnerability Exposures | AdySec 漏洞披露 | 项目归属 |
| AI-powered Vulnerability Engine | AI 驱动漏洞引擎 | 核心方法 |
| Automated Vulnerability Extractor | 全自动漏洞提取 | 无人值守 |

Description: AVE 是面向安全运营的多源漏洞知识库，统一 AVE 编号并输出结构化 TOML，同时整理和校验公开 PoC/EXP 资产，支持按严重等级快速筛选高价值漏洞。漏洞爬取与梳理的代码和逻辑暂未开源。

该目录用于独立公开的 GitHub 仓库，并通过 GitHub Pages 提供展示。

## 公开内容

- 漏洞详情（`vulns/*.toml`）
- PoC 文件（`pocs/`）
- EXP 文件（`exploits/`）
- 页面静态资源（`index.html`、`assets/`）

## 不公开内容

- 漏洞爬取与梳理的核心代码与处理逻辑（暂未开源）
- 内部基础设施与私有自动化实现

## 搜索架构

- 页面直接使用 GitHub Search API 与 Repository API 检索。
- 默认直访页面不自动检索；用户点击“开始加载”或“搜索”后才请求 API，以节约配额。
- 首次访问会优先展示项目说明，加载后自动切换到结果视图。
- 每次 push 后由 GitHub Actions 自动重新部署页面。
- 漏洞详情页由浏览器端 HTML/JS 直接拉取并解析 `vulns/*.toml` 渲染。

## GitHub Pages

- 通过 `.github/workflows/pages.yml` 自动部署。
- push 到 `main` 分支会触发构建与发布。

站点入口为 `index.html`。
