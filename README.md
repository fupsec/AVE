# AVE 公开仓库

该目录用于独立公开的 GitHub 仓库，并通过 GitHub Pages 提供展示。

## 公开内容

- 漏洞详情（`vulns/*.toml`）
- PoC 文件（`pocs/`）
- EXP 文件（`exploits/`）
- 页面静态资源（`index.html`、`assets/`）

## 不公开内容

- 内部爬虫与处理逻辑源码
- 内部基础设施与私有自动化实现

## 搜索架构

- 页面直接使用 GitHub Search API 与 Repository API 检索。
- 每次 push 后由 GitHub Actions 自动重新部署页面。

## 初始化独立仓库

```bash
cd output
git init -b main
git add .
git commit -m "初始化 AVE 公开仓库"
```

然后添加远程仓库并推送。

## GitHub Pages

- 通过 `.github/workflows/pages.yml` 自动部署。
- push 到 `main` 分支会触发构建与发布。

站点入口为 `index.html`。
