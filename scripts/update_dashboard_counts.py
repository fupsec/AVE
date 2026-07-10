#!/usr/bin/env python3
from __future__ import annotations

from pathlib import Path
from datetime import datetime, timezone
import re

ROOT = Path(__file__).resolve().parents[1]
INDEX = ROOT / "index.html"


def count_files(folder: str, pattern: str = "*") -> int:
    base = ROOT / folder
    if not base.exists():
        return 0
    return sum(1 for p in base.rglob(pattern) if p.is_file())


def replace_metric(html: str, metric_id: str, value: str) -> str:
    pattern = rf'(<p id="{re.escape(metric_id)}">)(.*?)(</p>)'
    def _repl(m: re.Match[str]) -> str:
        return f"{m.group(1)}{value}{m.group(3)}"

    updated, n = re.subn(pattern, _repl, html, count=1, flags=re.S)
    if n != 1:
        raise RuntimeError(f"metric not found or duplicated: {metric_id}")
    return updated


def main() -> None:
    html = INDEX.read_text(encoding="utf-8")

    vulns = count_files("vulns", "*.toml")
    pocs = count_files("pocs")
    exps = count_files("exploits")
    push_time = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")

    html = replace_metric(html, "m-vulns", str(vulns))
    html = replace_metric(html, "m-pocs", str(pocs))
    html = replace_metric(html, "m-exps", str(exps))
    html = replace_metric(html, "m-push", push_time)

    INDEX.write_text(html, encoding="utf-8")
    print(f"dashboard updated: vulns={vulns}, pocs={pocs}, exps={exps}, push={push_time}")


if __name__ == "__main__":
    main()
