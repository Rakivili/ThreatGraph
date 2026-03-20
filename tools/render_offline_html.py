#!/usr/bin/env python3
from __future__ import annotations

import argparse
import html
import json
from pathlib import Path
from typing import Any


def read_jsonl(path: Path) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    if not path.exists():
        return rows
    for line in path.read_text(encoding="utf-8", errors="ignore").splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            v = json.loads(line)
        except Exception:
            continue
        if isinstance(v, dict):
            rows.append(v)
    return rows


def score_key(incident: dict[str, Any]) -> tuple[float, int]:
    risk = incident.get("risk_product", 0)
    seq = incident.get("sequence_length", 0)
    try:
        risk_val = float(risk)
    except Exception:
        risk_val = 0.0
    try:
        seq_val = int(seq)
    except Exception:
        seq_val = 0
    return (risk_val, seq_val)


def esc(v: Any) -> str:
    return html.escape(str(v))


def build_html(title: str, incidents: list[dict[str, Any]], tactical: list[dict[str, Any]]) -> str:
    incidents = sorted(incidents, key=score_key, reverse=True)
    tactical_by_key = {
        f"{str(row.get('host', ''))}|{str(row.get('root', ''))}": row for row in tactical
    }

    rows_html: list[str] = []
    for i, inc in enumerate(incidents, start=1):
        host = str(inc.get("host", ""))
        root = str(inc.get("root", ""))
        key = f"{host}|{root}"
        t = tactical_by_key.get(key, {})
        score = t.get("score", {}) if isinstance(t, dict) else {}
        best = score.get("best_vertex_record_ids", []) if isinstance(score, dict) else []
        if not isinstance(best, list):
            best = []

        rows_html.append(
            "<tr>"
            f"<td>{i}</td>"
            f"<td>{esc(host)}</td>"
            f"<td>{esc(inc.get('severity', 'unknown'))}</td>"
            f"<td>{esc(inc.get('sequence_length', 0))}</td>"
            f"<td>{esc(inc.get('alert_count', 0))}</td>"
            f"<td>{esc(inc.get('risk_product', 0))}</td>"
            f"<td><code>{esc(root)}</code></td>"
            f"<td>{esc(', '.join(str(x) for x in best[:6]))}</td>"
            "</tr>"
        )

    if not rows_html:
        rows_html.append("<tr><td colspan='8'>No incidents found.</td></tr>")

    return f"""<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1" />
  <title>{esc(title)}</title>
  <style>
    body {{ font-family: -apple-system, BlinkMacSystemFont, Segoe UI, sans-serif; margin: 24px; color: #0f172a; }}
    h1 {{ margin: 0 0 8px 0; }}
    .muted {{ color: #475569; margin-bottom: 20px; }}
    table {{ width: 100%; border-collapse: collapse; }}
    th, td {{ border-bottom: 1px solid #cbd5e1; text-align: left; padding: 8px; font-size: 13px; vertical-align: top; }}
    th {{ background: #f8fafc; }}
    code {{ font-family: ui-monospace, SFMono-Regular, Menlo, monospace; }}
  </style>
</head>
<body>
  <h1>{esc(title)}</h1>
  <div class="muted">incidents={len(incidents)} tactical_rows={len(tactical)}</div>
  <table>
    <thead>
      <tr>
        <th>#</th><th>Host</th><th>Severity</th><th>Seq</th><th>Alerts</th><th>Risk</th><th>Root</th><th>Best Path (top 6)</th>
      </tr>
    </thead>
    <tbody>
      {"".join(rows_html)}
    </tbody>
  </table>
</body>
</html>
"""


def main() -> int:
    p = argparse.ArgumentParser(description="Render a simple offline HTML report from incident/tactical JSONL outputs.")
    p.add_argument("--incidents", required=True, help="Incidents JSONL path")
    p.add_argument("--tactical", required=True, help="Scored TPG JSONL path")
    p.add_argument("--out", required=True, help="Output HTML file path")
    p.add_argument("--title", default="ThreatGraph Offline Report", help="Report title")
    args = p.parse_args()

    incidents = read_jsonl(Path(args.incidents))
    tactical = read_jsonl(Path(args.tactical))

    out = Path(args.out)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(build_html(args.title, incidents, tactical), encoding="utf-8")
    print(f"offline_report_ok out={out} incidents={len(incidents)} tactical={len(tactical)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
