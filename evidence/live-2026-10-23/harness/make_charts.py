"""Regenerate benchmarks.csv and benchmarks.svg from rog/ and box/ report.json files."""

import csv
import json
import math
from pathlib import Path

here = Path(__file__).resolve().parent.parent
R = json.loads((here / "rog/report.json").read_text())
B = json.loads((here / "box/report.json").read_text())
P = json.loads((here / "rog/report-pegasus.json").read_text())["mcp"]["live_pegasus"]


def g(d, *ks):
    for k in ks:
        d = d[k]
    return d


rows = [
    ("MCP connect + initialize", "ms", ("mcp", "connect_initialize_ms")),
    ("MCP list_tools", "ms", ("mcp", "list_tools_ms")),
    ("MCP tool round-trip p50 (n=200)", "ms", ("mcp", "roundtrip_harnesses_ms", "p50")),
    ("MCP tool round-trip p95 (n=200)", "ms", ("mcp", "roundtrip_harnesses_ms", "p95")),
    ("Mock lifecycle total p50 (n=20)", "ms", ("mcp", "mock_lifecycle_ms", "total", "p50")),
    ("Mock prompt end-to-end p50", "ms", ("mcp", "mock_lifecycle_ms", "prompt_e2e", "p50")),
    ("Ledger append per receipt (5000)", "ms", ("ledger", "append_per_receipt_ms")),
    ("Ledger verify throughput", "receipts/s", ("ledger", "verify_receipts_per_s")),
    ("Peer signed hello in-process p50 (n=40)", "ms", ("peer", "signed_hello_inproc_ms", "p50")),
    ("Peer signed ping via CLI p50 (n=10)", "ms", ("peer", "signed_ping_cli_ms", "p50")),
    ("Peer delegated task via CLI p50 (n=5)", "ms", ("peer", "delegated_task_cli_ms", "p50")),
]
with open(here / "benchmarks.csv", "w", newline="") as f:
    w = csv.writer(f, lineterminator="\n")
    w.writerow(["metric", "unit", "rog_windows", "box_linux"])
    for n, u, k in rows:
        w.writerow([n, u, g(R, *k), g(B, *k)])
    w.writerow(
        [
            "Codex real turn via Interlink (prompt end-to-end)",
            "ms",
            R["mcp"]["live_codex"]["prompt_e2e_ms"],
            "",
        ]
    )
    w.writerow(["Codex as MCP client, 5-tool session wall", "ms", R["codex_client"]["wall_ms"], ""])
    w.writerow(["PEGASUS host launch (disposable copy)", "ms", P["launch_ms"], ""])
    w.writerow(["PEGASUS host stop", "ms", P["stop_ms"], ""])
chart = [r for r in rows if r[1] == "ms" and "p95" not in r[0]]
W, H0, rowh = 860, 70, 44
H = H0 + rowh * len(chart) + 50
x0, lo, hi = 330, -2, 4
span = W - x0 - 80


def X(v):
    return x0 + span * (math.log10(max(v, 10**lo)) - lo) / (hi - lo)


o = [
    f'<svg xmlns="http://www.w3.org/2000/svg" width="{W}" height="{H}" viewBox="0 0 {W} {H}" font-family="Segoe UI,Helvetica,Arial,sans-serif" font-size="13">',
    f'<rect width="{W}" height="{H}" fill="#ffffff"/>',
    '<text x="20" y="30" font-size="17" font-weight="600" fill="#111">Interlink live benchmarks, 2026-10-23 (median, lower is better, log scale)</text>',
    '<rect x="20" y="44" width="12" height="12" fill="#6d28d9"/><text x="38" y="55" fill="#333">Windows 11 laptop (Ryzen AI MAX+ 395, OneDrive-synced folder)</text>',
    '<rect x="470" y="44" width="12" height="12" fill="#0d9488"/><text x="488" y="55" fill="#333">Linux box (8-vCPU Xeon)</text>',
]
labels = {-2: "0.01 ms", -1: "0.1 ms", 0: "1 ms", 1: "10 ms", 2: "100 ms", 3: "1 s", 4: "10 s"}
for t in range(lo, hi + 1):
    x = X(10**t)
    o.append(f'<line x1="{x:.1f}" y1="{H0}" x2="{x:.1f}" y2="{H - 40}" stroke="#e5e7eb"/>')
    o.append(f'<text x="{x:.1f}" y="{H - 24}" text-anchor="middle" fill="#666">{labels[t]}</text>')
for i, (n, _u, k) in enumerate(chart):
    y = H0 + i * rowh + 6
    o.append(f'<text x="{x0 - 10}" y="{y + 20}" text-anchor="end" fill="#222">{n}</text>')
    for j, (d, c) in enumerate(((R, "#6d28d9"), (B, "#0d9488"))):
        v = g(d, *k)
        yy = y + j * 17
        o.append(f'<rect x="{x0}" y="{yy}" width="{X(v) - x0:.1f}" height="14" fill="{c}" rx="2"/>')
        o.append(
            f'<text x="{X(v) + 5:.1f}" y="{yy + 11}" fill="#333" font-size="11">{v:g} ms</text>'
        )
o.append("</svg>")
(here / "benchmarks.svg").write_text("\n".join(o) + "\n")
