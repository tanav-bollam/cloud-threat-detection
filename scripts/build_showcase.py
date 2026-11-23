"""Build a static showcase site (site/) from the generated reports: headline numbers, charts, screenshots and the rendered docs.

  python scripts/build_showcase.py            # -> site/index.html (+ site/docs/*.html, site/img/*.png)
Pure static files: host anywhere (GitHub Pages workflow included). Every number comes from reports/*.json; nothing is typed here.
Plotly is loaded from its public CDN; no server and no Streamlit are involved.
"""
from __future__ import annotations

import html
import json
import shutil
import sys
from datetime import datetime, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import markdown
import plotly.graph_objects as go

ROOT = Path(__file__).resolve().parents[1]
SITE = ROOT / "site"
BG, SURFACE, INK, INK2, MUTED, GRID = "#1a1a19", "#242423", "#f0efec", "#c3c2b7", "#8c8b84", "#2f2f2d"
BLUE, ORANGE, AQUA, YELLOW = "#3987e5", "#d95926", "#199e70", "#c98500"
LAYERS = {"rules_only": ("Rules", BLUE), "anomaly_only": ("IsolationForest", ORANGE), "ip_only": ("IP layer", AQUA), "combined": ("Combined", YELLOW)}

CSS = f"""
:root {{ color-scheme: dark; }}
* {{ box-sizing: border-box; }}
body {{ margin:0; background:{BG}; color:{INK}; font:16px/1.6 -apple-system,Segoe UI,Roboto,Helvetica,Arial,sans-serif; }}
a {{ color:#6da7ec; }}
header, main, footer {{ max-width: 1080px; margin: 0 auto; padding: 0 20px; }}
header {{ padding-top: 48px; }}
h1 {{ font-size: 2.1rem; margin: 0 0 6px; }} h2 {{ margin-top: 48px; border-bottom: 1px solid {GRID}; padding-bottom: 8px; }}
.sub {{ color:{INK2}; max-width: 760px; }}
.cards {{ display:grid; grid-template-columns: repeat(auto-fit,minmax(200px,1fr)); gap:14px; margin:24px 0; }}
.card {{ background:{SURFACE}; border:1px solid {GRID}; border-radius:10px; padding:14px 16px; }}
.card .v {{ font-size: 1.9rem; font-weight: 650; }} .card .l {{ color:{INK2}; font-size:.9rem; }} .card .n {{ color:{MUTED}; font-size:.8rem; margin-top:4px; }}
.note {{ background:#2b2517; border:1px solid #5a4a1c; border-radius:8px; padding:10px 14px; color:{INK}; }}
table {{ border-collapse: collapse; width:100%; font-size:.92rem; }} th,td {{ border-bottom:1px solid {GRID}; padding:6px 10px; text-align:left; }}
th {{ color:{INK2}; }} td:nth-child(n+2) {{ font-variant-numeric: tabular-nums; }}
.shots {{ display:grid; grid-template-columns: repeat(auto-fit,minmax(320px,1fr)); gap:18px; }}
figure {{ margin:0; background:{SURFACE}; border:1px solid {GRID}; border-radius:10px; overflow:hidden; }}
figure img {{ width:100%; display:block; }} figcaption {{ padding:8px 12px; color:{INK2}; font-size:.88rem; }}
code {{ background:{SURFACE}; padding:1px 5px; border-radius:4px; }} pre {{ background:{SURFACE}; padding:12px; border-radius:8px; overflow:auto; }}
.doc {{ max-width: 980px; margin: 0 auto; padding: 24px 20px 80px; }} .doc table {{ display:block; overflow-x:auto; }}
footer {{ color:{MUTED}; font-size:.85rem; padding: 40px 20px; }}
"""


def load(name):
    p = ROOT / "reports" / name
    return json.loads(p.read_text(encoding="utf-8")) if p.exists() else None


def style(fig, height=340):
    fig.update_layout(height=height, paper_bgcolor="rgba(0,0,0,0)", plot_bgcolor="rgba(0,0,0,0)", font=dict(color=INK2), margin=dict(l=10, r=10, t=30, b=10),
                      legend=dict(orientation="h", y=1.12, x=0), hoverlabel=dict(bgcolor=SURFACE, font_color=INK))
    fig.update_xaxes(gridcolor=GRID, zeroline=False, linecolor=GRID)
    fig.update_yaxes(gridcolor=GRID, zeroline=False, linecolor=GRID)
    return fig


def fragment(fig, first=[True]) -> str:
    out = fig.to_html(full_html=False, include_plotlyjs="cdn" if first[0] else False, config={"displayModeBar": False})
    first[0] = False
    return out


def card(value, label, note=""):
    return f'<div class="card"><div class="v">{html.escape(str(value))}</div><div class="l">{html.escape(label)}</div><div class="n">{html.escape(note)}</div></div>'


def page(title, body, extra_head=""):
    return (f'<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">'
            f'<title>{html.escape(title)}</title><style>{CSS}</style>{extra_head}</head><body>{body}</body></html>')


def main() -> None:
    g, rob, real, live = load("metrics.json"), load("robustness.json"), load("real_data.json"), load("live_ttd.json")
    if not g:
        sys.exit("reports/metrics.json missing: run scripts/evaluate.py first")
    if SITE.exists():
        shutil.rmtree(SITE)
    (SITE / "img").mkdir(parents=True)
    (SITE / "docs").mkdir()
    shots = sorted((ROOT / "docs" / "screenshots").glob("*.png"))
    for f in shots:
        shutil.copyfile(f, SITE / "img" / f.name)
    # ---- docs rendered to HTML
    nav = '<p><a href="../index.html">← Back to the overview</a></p>'
    for name in ("RESULTS", "DETECTIONS", "REAL_DATA_FINDINGS"):
        src = ROOT / "docs" / f"{name}.md"
        if src.exists():
            body = markdown.markdown(src.read_text(encoding="utf-8"), extensions=["tables", "fenced_code"])
            (SITE / "docs" / f"{name}.html").write_text(page(name.replace("_", " ").title(), f'<div class="doc">{nav}{body}</div>'), encoding="utf-8")

    C = g["layers"]["combined"]
    cards = [card(f"{C['test_week']['injection_recall']*100:.0f}%", "attack stages detected", f"synthetic held-out week, {g['injections']} injected stages"),
             card(C["benign_week"]["fp_incidents_per_day"], "false-positive incidents / day", f"benign week; {C['benign_week']['fp_high_or_critical_per_day']} HIGH+ per day"),
             card(f"{C['ttd_p50_s']:.0f} / {C['ttd_p95_s']:.0f} s", "time to detect p50 / p95", "simulated seconds"),
             card(f"{C['test_week']['chains_in_single_incident']}/{C['test_week']['chains']}", "kill chains in one incident", "S1→S5 chains grouped")]
    if rob:
        last = str(rob["levels"][-1])
        cards.append(card(f"{rob['results'][last]['combined']['incident_recall']*100:.0f}%", "recall vs a stealthy attacker", f"stealth {last}: victim's UA, region, hours"))
    st = (real or {}).get("stratus")
    if st and st["before"]:
        cards.append(card(f"{st['before']['covered_specific']}/{st['before']['techniques']}", "REAL Stratus techniques covered", "original 24 rules, held-out (the honest number)"))
        cards.append(card(f"{st['after']['covered_specific']}/{st['after']['techniques']}", "after adding rules (post-hoc)", "written after reading those samples"))
    if live:
        cards.append(card(f"{live['pipeline_latency_p50_ms']:.0f} ms", "event → alert, median", f"live pipeline, {live['detected']}/{live['injections']} detected"))

    charts = []
    sc = sorted(C["per_scenario"])
    f1 = go.Figure()
    for key, (nm, col) in LAYERS.items():
        f1.add_trace(go.Bar(x=sc, y=[g["layers"][key]["test_week"]["recall_by_scenario"].get(s, 0) * 100 for s in sc], name=nm, marker_color=col))
    f1.update_layout(barmode="group", yaxis_title="incident recall (%)")
    charts.append(("Which layer catches what (synthetic held-out week)", fragment(style(f1)),
                   "Rules, the IsolationForest and the IP layer fail on different scenarios; combined they cover all nine. Rules alone miss impossible travel (S9) entirely."))
    if rob:
        f2 = go.Figure()
        for key, (nm, col) in LAYERS.items():
            f2.add_trace(go.Scatter(x=rob["levels"], y=[rob["results"][str(x)][key]["incident_recall"] * 100 for x in rob["levels"]], mode="lines+markers", name=nm,
                                    line=dict(color=col, width=2), marker=dict(size=9, color=col, line=dict(color=BG, width=2))))
        f2.update_layout(yaxis_title="incident recall (%)", xaxis_title="attacker stealth (0 = noisy, 0.9 = blends in)")
        f2.update_yaxes(range=[0, 105])
        charts.append(("Recall as the attacker blends in", fragment(style(f2)),
                       "Each level adds to the previous: the victim's user agent, then their region and a same-country IP, then business hours. Detection by <em>where</em> an attacker connects erodes; "
                       "detection by <em>what</em> they do holds up better."))
    if st and st["before"]:
        f3 = go.Figure(go.Bar(x=[f"Original {st['before']['rules_evaluated']} rules<br>(held-out)", f"{st['after']['rules_evaluated']} rules<br>(post-hoc)"],
                              y=[st["before"]["covered_specific"], st["after"]["covered_specific"]], marker_color=[BLUE, "#6a6a66"],
                              text=[f"{st['before']['covered_specific']}/{st['before']['techniques']}", f"{st['after']['covered_specific']}/{st['after']['techniques']}"], textposition="outside"))
        f3.update_layout(yaxis_title="real Stratus techniques covered", showlegend=False)
        f3.update_yaxes(range=[0, st["before"]["techniques"] + 3])
        charts.append(("Real data: Stratus Red Team technique coverage", fragment(style(f3, 320)),
                       "The synthetic evaluation said 100%. On real captures of 35 techniques the original rules covered about a third. The right-hand bar is post-hoc: those rules were written after reading these samples."))
    chart_html = "".join(f"<h3>{t}</h3>{c}<p class='sub'>{d}</p>" for t, c, d in charts)

    caps = {"overview": "Overview: live KPIs, alert markers on the event stream, top risky identities", "investigation": "Incident investigation: timeline, MITRE chain, why each alert fired, report export",
            "simulator": "Attack simulator: inject a labeled attack, compare with what was detected", "incidents": "Alerts and incidents queue with triage actions", "forensics": "Forensics search with pivots and read-only SQL",
            "quality": "Detection quality: ablations, per-scenario results", "robustness": "Stealth robustness study", "real_data": "Real data: flaws.cloud and Stratus validation", "settings": "Settings: rules, deduplication, sensitivity, webhook"}
    figs = "".join(f'<figure><a href="img/{f.name}"><img src="img/{f.name}" alt="{html.escape(caps.get(f.stem, f.stem))}" loading="lazy"></a><figcaption>{html.escape(caps.get(f.stem, f.stem))}</figcaption></figure>' for f in shots)
    now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    body = f"""
<header><h1>Cloud Threat Detection</h1>
<p class="sub">Defensive monitoring of AWS CloudTrail: synthetic attack generation, a rules engine, an IsolationForest behavioural layer and an IP/access-pattern layer, grouped into incidents with MITRE tactics and an analyst dashboard. Free and open source; no AWS account required.</p></header>
<main>
<div class="cards">{''.join(cards)}</div>
<p class="note"><strong>Read the caveats.</strong> The headline synthetic numbers are optimistic: the detectors and the data generator share an author. Real-data checks (flaws.cloud, Stratus Red Team samples) are reported honestly alongside them, including where the project fell short.</p>
<h2>Results</h2>{chart_html}
<p><a href="docs/RESULTS.html">Full results</a> · <a href="docs/REAL_DATA_FINDINGS.html">Real-data findings</a> · <a href="docs/DETECTIONS.html">Detection catalogue</a></p>
<h2>The dashboard</h2><div class="shots">{figs}</div>
<h2>Run it yourself</h2>
<pre><code>docker compose up      # then open http://localhost:8501  (offline demo, no AWS account)</code></pre>
</main>
<footer>Static page generated {now} from the project's measured reports. Charts use Plotly from its public CDN.</footer>"""
    (SITE / "index.html").write_text(page("Cloud Threat Detection", body), encoding="utf-8")
    (SITE / ".nojekyll").write_text("", encoding="utf-8")
    size = sum(f.stat().st_size for f in SITE.rglob("*") if f.is_file())
    print(f"site/ built: {len(list(SITE.rglob('*.html')))} pages, {len(shots)} screenshots, {size/1e6:.1f} MB")


if __name__ == "__main__":
    main()
