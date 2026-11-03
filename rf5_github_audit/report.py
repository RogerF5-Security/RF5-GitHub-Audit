"""Standalone reports: escaped API data, no external assets or telemetry."""

from datetime import datetime, timezone
from html import escape
import json
from pathlib import Path
import secrets


def render_html(report):
    nonce = secrets.token_hex(16)
    rows = []
    for repo in report["repositories"]:
        checks = repo.get("checks", {})
        dep = checks.get("dependency_alerts", {})
        count = str(sum(dep["value"].values())) if dep.get("status") == "checked" else "Sin comprobar"
        findings = "<br>".join(escape(f["message"]) for f in repo.get("findings", [])) or "Sin observaciones en controles comprobados"
        controls = "<br>".join(f"{escape(k)}: <strong>{escape(str(v))}</strong>" for k, v in repo.get("controls", {}).items())
        url = "https://github.com/" + repo["repository"]
        name = escape(repo["repository"])
        repository = name if repo["status"] == "skipped" else f'<a href="{escape(url, quote=True)}" target="_blank" rel="noopener noreferrer">{name}</a>'
        rows.append(f'<tr data-status="{escape(repo["status"], quote=True)}"><td>{repository}<p>{escape(repo.get("description", ""))}</p></td><td>{escape(repo["status"])}</td><td>{controls}</td><td>{count}</td><td>{findings}</td><td>{escape(str(repo.get("coverage", {}).get("unavailable", "—")))}</td></tr>')
    simulated = "DATOS SIMULADOS · DEMOSTRACIÓN SIN CONEXIÓN" if report.get("simulated") else "CONSULTAS DE LECTURA · GITHUB API"
    summary = report.get("summary", {})
    scope = report.get("scope", {})
    scope_note = f'<p class="note">Alcance limitado: se revisaron {len(report["repositories"])} de {escape(str(scope.get("discovered", "?")))} repositorios descubiertos.</p>' if scope.get("truncated") else ""
    stats = "".join(f'<div class="stat"><strong>{escape(str(summary.get(key, 0)))}</strong><span>{label}</span></div>' for key, label in [("checked", "Sin observaciones comprobadas"), ("attention", "Requieren atención"), ("partial", "Cobertura parcial"), ("unavailable", "No disponibles")])
    return f'''<!doctype html>
<html lang="es"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src 'unsafe-inline'; script-src 'nonce-{nonce}'; base-uri 'none'; form-action 'none'">
<title>RF5 GitHub Audit</title><style>
:root{{color-scheme:dark}}*{{box-sizing:border-box}}body{{margin:0;background:#081018;color:#edf5f3;font:15px/1.6 system-ui,sans-serif}}main{{max-width:1440px;margin:auto;padding:40px 24px}}.eyebrow{{color:#65e2c9;letter-spacing:.1em;font-weight:700;font-size:12px}}h1{{font-size:clamp(30px,5vw,54px);margin:12px 0}}h1 span{{color:#bff36b}}.intro,p{{color:#afbdc8}}.stats{{display:grid;grid-template-columns:repeat(auto-fit,minmax(180px,1fr));gap:14px;margin:30px 0}}.stat{{background:#10212d;border:1px solid #28434b;border-radius:12px;padding:20px}}.stat strong{{display:block;font-size:32px;color:#bff36b}}.stat span{{font-size:13px}}.filters{{display:flex;flex-wrap:wrap;gap:14px;margin:24px 0}}label{{display:grid;gap:6px;flex:1;min-width:190px}}input,select{{background:#10212d;color:inherit;border:1px solid #42606a;border-radius:8px;padding:12px}}.table-wrap{{overflow:auto;border:1px solid #28434b;border-radius:12px}}table{{width:100%;border-collapse:collapse;min-width:1000px}}th,td{{padding:16px;text-align:left;vertical-align:top;border-bottom:1px solid #28434b}}th{{background:#10212d}}a{{color:#77e4d1}}td p{{font-size:13px;max-width:300px;margin:8px 0}}.note{{background:#10212d;border-left:3px solid #65e2c9;padding:14px 18px}}footer{{margin-top:25px;font-size:13px;color:#afbdc8}}[hidden]{{display:none!important}}
</style></head><body><main><div class="eyebrow">{simulated}</div><h1>RF5 <span>GitHub Audit</span></h1><p class="intro">Inventario de controles, permisos de automatización y alertas de repositorios. Informe generado: {escape(report["generated_at"])}</p><div class="stats">{stats}</div>{scope_note}<p class="note">Una consulta no disponible queda marcada como cobertura parcial. Las alertas de dependencias no demuestran explotabilidad. El informe conserva cantidades de alertas de secretos, sin sus valores.</p><div class="filters"><label>Buscar repositorio<input id="search" type="search" placeholder="Nombre, descripción u observación"></label><label>Estado<select id="status"><option value="">Todos</option><option>attention</option><option>partial</option><option>checked</option><option>unavailable</option><option>skipped</option></select></label></div><p id="count" aria-live="polite"></p><div class="table-wrap"><table><thead><tr><th>Repositorio</th><th>Estado</th><th>Controles</th><th>Alertas de dependencias</th><th>Observaciones</th><th>Consultas no disponibles</th></tr></thead><tbody>{''.join(rows)}</tbody></table></div><footer>Roger Arana · Roger F5 · RF5 GitHub Audit {escape(report["version"])} · Reporte local sin recursos externos</footer></main><script nonce="{nonce}">
const search=document.getElementById('search'),status=document.getElementById('status'),rows=[...document.querySelectorAll('tbody tr')];function filter(){{let n=0;for(const row of rows){{row.hidden=!(row.textContent.toLowerCase().includes(search.value.toLowerCase())&&(!status.value||row.dataset.status===status.value));if(!row.hidden)n++;}}document.getElementById('count').textContent=`${{n}} de ${{rows.length}} repositorios`;}}search.addEventListener('input',filter);status.addEventListener('change',filter);filter();
</script></body></html>'''


def write_reports(report, directory):
    directory = Path(directory)
    directory.mkdir(parents=True, exist_ok=True)
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S%fZ")
    json_path, html_path = directory / f"audit-{stamp}.json", directory / f"audit-{stamp}.html"
    with json_path.open("x", encoding="utf-8") as stream:
        json.dump(report, stream, ensure_ascii=False, indent=2)
    with html_path.open("x", encoding="utf-8") as stream:
        stream.write(render_html(report))
    return json_path, html_path
