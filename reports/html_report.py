"""HTML report generator. Renders the same structured data as the
Markdown report into a styled standalone HTML page via Jinja2."""
from __future__ import annotations

from jinja2 import Environment, BaseLoader

from analyzers.timeline import build_timeline
from database.models import Confidence, Investigation

_TEMPLATE = """
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>OSINT Investigation Report {{ investigation.id }}</title>
<style>
  :root { color-scheme: light dark; }
  body { font-family: -apple-system, Segoe UI, Roboto, sans-serif; max-width: 900px; margin: 2rem auto; padding: 0 1rem; line-height: 1.5; }
  h1 { font-size: 1.4rem; }
  h2 { border-bottom: 2px solid #6669; padding-bottom: .25rem; margin-top: 2rem; }
  .finding { border: 1px solid #8884; border-radius: 8px; padding: .75rem 1rem; margin: .75rem 0; }
  .badge { display: inline-block; padding: .1rem .5rem; border-radius: 999px; font-size: .75rem; font-weight: 600; }
  .CONFIRMED { background: #1a7f37; color: white; }
  .SUPPORTED { background: #9a6700; color: white; }
  .POSSIBLE { background: #6e7781; color: white; }
  .UNVERIFIED { background: #a1a1a1; color: white; }
  .meta { color: #666; font-size: .9rem; }
  code { background: #8882; padding: .1rem .3rem; border-radius: 4px; }
  .unavailable { opacity: .6; font-style: italic; }
</style>
</head>
<body>
<h1>OSINT Investigation Report</h1>
<p class="meta">
  <strong>ID:</strong> {{ investigation.id }} &middot;
  <strong>Date:</strong> {{ investigation.created_at }} &middot;
  <strong>Investigator:</strong> {{ investigation.investigator }}
</p>

<h2>1. Executive Summary</h2>
<p>{{ findings|length }} finding(s) collected; {{ confirmed|length }} confirmed,
{{ unverified|length }} unverified, {{ unavailable|length }} source(s) unavailable.</p>

<h2>2. Target Identifiers</h2>
<ul>
{% for k, v in scope.items() %}{% if v %}<li><strong>{{ k }}:</strong> {{ v }}</li>{% endif %}{% endfor %}
</ul>

<h2>3-9. Findings by Category</h2>
{% for category, items in by_category.items() %}
  <h3>{{ category|capitalize }}</h3>
  {% for f in items %}
    {% if not f.unavailable %}
    <div class="finding">
      <strong>{{ f.label }}</strong>
      <span class="badge {{ f.confidence.value }}">{{ f.confidence.value }}</span>
      <p>{{ f.detail }}</p>
      {% for s in f.sources %}
        <div class="meta">Source: {{ s.source }} {% if s.url %}(<a href="{{ s.url }}">{{ s.url }}</a>){% endif %}
        — collected {{ s.collected_at }} — reliability: {{ s.reliability }}</div>
      {% endfor %}
      {% if f.reasoning %}<p class="meta">Reasoning: {{ f.reasoning }}</p>{% endif %}
    </div>
    {% endif %}
  {% endfor %}
{% endfor %}

<h2>10-11. Associated Entities &amp; Relationship Graph</h2>
<ul>
{% for r in investigation.relationships %}
  <li><code>{{ r.from_key }}</code> &rarr; <code>{{ r.to_key }}</code>
  [{{ r.relation_type }}] <span class="badge {{ r.confidence.value }}">{{ r.confidence.value }}</span>
  <div class="meta">{{ r.explanation }}</div></li>
{% else %}
  <li>No relationships established.</li>
{% endfor %}
</ul>

<h2>12. Timeline</h2>
<ul>
{% for e in timeline %}
  <li>{{ e.timestamp }} — {{ e.label }} ({{ e.source }})</li>
{% endfor %}
</ul>

<h2>13. Important Findings</h2>
<ul>{% for f in confirmed %}<li>{{ f.label }}: {{ f.detail[:200] }}</li>{% endfor %}</ul>

<h2>14. Unverified Findings</h2>
<ul>{% for f in unverified %}<li>{{ f.label }}: {{ f.detail[:200] }}</li>{% endfor %}</ul>

<h2>15. Data Sources</h2>
<ul>{% for s in sources %}<li>{{ s.source }} ({{ s.source_type }})</li>{% endfor %}</ul>

<h2>16. Limitations</h2>
<ul>
<li>Only publicly accessible sources were queried; nothing was bypassed.</li>
<li>Username/email matches across platforms are leads, not proof of identity.</li>
{% for u in investigation.unavailable_sources %}
<li class="unavailable">Unavailable: {{ u.module }} / {{ u.target }} — {{ u.error }}</li>
{% endfor %}
</ul>

<h2>17. Collection Timestamp</h2>
<p>{{ now }}</p>

<h2>18. OPSEC / Privacy Notes</h2>
<p>This report may contain personal data. Handle it per your organization's data
protection policy and applicable law, and delete the investigation when no longer needed.</p>

</body>
</html>
"""


def generate_html_report(investigation: Investigation) -> str:
    env = Environment(loader=BaseLoader(), autoescape=True)
    template = env.from_string(_TEMPLATE)

    by_category: dict[str, list] = {}
    for f in investigation.findings:
        by_category.setdefault(f.category, []).append(f)

    confirmed = [f for f in investigation.findings if f.confidence == Confidence.CONFIRMED and not f.unavailable]
    unverified = [f for f in investigation.findings if f.confidence == Confidence.UNVERIFIED and not f.unavailable]
    unavailable = [f for f in investigation.findings if f.unavailable]

    import datetime as _dt

    return template.render(
        investigation=investigation,
        findings=investigation.findings,
        by_category=by_category,
        confirmed=confirmed,
        unverified=unverified,
        unavailable=unavailable,
        scope=investigation.scope.model_dump(exclude_none=True),
        timeline=build_timeline(investigation),
        sources={s.source: s for s in investigation.sources_consulted}.values(),
        now=_dt.datetime.now(_dt.timezone.utc).isoformat(),
    )
