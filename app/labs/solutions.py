"""Serves solution markdown files."""
import os
from flask import Blueprint, render_template_string, abort

solutions = Blueprint('solutions', __name__)

SOL_DIR = os.path.join(os.path.dirname(__file__), '..', '..', 'solutions')

TEMPLATE = """
{% extends "base.html" %}
{% block title %}Solution: {{ lab }}{% endblock %}
{% block content %}
<div class="d-flex justify-content-between align-items-center mb-3">
  <h4>Solution: {{ lab }}</h4>
  <a href="/" class="btn btn-outline-secondary btn-sm">← Back to Index</a>
</div>
<div class="card">
  <div class="card-body">
    {{ content | safe }}
  </div>
</div>
{% endblock %}
"""


@solutions.route('/<lab>')
def show(lab):
    if not lab.startswith('a') or not lab[1:].isdigit():
        abort(404)
    path = os.path.join(SOL_DIR, f"{lab}.md")
    if not os.path.exists(path):
        abort(404)
    with open(path) as f:
        raw = f.read()
    try:
        import markdown
        html = markdown.markdown(raw, extensions=['fenced_code', 'tables'])
    except ImportError:
        html = f"<pre>{raw}</pre>"
    return render_template_string(TEMPLATE, lab=lab.upper(), content=html)
