"""
A03:2025 – Software Supply Chain Failures
Vulnerabilities demonstrated:
  - requirements.txt pins known-vulnerable package versions (Pillow, PyYAML)
  - Unsafe yaml.load() usage (arbitrary code execution via YAML)
  - No integrity check on "plugin" downloads (simulated)
  - Outdated dependency detection via pip-audit
"""
import subprocess
import yaml
from flask import Blueprint, render_template, request

a03 = Blueprint('a03', __name__)


@a03.route('/')
def index():
    return render_template('a03/index.html')


# ── VULNERABLE: yaml.load without Loader (CVE-2020-14343 style) ──────────────
@a03.route('/parse-config', methods=['GET', 'POST'])
def parse_config():
    result = None
    error = None
    sample = "name: MyApp\nversion: 1.0\ndebug: true"
    if request.method == 'POST':
        config_text = request.form.get('config', '')
        try:
            # BUG: yaml.load() without Loader allows arbitrary Python object creation
            result = yaml.load(config_text, Loader=yaml.Loader)
        except Exception as e:
            error = str(e)
    return render_template('a03/parse_config.html', result=result,
                           error=error, sample=sample)


# ── TOOL: run pip-audit to find vulnerable dependencies ──────────────────────
@a03.route('/audit')
def audit():
    try:
        proc = subprocess.run(
            ['pip-audit', '--format', 'json'],
            capture_output=True, text=True, timeout=60
        )
        output = proc.stdout or proc.stderr
    except FileNotFoundError:
        output = '{"error": "pip-audit not installed. Run: pip install pip-audit"}'
    except subprocess.TimeoutExpired:
        output = '{"error": "Audit timed out"}'
    return render_template('a03/audit.html', output=output)


# ── VULNERABLE: simulated unsigned plugin loader ──────────────────────────────
PLUGIN_REGISTRY = {
    'logger':   {'version': '1.2', 'hash': None,  'url': 'http://plugins.internal/logger.zip'},
    'reporter': {'version': '2.0', 'hash': None,  'url': 'http://plugins.internal/reporter.zip'},
}


@a03.route('/install-plugin', methods=['GET', 'POST'])
def install_plugin():
    message = None
    if request.method == 'POST':
        name = request.form.get('plugin', '')
        plugin = PLUGIN_REGISTRY.get(name)
        if plugin:
            # BUG: no hash/signature verification before "installing"
            message = (
                f"Installing '{name}' v{plugin['version']} from {plugin['url']} "
                f"— NO integrity check performed!"
            )
        else:
            message = f"Plugin '{name}' not found."
    return render_template('a03/install_plugin.html', plugins=PLUGIN_REGISTRY,
                           message=message)
