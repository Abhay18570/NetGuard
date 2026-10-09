"""Owned, isolated real-process validation. Never touches the default database."""
import hashlib
import json
import os
from pathlib import Path
import secrets
import socket
import subprocess
import sys
import tempfile
import time
from urllib.request import urlopen

ROOT = Path(__file__).resolve().parents[2]
PYTHON = ROOT / '.venv/bin/python'


def read_api(path):
    with urlopen('http://127.0.0.1:5001/api/' + path, timeout=2) as response:
        return json.load(response)


def wait_ready(url, process):
    deadline = time.monotonic() + 15
    while time.monotonic() < deadline:
        if process.poll() is not None:
            raise RuntimeError('Validation server exited; inspect its temporary log')
        try:
            with urlopen(url, timeout=1) as response:
                if response.status == 200:
                    return
        except OSError:
            time.sleep(0.1)
    raise RuntimeError('Server startup timed out')


def stop_owned(process):
    if process and process.poll() is None:
        process.terminate()
        try:
            process.wait(timeout=5)
        except subprocess.TimeoutExpired:
            process.kill(); process.wait(timeout=5)


def normal_files():
    folder = ROOT / 'backend/instance'
    return {str(file): hashlib.sha256(file.read_bytes()).hexdigest() for file in folder.glob('*') if file.is_file()}


def main(extra_script=None):
    for port in (5001, 5173):
        with socket.socket() as probe:
            probe.settimeout(0.2)
            if probe.connect_ex(('127.0.0.1', port)) == 0:
                raise RuntimeError(f'Port {port} is occupied. No process was stopped. Run after its owner stops the development server.')
    before_normal = normal_files()
    backend = frontend = None
    with tempfile.TemporaryDirectory(prefix='netguard-validation-') as temporary:
        directory = Path(temporary)
        token = secrets.token_urlsafe(32)
        backend_env = {**os.environ, 'NETGUARD_DATABASE_URL': 'sqlite:///' + str(directory / 'validation.sqlite3'),
                       'NETGUARD_ADMIN_TOKEN': token, 'NETGUARD_ADMIN_ACTOR': 'isolated-validation-admin',
                       'NETGUARD_DETECTION_THRESHOLDS': '{}', 'NETGUARD_GATEWAY_MAPPING_IDS': '[]',
                       'NETGUARD_INCIDENT_LIMITS': '{}', 'NETGUARD_DATABASE_MAX_BYTES': '1073741824'}
        frontend_env = {key: value for key, value in os.environ.items() if key not in ('NETGUARD_ADMIN_TOKEN', 'NETGUARD_TEST_ADMIN_TOKEN')}
        with (directory / 'backend.log').open('w+') as backend_log, (directory / 'frontend.log').open('w+') as frontend_log:
            try:
                backend = subprocess.Popen([str(PYTHON), '-m', 'backend.app'], cwd=ROOT, env=backend_env, stdout=backend_log, stderr=subprocess.STDOUT)
                wait_ready('http://127.0.0.1:5001/api/health', backend)
                frontend = subprocess.Popen(['node', 'frontend/node_modules/vite/bin/vite.js', '--config', 'frontend/vite.config.ts', 'frontend'], cwd=ROOT, env=frontend_env, stdout=frontend_log, stderr=subprocess.STDOUT)
                wait_ready('http://127.0.0.1:5173/api/health', frontend)
                subprocess.run(['node', 'frontend/tests/phase4-integration.mjs'], cwd=ROOT,
                               env={**frontend_env, 'NETGUARD_TEST_ADMIN_TOKEN': token}, check=True, timeout=45)
                if extra_script:
                    subprocess.run(['node', extra_script], cwd=ROOT, env={**frontend_env, 'NETGUARD_TEST_ADMIN_TOKEN': token}, check=True, timeout=45)
                expected_incidents = read_api('incidents')
                expected_incident_details = {item['id']: read_api(f"incidents/{item['id']}") for item in expected_incidents['items']}
                expected_incident_audits = {item['id']: read_api(f"incidents/{item['id']}/audit") for item in expected_incidents['items']}
                expected_security_alerts = read_api('security-alerts')
                expected_alert_audits = {item['id']: read_api(f"security-alerts/{item['id']}/audit") for item in expected_security_alerts['items']}
                expected_findings = read_api('alerts')
                expected = read_api('devices?limit=500')
                expected_trust = read_api('trusted-mappings')
                mapping_id = expected_trust['items'][0]['id']
                expected_audit = read_api(f'trusted-mappings/{mapping_id}/audit')
                stop_owned(backend)
                backend = subprocess.Popen([str(PYTHON), '-m', 'backend.app'], cwd=ROOT, env=backend_env, stdout=backend_log, stderr=subprocess.STDOUT)
                wait_ready('http://127.0.0.1:5001/api/health', backend)
                assert read_api('incidents') == expected_incidents
                for incident_id, detail in expected_incident_details.items():
                    assert read_api(f'incidents/{incident_id}') == detail
                    assert read_api(f'incidents/{incident_id}/audit') == expected_incident_audits[incident_id]
                assert read_api('security-alerts') == expected_security_alerts
                for alert_id, audit in expected_alert_audits.items():
                    assert read_api(f'security-alerts/{alert_id}/audit') == audit
                assert read_api('alerts') == expected_findings
                assert read_api('devices?limit=500') == expected
                assert read_api('trusted-mappings') == expected_trust
                assert read_api(f'trusted-mappings/{mapping_id}/audit') == expected_audit
                assert read_api('monitor/status')['state'] == 'not_started'
                assert read_api('packets')['items'] == []
                print('Real backend restart passed: incidents, incident audit, alerts, alert audit, findings, inventory, trust and audit persisted; capture reset safely.')
                assert normal_files() == before_normal
                print('Normal workspace database unchanged. All isolated integration checks passed.')
            except Exception:
                backend_log.flush(); frontend_log.flush()
                backend_log.seek(0); frontend_log.seek(0)
                # Flask/Vite logs contain no authorization headers; redact token defensively.
                print(backend_log.read().replace(token, '[redacted]'), file=sys.stderr)
                print(frontend_log.read().replace(token, '[redacted]'), file=sys.stderr)
                raise
            finally:
                stop_owned(backend); stop_owned(frontend)


if __name__ == '__main__':
    main()
