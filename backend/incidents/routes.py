"""Validated investigation and explicitly authorized evidence export."""
import csv
import io
import json
import re
from flask import Blueprint, current_app, jsonify, request, Response
from backend.errors import APIError
from backend.validation import pagination, validate_query, json_object
from backend.trust_routes import administrator
from backend.incidents.policy import STATES

incident_api = Blueprint('incident_api', __name__, url_prefix='/api')


def service(): return current_app.extensions['incidents']


@incident_api.get('/incidents')
def incidents():
    page = pagination(('source', 'severity', 'status', 'q'))
    source, severity, status, q = (request.args.get(k, default) for k, default in (('source', 'all'), ('severity', 'all'), ('status', 'all'), ('q', '')))
    if source not in ('all', 'live', 'offline') or severity not in ('all', 'Low', 'Medium', 'High') or status not in ('all', *STATES) or len(q) > 120:
        raise APIError('invalid_query', 'Invalid incident filters or search longer than 120 characters.')
    return jsonify(service().page(**page, source=source, severity=severity, status=status, q=q))


@incident_api.get('/incidents/<incident_id>')
def detail(incident_id):
    validate_query()
    return jsonify(service().detail(incident_id))


@incident_api.patch('/incidents/<incident_id>')
@administrator
def change(incident_id):
    body = json_object(('status', 'version', 'reason', 'assignedTo', 'resolutionNotes', 'containmentConfirmed', 'externalAction'))
    return jsonify(service().change(incident_id, body, current_app.config['ADMIN_ACTOR']))


@incident_api.post('/incidents/<incident_id>/actions')
@administrator
def action(incident_id):
    body = json_object(('actionId', 'version', 'reason', 'confirmed', 'description', 'performedAt'))
    return jsonify(service().change(incident_id, body, current_app.config['ADMIN_ACTOR'], action=True))


@incident_api.get('/incidents/<incident_id>/audit')
def audit(incident_id):
    return jsonify(service().audit(incident_id, **pagination()))


@incident_api.get('/defense/summary')
def defense_summary():
    validate_query()
    return jsonify(service().summary())


def csv_safe(value):
    text = value if isinstance(value, str) else json.dumps(value, ensure_ascii=False)
    if text.lstrip().startswith(('=', '+', '-', '@')) or text.startswith(('\t', '\r', '\n')):
        return "'" + text
    return text


def csv_document(document):
    output = io.StringIO(newline='')
    writer = csv.writer(output)
    writer.writerow(('section', 'reference', 'field', 'value'))
    for key, value in document.items():
        if key not in ('incident', 'timeline'): writer.writerow(('export', '', key, csv_safe(value)))
    incident = document['incident']
    for key, value in incident.items():
        if key not in ('alerts', 'observedMappings'):
            writer.writerow(('incident', incident['id'], key, csv_safe(value)))
    for section, values in (('alert', incident['alerts']), ('mapping', incident['observedMappings']), ('action', document['timeline'])):
        for value in values:
            reference = str(value.get('id', value.get('findingId', '')))
            for key, field in value.items(): writer.writerow((section, reference, key, csv_safe(field)))
    return output.getvalue()


@incident_api.get('/incidents/<incident_id>/export')
@administrator
def export(incident_id):
    validate_query(('format',))
    format_name = request.args.get('format', 'json')
    if format_name not in ('json', 'csv'): raise APIError('invalid_query', 'Export format must be json or csv.')
    document = service().export(incident_id)
    # No configuration or request headers enter the export. Redact a known admin token
    # even if it was accidentally pasted into an administrator-authored note.
    secret = current_app.config['ADMIN_TOKEN']
    def redact(value):
        if isinstance(value, str): return value.replace(secret, '[REDACTED]')
        if isinstance(value, dict): return {k: redact(v) for k, v in value.items()}
        if isinstance(value, list): return [redact(v) for v in value]
        return value
    document = redact(document)
    text = json.dumps(document, ensure_ascii=False, indent=2) if format_name == 'json' else csv_document(document)
    if len(text.encode('utf-8')) > current_app.config['INCIDENT_EXPORT_MAX_BYTES']:
        raise APIError('export_too_large', 'Export exceeds the configured size limit. Evidence remains available through paginated APIs.', 413)
    safe_id = re.sub(r'[^a-zA-Z0-9-]', '', incident_id)[:36]
    response = Response(text, content_type='application/json; charset=utf-8' if format_name == 'json' else 'text/csv; charset=utf-8')
    response.headers['Content-Disposition'] = f'attachment; filename="netguard-incident-{safe_id}.{format_name}"'
    response.headers['X-Content-Type-Options'] = 'nosniff'
    return response
