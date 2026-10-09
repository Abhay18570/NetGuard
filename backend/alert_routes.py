"""Phase 6 resource; /api/alerts retains the Phase 5 finding contract."""
from flask import Blueprint, current_app, request, jsonify
from backend.validation import pagination, validate_query, json_object
from backend.trust_routes import administrator
from backend.services.alerts import STATES
from backend.errors import APIError
from backend.database.models import DetectionFinding

alert_api = Blueprint('alert_api', __name__, url_prefix='/api')


def service(): return current_app.extensions['alerts']


@alert_api.get('/security-alerts')
def alerts():
    page = pagination(('source', 'severity', 'status', 'q'))
    source, severity, status, q = (request.args.get(k, default) for k, default in (('source', 'all'), ('severity', 'all'), ('status', 'all'), ('q', '')))
    if source not in ('all', 'live', 'offline') or severity not in ('all', 'Low', 'Medium', 'High') or status not in ('all', *STATES) or len(q) > 120:
        raise APIError('invalid_query', 'Invalid alert filter or search longer than 120 characters.')
    return jsonify(service().page(**page, source=source, severity=severity, status=status, q=q))


@alert_api.get('/security-alerts/summary')
def summary():
    validate_query()
    return jsonify(service().counts())


@alert_api.get('/security-alerts/<alert_id>')
def detail(alert_id):
    validate_query()
    return jsonify(service().detail(alert_id))


@alert_api.patch('/security-alerts/<alert_id>')
@administrator
def change(alert_id):
    body = json_object(('status', 'version', 'reason'))
    return jsonify(service().change(alert_id, body, current_app.config['ADMIN_ACTOR']))


@alert_api.get('/security-alerts/<alert_id>/audit')
def audit(alert_id):
    return jsonify(service().audit(alert_id, **pagination()))


@alert_api.get('/findings/<finding_id>')
def finding(finding_id):
    validate_query()
    with current_app.extensions['database'].transaction() as session:
        row = session.get(DetectionFinding, finding_id)
        if not row: raise APIError('finding_not_found', 'Finding not found.', 404)
        return jsonify(row.payload)
