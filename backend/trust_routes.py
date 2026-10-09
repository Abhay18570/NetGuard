"""Validated local administrator mapping management; audit identity is server-owned."""
from functools import wraps
from hmac import compare_digest
from flask import Blueprint, current_app, jsonify, request
from backend.errors import APIError
from backend.validation import json_object, pagination, validate_query

trust_api = Blueprint('trust_api', __name__, url_prefix='/api')


def inventory():
    return current_app.extensions['inventory']


def administrator(function):
    @wraps(function)
    def protected(*args, **kwargs):
        token = current_app.config['ADMIN_TOKEN']
        if not isinstance(token, str) or len(token) < 32:
            raise APIError('admin_not_configured', 'Administrative changes require a configured administrator token (at least 32 characters).', 503)
        authorization = request.headers.get('Authorization', '')
        if not authorization.startswith('Bearer ') or not compare_digest(authorization[7:].encode(), token.encode()):
            raise APIError('admin_required', 'A valid administrator bearer token is required.', 401)
        return function(*args, **kwargs)
    return protected


@trust_api.get('/devices')
def devices():
    page = pagination(('q', 'source', 'trusted'))
    query = request.args.get('q', '').strip()
    source = request.args.get('source', 'all')
    trusted = request.args.get('trusted', 'false')
    if len(query) > 120 or source not in ('all', 'live', 'offline') or trusted not in ('true', 'false'):
        raise APIError('invalid_query', 'Use q up to 120 characters, source all/live/offline, and trusted true/false.')
    return jsonify(inventory().devices(**page, query=query, source=source, trusted=trusted == 'true'))


@trust_api.get('/discovery/status')
def discovery_status():
    validate_query()
    return jsonify(inventory().status())


@trust_api.get('/mapping-conflicts')
def mapping_conflicts():
    return jsonify(inventory().conflicts(**pagination()))


@trust_api.get('/trusted-mappings')
def trusted_mappings():
    page = pagination(('state',))
    state = request.args.get('state', 'all')
    if state not in ('all', 'pending', 'verified', 'revoked'):
        raise APIError('invalid_query', 'state must be all, pending, verified, or revoked.')
    return jsonify(inventory().trusted(**page, state=state))


@trust_api.get('/trusted-mappings/<mapping_id>')
def trusted_mapping(mapping_id):
    validate_query()
    return jsonify(inventory().get_trusted(mapping_id))


@trust_api.get('/trusted-mappings/<mapping_id>/audit')
def trusted_audit(mapping_id):
    return jsonify(inventory().audit(mapping_id, **pagination()))


@trust_api.post('/trusted-mappings')
@administrator
def create_trusted():
    body = json_object(('ip', 'mac', 'interface', 'label', 'reason'))
    return jsonify(inventory().change_trust('create', body, current_app.config['ADMIN_ACTOR'])), 201


@trust_api.patch('/trusted-mappings/<mapping_id>')
@administrator
def update_trusted(mapping_id):
    body = json_object(('ip', 'mac', 'interface', 'label', 'reason', 'version'))
    return jsonify(inventory().change_trust('update', body, current_app.config['ADMIN_ACTOR'], mapping_id))


@trust_api.post('/trusted-mappings/<mapping_id>/verify')
@administrator
def verify_trusted(mapping_id):
    body = json_object(('reason', 'version'))
    return jsonify(inventory().change_trust('verify', body, current_app.config['ADMIN_ACTOR'], mapping_id))


@trust_api.delete('/trusted-mappings/<mapping_id>')
@administrator
def revoke_trusted(mapping_id):
    body = json_object(('reason', 'version'))
    return jsonify(inventory().change_trust('revoke', body, current_app.config['ADMIN_ACTOR'], mapping_id))
