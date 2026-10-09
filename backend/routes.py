"""Version-one HTTP contracts. Empty means uncollected, not a safe network."""
from flask import Blueprint, current_app, jsonify, request
from backend.discovery.interfaces import discover_interfaces
from backend.errors import APIError
from backend.capture.pcap import read_pcap
from backend.validation import json_object, pagination, validate_query

api = Blueprint('api', __name__, url_prefix='/api')


def monitor():
    return current_app.extensions['monitor']


@api.get('/health')
def health():
    validate_query()
    return jsonify(status='ok', service='netguard', phase=7)


@api.get('/monitor/status')
def monitor_status():
    validate_query()
    return jsonify(monitor().status())


@api.post('/monitor/start')
def monitor_start():
    body = json_object(('interface',))
    interface = body.get('interface')
    if 'interface' not in body:
        raise APIError('invalid_interface', 'Select an explicit local interface before starting capture.')
    if 'interface' in body:
        if not isinstance(interface, str) or not interface.strip() or len(interface) > 128:
            raise APIError('invalid_interface', 'interface must be a nonempty name of at most 128 characters.')
        if interface not in {item['name'] for item in discover_interfaces()}:
            raise APIError('invalid_interface', 'The selected interface does not exist.')
    status = monitor().start(interface)
    return jsonify(status), 202 if status['state'] == 'starting' else 200


@api.post('/monitor/stop')
def monitor_stop():
    json_object()
    status = monitor().stop()
    return jsonify(status), 202 if status['state'] == 'stopping' else 200


@api.get('/interfaces')
def interfaces():
    validate_query()
    items = discover_interfaces()
    return jsonify(items=items, total=len(items))


def empty_collection():
    page = pagination()
    return jsonify(items=[], total=0, **page)


@api.get('/packets')
def packets():
    page = pagination()
    return jsonify(monitor().buffer.page(**page))


@api.post('/monitor/replay')
def replay():
    validate_query()
    if request.mimetype != 'multipart/form-data':
        raise APIError('invalid_upload', 'Upload one .pcap file using multipart field "file".', 415)
    if request.form or set(request.files) != {'file'} or len(request.files.getlist('file')) != 1:
        raise APIError('invalid_upload', 'Exactly one file field and no other fields are allowed.')
    uploaded = request.files['file']
    if not uploaded.filename or not uploaded.filename.lower().endswith('.pcap'):
        raise APIError('invalid_upload', 'The uploaded filename must end in .pcap.')
    limit = current_app.config['PCAP_MAX_BYTES']
    # Nothing is saved to a user-specified path, and only a bounded read is made.
    data = uploaded.stream.read(limit + 1)
    packets = read_pcap(data, limit, current_app.config['PCAP_MAX_RECORDS'])
    status = monitor().replay(packets)
    return jsonify(status), 202 if status['state'] == 'starting' else 200


@api.get('/alerts')
def findings():
    page = pagination(('source', 'severity', 'q'))
    source = request.args.get('source', 'all')
    severity = request.args.get('severity', 'all')
    query = request.args.get('q', '')
    if source not in ('all', 'live', 'offline') or severity not in ('all', 'Low', 'Medium', 'High') or len(query) > 120:
        raise APIError('invalid_query', 'Invalid finding source, severity, or search (maximum 120 characters).')
    return jsonify(current_app.extensions['detection'].findings(**page, source=source, severity=severity, q=query))


@api.get('/detection/status')
def detection_status():
    validate_query()
    return jsonify(current_app.extensions['detection'].status())
