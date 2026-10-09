"""Application factory and local development entrypoint."""
from flask import Flask, request
from pathlib import Path
from threading import RLock
from flask_cors import CORS
from flask_socketio import SocketIO
from backend.host_guard import LocalHostGuard
from backend.config import Config
from backend.errors import APIError, register_error_handlers
from backend.routes import api
from backend.services.monitor import MonitorService
from backend.capture.engine import ScapyCapture
from backend.database.store import Database
from backend.services.inventory import InventoryService
from backend.trust_routes import trust_api
from backend.alert_routes import alert_api
from backend.services.alerts import AlertService
from backend.detection.service import DetectionService
from backend.incidents.service import IncidentService
from backend.incidents.routes import incident_api


def create_app(config=None):
    app = Flask(__name__)
    app.config.from_object(Config)
    if config:
        app.config.update(config)
    app.json.sort_keys = False
    CORS(app, resources={r'/api/*': {'origins': app.config['CORS_ORIGINS']}},
         methods=['GET', 'POST', 'PATCH', 'DELETE', 'OPTIONS'], allow_headers=['Content-Type', 'Authorization'],
         supports_credentials=False)
    # One SocketIO instance per application; serialized capture event emission.
    socketio = SocketIO(app, async_mode='threading',
             cors_allowed_origins=list(app.config['CORS_ORIGINS']),
             logger=False, engineio_logger=False)
    event_lock = RLock()

    def publish(event, payload):
        with event_lock:
            try:
                socketio.emit(event, payload)
            except Exception:
                app.logger.exception('Socket.IO event delivery failed')
        if event == 'alert_created' and 'incidents' in app.extensions:
            app.extensions['incidents'].enqueue()

    database_url = app.config['DATABASE_URL']
    if not database_url:
        if app.testing:
            database_url = 'sqlite://'
        else:
            folder = Path(__file__).resolve().parent / 'instance'
            folder.mkdir(parents=True, exist_ok=True)
            database_url = f'sqlite:///{folder / "netguard.sqlite3"}'
    database = Database(database_url, app.config['DATABASE_MAX_BYTES'])
    app.extensions['database'] = database
    app.extensions['alerts'] = AlertService(database, publish)
    app.extensions['incidents'] = IncidentService(database, publish, app.config['INCIDENT_LIMITS'], app.config['DETECTION_GATEWAY_MAPPING_IDS'])
    inventory = InventoryService(database, publish)
    app.extensions['inventory'] = inventory
    detection = DetectionService(database, publish, app.config['DETECTION_THRESHOLDS'], app.config['DETECTION_GATEWAY_MAPPING_IDS'])
    app.extensions['detection'] = detection

    def observe(packet):
        detection.enqueue(packet)
        inventory.ingest(packet)

    app.extensions['monitor'] = MonitorService(
        emit=publish,
        observe=observe,
        engine_factory=app.config.get('CAPTURE_ENGINE_FACTORY', ScapyCapture),
        capacity=app.config['PACKET_BUFFER_CAPACITY'],
        start_timeout=app.config['CAPTURE_START_TIMEOUT'],
        stop_timeout=app.config['CAPTURE_STOP_TIMEOUT'],
        replay_interval=app.config['REPLAY_INTERVAL'],
    )

    @app.before_request
    def replay_upload_limit():
        if request.method in ('POST', 'PATCH', 'DELETE') and request.path.startswith('/api/'):
            origin = request.headers.get('Origin')
            if origin is not None and origin not in app.config['CORS_ORIGINS']:
                raise APIError('origin_not_allowed', 'This request origin is not allowed.', 403)
        if request.path == '/api/monitor/replay':
            request.max_content_length = app.config['PCAP_MAX_BYTES'] + 64 * 1024

    register_error_handlers(app)
    app.register_blueprint(api)
    app.register_blueprint(trust_api)
    app.register_blueprint(alert_api)
    app.register_blueprint(incident_api)

    @app.after_request
    def no_store(response):
        response.headers['Cache-Control'] = 'no-store'
        return response

    app.wsgi_app = LocalHostGuard(app.wsgi_app)
    return app


if __name__ == '__main__':
    application = create_app()
    # Development only: loopback, no debugger or reloader.
    application.extensions['socketio'].run(
        application, host='127.0.0.1', port=5001,
        debug=False, use_reloader=False, allow_unsafe_werkzeug=True,
    )
