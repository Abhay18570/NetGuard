"""Local-development configuration. No wildcard origins or remote binding."""

import os
import json


class Config:
    DATABASE_URL = os.environ.get('NETGUARD_DATABASE_URL')
    ADMIN_TOKEN = os.environ.get('NETGUARD_ADMIN_TOKEN', '')
    ADMIN_ACTOR = os.environ.get('NETGUARD_ADMIN_ACTOR', 'local-admin')[:120]
    MAX_CONTENT_LENGTH = 16 * 1024
    CORS_ORIGINS = (
        'http://localhost:5173',
        'http://127.0.0.1:5173',
    )
    PCAP_MAX_BYTES = 5 * 1024 * 1024
    PCAP_MAX_RECORDS = 10000
    PACKET_BUFFER_CAPACITY = 1000
    CAPTURE_START_TIMEOUT = 2
    CAPTURE_STOP_TIMEOUT = 2
    REPLAY_INTERVAL = 0.05
    DETECTION_THRESHOLDS = json.loads(os.environ.get('NETGUARD_DETECTION_THRESHOLDS', '{}'))
    DETECTION_GATEWAY_MAPPING_IDS = json.loads(os.environ.get('NETGUARD_GATEWAY_MAPPING_IDS', '[]'))
    INCIDENT_LIMITS = json.loads(os.environ.get('NETGUARD_INCIDENT_LIMITS', '{}'))
    DATABASE_MAX_BYTES = int(os.environ.get('NETGUARD_DATABASE_MAX_BYTES', '1073741824'))
    INCIDENT_EXPORT_MAX_BYTES = 5 * 1024 * 1024
    JSON_SORT_KEYS = False
