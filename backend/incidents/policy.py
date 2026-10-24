"""Conservative correlation and administrative-only response policy."""
from dataclasses import dataclass
from hashlib import sha256
import json

STATES = ('Open', 'Investigating', 'Contained', 'Resolved', 'Closed')
TRANSITIONS = {'Open': ('Investigating', 'Resolved'), 'Investigating': ('Contained', 'Resolved'),
               'Contained': ('Investigating', 'Resolved'), 'Resolved': ('Investigating', 'Closed'),
               'Closed': ('Investigating',)}
SEVERITIES = {'Low': 0, 'Medium': 1, 'High': 2}
RECOMMENDATIONS = [
    {'id': 'gateway_baseline', 'title': 'Verify the gateway baseline', 'description': 'Confirm the legitimate gateway MAC through trusted router administration and review the explicitly verified mapping. NetGuard does not infer a gateway.'},
    {'id': 'dhcp_leases', 'title': 'Check DHCP lease changes', 'description': 'Review authorized DHCP lease records for reassignment or legitimate device replacement.'},
    {'id': 'equipment', 'title': 'Inspect authorized equipment', 'description': 'Compare observed mappings with approved inventory and inspect authorized network equipment.'},
    {'id': 'switch_review', 'title': 'Review switch security settings', 'description': 'Ask an authorized administrator to review existing switch security policy through approved management tools. NetGuard changes no settings.'},
    {'id': 'escalate', 'title': 'Escalate for investigation', 'description': 'Discuss suspicious evidence with the responsible network administrator. Findings do not establish a confirmed attack.'},
    {'id': 'document_action', 'title': 'Document external corrective actions', 'description': 'Record who performed an authorized external action, when, and what was verified. This is an administrator report, not automated verification.'},
]


@dataclass(frozen=True)
class IncidentLimits:
    window_seconds: int = 300
    max_incidents: int = 10000
    max_links: int = 50000
    max_audit: int = 100000
    links_per_incident: int = 200
    audit_per_incident: int = 500

    def __post_init__(self):
        for key, value in vars(self).items():
            if type(value) is not int or not 1 <= value <= 1000000:
                raise ValueError(f'Incident {key} must be an integer from 1 to 1000000')
        if self.links_per_incident > 500 or self.audit_per_incident > 1000:
            raise ValueError('Incident detail/export bounds exceed supported limits')


def correlation_key(finding):
    p = finding.payload
    # Exact rule and unordered mapping pair/set; include capture session even for live data.
    mappings = sorted(set([p['observedMac'], *p['expectedMacs']]))
    return sha256(json.dumps([p['source'], p['scope'], p['sessionId'], p['interface'], p['ruleId'], p['sourceIp'], mappings]).encode()).hexdigest()
