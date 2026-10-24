"""Pure, explainable rules over a bounded chronological observation window."""
from dataclasses import dataclass


@dataclass(frozen=True)
class Thresholds:
    claim_window: int = 60
    request_window: int = 5
    burst_window: int = 10
    burst_count: int = 30
    unsolicited_count: int = 5
    cooldown: int = 60
    history_capacity: int = 4096
    queue_capacity: int = 2048

    def __post_init__(self):
        for key, value in vars(self).items():
            if type(value) is not int or not 1 <= value <= 100000:
                raise ValueError(f'Detection {key} must be an integer between 1 and 100000')
        if self.burst_count > self.history_capacity or self.unsolicited_count > self.history_capacity:
            raise ValueError('Detection thresholds exceed history capacity')


def gratuitous(p):
    return p['senderIp'] == p['targetIp']


def correlated(reply, history, window):
    return any(p['operation'] == 'Request' and 0 <= reply['_time'] - p['_time'] <= window
               and p['targetIp'] == reply['senderIp'] and p['senderIp'] == reply['targetIp']
               and p['senderMac'] == reply['targetMac'] for p in history)


def conflict(p, history, baseline, config):
    previous = [x for x in history if x['senderIp'] == p['senderIp'] and x['senderMac'] != p['senderMac']
                and 0 <= p['_time'] - x['_time'] <= config.claim_window]
    # An explicitly verified replacement/allowed alias is not rejected using stale observations.
    allowed = {x.mac for x in baseline}
    if p['senderMac'] in allowed:
        return None
    if not previous:
        return None
    return ('ARP_CLAIM_CONFLICT', 'Medium', 'Medium', previous,
            'Different MAC addresses claimed this IP within the recent claim window. DHCP, failover, or replacement may explain this observation.',
            sorted({x['senderMac'] for x in previous}), {})


def gateway(p, history, baseline, config, gateway_ids):
    configured = [x for x in baseline if x.id in gateway_ids]
    if not configured or p['senderMac'] in {x.mac for x in baseline}:
        return None
    related = [x for x in history if x['senderIp'] == p['senderIp'] and x['senderMac'] == p['senderMac']]
    repeated = len(related) >= 2
    return ('ARP_GATEWAY_MISMATCH', 'High' if repeated else 'Medium', 'High' if repeated else 'Medium', related,
            'Observed claim differs from an explicitly configured, currently verified gateway baseline. This is a suspicious observation, not proof of impersonation.',
            sorted({x.mac for x in configured}), {'baselineIds': [x.id for x in configured], 'baselineVersions': [x.version for x in configured]})


def burst(p, history, baseline, config):
    if p['operation'] != 'Reply':
        return None
    replies = [x for x in history if x['operation'] == 'Reply' and x['senderMac'] == p['senderMac']
               and 0 <= p['_time'] - x['_time'] <= config.burst_window] + [p]
    if len(replies) < config.burst_count:
        return None
    return ('ARP_REPLY_BURST', 'Low' if gratuitous(p) else 'Medium', 'Low', replies,
            f'{len(replies)} ARP replies from this MAC in {config.burst_window} seconds; legitimate failover and busy hosts can also produce bursts.',
            [], {'count': len(replies), 'windowSeconds': config.burst_window, 'gratuitous': gratuitous(p)})


def unsolicited(p, history, baseline, config):
    if p['operation'] != 'Reply' or gratuitous(p) or correlated(p, history, config.request_window):
        return None
    # Require a complete local correlation-window warmup, not proof of complete network visibility.
    if not history or p['_time'] - history[0]['_time'] < config.request_window:
        return None
    unmatched = [x for x in history if x['operation'] == 'Reply' and not gratuitous(x)
                 and x['senderIp'] == p['senderIp'] and x['senderMac'] == p['senderMac']
                 and 0 <= p['_time'] - x['_time'] <= config.burst_window
                 and x.get('_uncorrelatedEligible', False)] + [p]
    if len(unmatched) < config.unsolicited_count:
        return None
    return ('ARP_UNCORRELATED_REPLY', 'Low', 'Low', unmatched,
            'Repeated replies have no matching request in the observed correlation window. Requests may have been missed or outside capture visibility; absence is not proof they were unsolicited.',
            [], {'count': len(unmatched), 'requestWindowSeconds': config.request_window, 'requestEvidence': 'not_observed'})


def evaluate(p, history, baseline, config, gateway_ids):
    candidates = [conflict(p, history, baseline, config), gateway(p, history, baseline, config, gateway_ids),
                  burst(p, history, baseline, config), unsolicited(p, history, baseline, config)]
    return [item for item in candidates if item is not None]
