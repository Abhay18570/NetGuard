"""Probe an owned Safari WebDriver session without enabling remote automation."""
import json
import socket
import subprocess
import time
from pathlib import Path
from urllib.request import Request, urlopen
from urllib.error import HTTPError, URLError


def main():
    with socket.socket() as sock:
        sock.bind(('127.0.0.1', 0)); port = sock.getsockname()[1]
    process = subprocess.Popen(['/usr/bin/safaridriver', '-p', str(port)], stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)
    result = {'driver': 'Safari WebDriver', 'available': False, 'settingsChanged': False}
    base = f'http://127.0.0.1:{port}'
    try:
        for _ in range(40):
            try:
                with urlopen(base + '/status', timeout=1): break
            except (URLError, OSError): time.sleep(.1)
        try:
            payload = json.dumps({'capabilities': {'alwaysMatch': {'browserName': 'safari'}}}).encode()
            with urlopen(Request(base + '/session', data=payload, headers={'Content-Type': 'application/json'}), timeout=15) as response:
                body = json.load(response)
            session_id = body['value']['sessionId']; result['available'] = True
            with urlopen(Request(base + '/session/' + session_id, method='DELETE'), timeout=5): pass
        except HTTPError as error:
            result['reason'] = json.load(error).get('value', {}).get('message', str(error))
        except Exception as error:
            result['reason'] = str(error)
    finally:
        if process.poll() is None:
            process.terminate()
            try: process.wait(timeout=5)
            except subprocess.TimeoutExpired: process.kill(); process.wait(timeout=5)
    Path('validation/browser-availability.json').write_text(json.dumps(result, indent=2) + '\n')
    print(json.dumps(result, indent=2))

if __name__ == '__main__': main()
