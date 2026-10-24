"""Reject DNS-rebinding hostnames before Flask or Engine.IO handles a request."""
import re
from werkzeug.wrappers import Response


class LocalHostGuard:
    def __init__(self, application):
        self.application = application

    def __call__(self, environ, start_response):
        host = environ.get('HTTP_HOST', '')
        match = re.fullmatch(r'(?:localhost|127\.0\.0\.1|\[::1\])(?::([0-9]{1,5}))?', host, re.IGNORECASE)
        if not match or (match.group(1) and not 1 <= int(match.group(1)) <= 65535):
            response = Response(
                '{"error":{"code":"untrusted_host","message":"A loopback hostname is required."}}',
                status=400, content_type='application/json',
                headers={'Cache-Control': 'no-store', 'X-Content-Type-Options': 'nosniff'},
            )
            return response(environ, start_response)
        return self.application(environ, start_response)
