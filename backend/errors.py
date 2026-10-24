"""One JSON error contract for validation, HTTP, and unexpected failures."""
from flask import current_app, jsonify
from werkzeug.exceptions import HTTPException


class APIError(Exception):
    def __init__(self, code, message, status=400):
        super().__init__(message)
        self.code = code
        self.message = message
        self.status = status


def register_error_handlers(app):
    @app.errorhandler(APIError)
    def api_error(error):
        return jsonify(error={'code': error.code, 'message': error.message}), error.status

    @app.errorhandler(HTTPException)
    def http_error(error):
        response = error.get_response()
        # Preserve headers such as Allow for a 405 response.
        response.data = current_app.json.dumps({'error': {
            'code': error.name.lower().replace(' ', '_'),
            'message': error.description,
        }})
        response.content_type = 'application/json'
        return response

    @app.errorhandler(Exception)
    def unexpected_error(error):
        current_app.logger.exception('Unhandled API error')
        return jsonify(error={
            'code': 'internal_error',
            'message': 'An unexpected server error occurred.',
        }), 500
