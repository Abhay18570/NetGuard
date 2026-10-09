"""Strict request boundaries for the small Phase 2 API."""
import re
from flask import request
from backend.errors import APIError


def validate_query(allowed=()):
    for key in request.args:
        if key not in allowed:
            raise APIError('invalid_query', f'Unsupported query parameter: {key}.')
        if len(request.args.getlist(key)) != 1:
            raise APIError('invalid_query', f'Query parameter {key} must appear once.')


def pagination(extra=()):
    validate_query(('limit', 'offset') + tuple(extra))
    result = {}
    for name, default, minimum, maximum in (
        ('limit', 100, 1, 500), ('offset', 0, 0, 1_000_000),
    ):
        raw = request.args.get(name, str(default))
        if not re.fullmatch(r'[0-9]{1,7}', raw):
            raise APIError('invalid_query', f'{name} must be an integer from {minimum} to {maximum}.')
        value = int(raw)
        if not minimum <= value <= maximum:
            raise APIError('invalid_query', f'{name} must be between {minimum} and {maximum}.')
        result[name] = value
    return result


def json_object(allowed=()):
    validate_query()
    # Flask supplies JSON 400/415 errors through our HTTP error handler.
    body = request.get_json()
    if not isinstance(body, dict):
        raise APIError('invalid_body', 'The JSON body must be an object.')
    unknown = set(body) - set(allowed)
    if unknown:
        raise APIError('invalid_body', f'Unsupported body field: {sorted(unknown)[0]}.')
    return body
