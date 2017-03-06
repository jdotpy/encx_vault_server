from flask import request
from .http import json_response
from .models import User

not_authed = json_response({
    'success': False,
    'message': 'Not Authenticated',
}, code=401)

forbidden = json_response({
    'success': False,
    'message': 'You are not authorized to do this operation.',
}, code=403)

auth_failed = json_response({
    'success': False,
    'message': 'You are not authorized to do this operation.',
}, code=403)

def auth():
    user_name = request.headers.get('X-CRYPT-USER', None)
    token = request.headers.get('X-CRYPT-TOKEN', None)
    print('Got username:', user_name, 'token:', token)
    if not token or not user_name:
        return not_authed
    try:
        user = User.objects.get(user_name=user_name)
    except Exception as e:
        user = None
        return auth_failed

    if user.token != token:
        return auth_failed

    request.user = user
