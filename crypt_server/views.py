from . import models
from .http import json_response
from crypt_server.security import RSA

from flask import request

def home():
    return 'Crypt Server'

def user_init():
    if request.user.initialized:
        return json_response({
            'success': False,
            'message': 'A User cannot be re-initialized',
        }, code=403)

    passphrase = request.form.get('passphrase', None)

    key = RSA({}, RSA.generate_key())
    private_key = key.get_key(passphrase=passphrase)
    public_key = key.get_public_key()
    request.user.public_key = public_key
    new_token = request.user.regen_token()
    request.user.initialized = True
    request.user.save()
    return json_response({
        'success': True,
        'token': new_token,
        'public_key': public_key,
        'private_key': private_key,
    })


def new():
    file_obj = request.files.get('file', None)
    path = request.form.get('path', None)

    print('New Key:\n', private_key)
    print('Got file:', path, len(file_obj.read()))

    return json_response({
        'success': True,
        'path': path
    })
