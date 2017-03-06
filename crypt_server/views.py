from . import models
from .http import json_response, binary_response
from crypt_server.security import AES, RSA, hasher, to_b64_str, from_b64_str

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

def query():
    results = models.Document.objects.all()
    documents = []
    for result in results:
        documents.append({
            'path': result.path,
        })
    return json_response({
        'documents': documents
    })

def new():
    file_obj = request.files.get('file', None)
    path = request.form.get('path', None)

    payload = file_obj.read()
    file_obj.seek(0)
    new_key = AES.generate_key()
    raw_aes_key = from_b64_str(new_key)
    encryption_metadata = {}
    aes = AES(encryption_metadata, key=new_key)
    encrypted_payload = aes.encrypt(file_obj)

    # Save encrypted data
    doc = models.Document(
        path=path,
        encrypted_data=encrypted_payload,
        key_fingerprint=hasher(new_key),
        data_fingerprint=hasher(payload),
        metadata=encryption_metadata,
    )
    doc.save()

    # Encrypt key with public key of all sanctioned users
    sanctioned_users = [request.user]
    for user in sanctioned_users:
        rsa = RSA({}, key=user.public_key)
        encrypted_key = rsa.encrypt(raw_aes_key)
        encrypted_key = to_b64_str(encrypted_key)
        models.Sanction(
            document=doc,
            user=user,
            encrypted_key=encrypted_key,
        ).save()


    return json_response({
        'success': True,
        'path': path
    })

def read():
    path = request.args.get('path', None)
    doc = models.Document.objects.get(path=path)
    sanction = models.Sanction.objects.get(document=doc, user=request.user)
    return json_response({
        'path': path,
        'metadata': doc.metadata,
        'encrypted_key': sanction.encrypted_key,
    })

def read_data():
    path = request.args.get('path', None)
    doc = models.Document.objects.get(path=path)
    sanction = models.Sanction.objects.get(document=doc, user=request.user)
    return binary_response(doc.encrypted_data)
