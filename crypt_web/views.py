from django.http import JsonResponse, FileResponse
from crypt_core.security import AES, RSA, hasher, to_b64_str, from_b64_str

from . import models

import io

def home(request):
    return 'Crypt Server'

def add_user(request):
    pass

def user_init(request):
    if request.user.initialized:
        return JsonResponse({
            'success': False,
            'message': 'A User cannot be re-initialized',
        }, code=403)

    passphrase = request.POST.get('passphrase', None)

    key = RSA({}, RSA.generate_key())
    private_key = key.get_key(passphrase=passphrase)
    public_key = key.get_public_key()
    request.user.public_key = public_key
    new_token = request.user.regen_token()
    request.user.initialized = True
    request.user.save()
    return JsonResponse({
        'success': True,
        'token': new_token,
        'public_key': public_key,
        'private_key': private_key,
    })

def query(request):
    search_term = request.GET.get('q', None)
    results = models.Document.objects.filter().only('path', 'created')
    if search_term:
        results = results.filter(path={'$regex': search_term})
    results = results.order_by('path')
    documents = []
    documents = list(map(models.Document.struct, results))
    return JsonResponse({
        'documents': documents
    })

def new(request):
    if request.method != 'POST':
        return JsonResponse({
            'success': False,
            'message': 'You must POST to this endpoint',
        }, status=405)

    file_obj = request.FILES.get('file', None)
    path = request.POST.get('path', None)

    if not file_obj:
        return JsonResponse({
            'success': False,
            'message': 'Invalid file upload',
        }, status=400)
    if not path:
        return JsonResponse({
            'success': False,
            'message': 'Invalid file path',
        }, status=400)
    if models.Document.objects.filter(path=path).exists():
        return JsonResponse({
            'success': False,
            'message': 'Document already exists',
        }, status=400)



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
        creator=request.user,
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


    return JsonResponse({
        'success': True,
        'path': path
    })

def read(request):
    path = request.GET.get('path', None)
    doc = models.Document.objects.get(path=path)
    sanction = models.Sanction.objects.get(document=doc, user=request.user)
    return JsonResponse({
        'path': path,
        'metadata': doc.metadata,
        'encrypted_key': sanction.encrypted_key,
    })

def read_data(request):
    path = request.GET.get('path', None)
    doc = models.Document.objects.get(path=path)
    sanction = models.Sanction.objects.get(document=doc, user=request.user)
    return FileResponse(io.BytesIO(doc.encrypted_data))

