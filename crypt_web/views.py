from django.http import JsonResponse, FileResponse

from .utils  import FORBIDDEN
from . import models

from crypt_core.security import generate_uuid, AES, RSA, hasher, to_b64_str, from_b64_str

import io

def ping(request):
    return JsonResponse({
        'message': 'pong',
        'user': {
            'user_name': request.user.user_name,
            'fingerprint': request.user.get_fingerprint(),
            'is_admin': request.user.is_admin,
        },
    })


def add_user(request):
    if not request.user.can('create', models.User):
        return FORBIDDEN

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

def audit_log(request):
    user = request.GET.get('user', None)
    doc_path = request.GET.get('path', None)
    action = request.GET.get('action', None)

    if not request.user.can('query', models.Audit):
        return FORBIDDEN

    results = models.Audit.objects.all()
    if user:
        results = results.filter(user_name=user)
    if doc_path:
        results = results.filter(document_path=doc_path)
    if action:
        results = results.filter(action=action)

    log = list(map(models.Audit.struct, results))
    return JsonResponse({
        'log': log
    })

def doc_query(request):
    if not request.user.can('query', models.Document):
        return FORBIDDEN

    search_term = request.GET.get('q', None)
    results = models.Document.objects.latest_versions(for_user=request.user)
    if search_term:
        results = results.filter(path__icontains=search_term)
    documents = list(map(models.Document.struct, results))
    return JsonResponse({
        'documents': documents
    })

def doc_new(request):
    if not request.user.can('create', models.Document):
        return FORBIDDEN

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

    doc = models.Document.objects.new(request.user, path, file_obj.read())

    doc.audit(request.user, models.Audit.ACTION_CREATE)

    return JsonResponse({
        'success': True,
        'path': path
    })

def doc_update(request):
    if request.method != 'POST':
        return JsonResponse({
            'success': False,
            'message': 'You must POST to this endpoint',
        }, status=405)

    path = request.POST.get('path', None)
    try:
        previous_version = models.Document.objects.latest_versions().get(path=path)
    except models.Document.DoesNotExist:
        return JsonResponse({
            'success': False,
            'message': 'No Document with this path to edit',
        }, status=404)
        
    if not request.user.can(models.Audit.ACTION_UPDATE, previous_version):
        return FORBIDDEN

    file_obj = request.FILES.get('file', None)
    if not file_obj:
        return JsonResponse({
            'success': False,
            'message': 'Invalid file upload',
        }, status=400)

    payload = file_obj.read()
    if hasher(payload) == previous_version.data_fingerprint:
        return JsonResponse({
            'success': False,
            'message': 'Document unchanged.',
        }, status=400)

    doc = models.Document.objects.new(
        request.user,
        path,
        payload,
        previous=previous_version,
    )
    doc.audit(request.user, models.Audit.ACTION_CREATE)

    return JsonResponse({
        'success': True,
        'doc': doc.struct(),
    })

def doc_read_meta(request):
    path = request.GET.get('path', None)
    doc = models.Document.objects.latest_versions().get(path=path)

    if not request.user.can('read', doc):
        return FORBIDDEN

    sanction = doc.sanction_for(request.user)
    return JsonResponse({
        'path': path,
        'metadata': doc.metadata,
        'encrypted_key': sanction.encrypted_key,
    })

def doc_read_data(request):
    path = request.GET.get('path', None)
    doc = models.Document.objects.latest_versions().get(path=path)

    if not request.user.can('read', doc):
        return FORBIDDEN

    doc.audit(request.user, models.Audit.ACTION_READ)
    return FileResponse(io.BytesIO(doc.encrypted_data))

def doc_versions(request):
    path = request.GET.get('path', None)

    if not request.user.can('query', models.Document):
        return FORBIDDEN

    results = models.Document.objects.for_user(request.user).filter(path=path)
    versions = list(map(models.Document.struct, results))
    return JsonResponse({
        'documents': versions,
    })

def doc_remove_version(request):
    return FORBIDDEN

def doc_destroy(request):
    return FORBIDDEN
