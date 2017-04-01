from django.http import JsonResponse, FileResponse
from .utils  import FORBIDDEN
from . import models

import json
import io

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

def doc_sanction(request):
    user_name = request.POST.get('user', None)
    encrypted_key = request.POST.get('encrypted_key', None)
    key_metadata = request.POST.get('key_metadata', None)
    path = request.POST.get('path', None)
    version = request.POST.get('version', None)

    if version is not None:
        query = models.Document.objects.filter(id=version, path=path)
    else:
        query = models.Document.objects.latest_versions().filter(path=path)
    try:
        doc = query.get()
    except models.Document.DoesNotExist:
        print('Document doesnt exist, forbidden')
        return FORBIDDEN # Dont give a 404 before permission check 

    # Check to see if the user can do any kind of sanction
    if not request.user.can('sanction', doc):
        return FORBIDDEN

    try:
        user = models.User.objects.get(user_name=user_name)
    except models.User.DoesNotExist:
        return JsonResponse({
            'success': False,
            'message': 'User does not exist.',
        }, status=400)
    if not user.initialized:
        return JsonResponse({
            'success': False,
            'message': 'User is not initialized... no sanctions can be done.',
        }, status=400)

    existing_sanction = doc.sanction_for(user)
    if existing_sanction:
        existing_sanction.delete()

    # +1 Good to go
    doc.sanction_user(user, encrypted_key, json.loads(key_metadata))
    return JsonResponse({
        'success': True,
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

def doc_create_version(request, update=False):
    action = 'create'
    if update:
        action = 'update'
    if not request.user.can(action, models.Document):
        return FORBIDDEN

    if request.method != 'POST':
        return JsonResponse({
            'success': False,
            'message': 'You must POST to this endpoint',
        }, status=405)

    file_obj = request.FILES.get('encrypted_document', None)
    path = request.POST.get('path', None)
    document_fingerprint = request.POST.get('document_fingerprint', None)

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

    try: 
        existing = models.Document.objects.latest_versions().get(path=path)
    except models.Document.DoesNotExist:
        existing = None

    if update:
        if existing is None:
            return JsonResponse({
                'success': False,
                'message': 'Document doesnt exist!',
            }, status=400)
        if existing.data_fingerprint == document_fingerprint:
            return JsonResponse({
                'success': False,
                'message': 'Document didnt change! (Digest matched previous)',
            }, status=400)
    elif existing:
        return JsonResponse({
            'success': False,
            'message': 'Document already exists!',
        }, status=400)

    doc = models.Document.objects.create(
        creator=request.user,
        path=path,
        encrypted_data=file_obj.read(),
        data_fingerprint=document_fingerprint,
        key_fingerprint=request.POST.get('key_fingerprint'),
        metadata=json.loads(request.POST.get('document_metadata')),
    )
    doc.audit(request.user, models.Audit.ACTION_CREATE)
    return JsonResponse({
        'success': True,
        'doc': {
            'id': doc.id,
            'path': doc.path,
        }
    })

def doc_read_meta(request):
    path = request.GET.get('path', None)
    version = request.GET.get('version', None)

    doc = models.Document.objects.get_doc(request.user, path, version)
    if not doc and request.user.is_admin:
        return JsonResponse({
            'success': False,
            'message': 'Document does not exist',
        }, status=404)
        
    if not doc or not request.user.can('read', doc):
        return FORBIDDEN

    sanction = doc.sanction_for(request.user)
    if not sanction:
        return JsonResponse({
            'success': False,
            'message': 'You do not have a sanction for this document.',
        }, status=400)

    return JsonResponse({
        'id': doc.id,
        'path': doc.path,
        'document_fingerprint': doc.data_fingerprint,
        'document_metadata': doc.metadata,
        'encrypted_key': sanction.encrypted_key,
        'key_metadata': sanction.metadata,
    })

def doc_read_data(request):
    path = request.GET.get('path', None)
    version = request.GET.get('version', None)
    doc = models.Document.objects.get_doc(request.user, path, version)
    if not doc and request.user.is_admin:
        return JsonResponse({
            'success': False,
            'message': 'Document does not exist',
        }, status=404)
    if not request.user.can('read', doc):
        return FORBIDDEN

    doc.audit(request.user, models.Audit.ACTION_READ)
    return FileResponse(io.BytesIO(doc.encrypted_data))

def doc_versions(request):
    path = request.GET.get('path', None)

    if not request.user.can('query', models.Document):
        return FORBIDDEN

    results = models.Document.objects.for_user(request.user).filter(path=path)
    results = results.order_by('-created')
    versions = list(map(models.Document.struct, results))
    return JsonResponse({
        'documents': versions,
    })

def doc_remove_version(request):
    path = request.POST.get('path', None)
    version = request.POST.get('version', None)
    try:
        doc = models.Document.objects.get(path=path, id=version)
    except models.Document.DoesNotExist:
        return JsonResponse({
            'success': False,
            'message': 'Document not found!'
        }, status=400)
    doc.delete()
    return JsonResponse({
        'success': True,
        'id': doc.id,
    })

def doc_destroy(request):
    path = request.POST.get('path', None)
    if not request.user.can('delete', models.Document):
        return FORBIDDEN

    documents = []
    queryset = models.Document.objects.filter(path=path)
    for document in queryset:
        documents.append({
            'id': document.id,
        })
        document.delete()
        
    return JsonResponse({
        'documents': documents,
    })
