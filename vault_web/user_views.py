from django.http import JsonResponse
from .utils  import FORBIDDEN
from . import models

def user_new(request):
    if not request.user.can('create', models.User):
        return FORBIDDEN

    user_name = request.POST.get('user_name', None)
    is_admin = request.POST.get('is_admin', '') == 'True'

    # Ensure we don't replace existing user
    if models.User.objects.filter(user_name=user_name).exists():
        return JsonResponse({
            'success': False,
            'message': 'User already exists',
        }, status=403)
        
    # Make new one with starting token for initializing
    user, token = models.User.objects.new(
        user_name=user_name,
        is_admin=is_admin,
    )
    return JsonResponse({
        'success': True,
        'user_name': user.user_name,
        'token': token,
    })

def user_get(request):
    if not request.user.can('read', models.User):
        return FORBIDDEN
    user_name = request.GET.get('user_name', None)

    try:
        user = models.User.objects.get(user_name=user_name)
    except models.User.DoesNotExist:
        return JsonResponse({
            'success': False,
            'message': 'User doesnt exists',
        }, status=403)
        
    return JsonResponse({
        'success': True,
        'user': user.struct(),
    })

def user_init(request):
    if request.user.initialized:
        return JsonResponse({
            'success': False,
            'message': 'A User cannot be re-initialized',
        }, status=403)

    public_key = request.POST.get('public_key', None)
    name = request.POST.get('name', None)

    print('Got name:', name)

    request.user.public_key = public_key
    request.user.name = name
    new_token = request.user.regen_token()
    request.user.initialized = True
    request.user.save()
    return JsonResponse({
        'success': True,
        'token': new_token,
        'public_key': public_key,
        'name': name,
    })
