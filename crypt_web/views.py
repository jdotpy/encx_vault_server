from django.http import JsonResponse

def ping(request):
    return JsonResponse({
        'message': 'pong',
        'user': {
            'user_name': request.user.user_name,
            'public_key': request.user.public_key,
            'is_admin': request.user.is_admin,
        },
    })
