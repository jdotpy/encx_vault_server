from django.http import JsonResponse

NOT_AUTHED = JsonResponse({
    'success': False,
    'message': 'Not Authenticated',
}, status=401)

FORBIDDEN = JsonResponse({
    'success': False,
    'message': 'You are not authorized to do this operation.',
}, status=403)

AUTH_FAILED = JsonResponse({
    'success': False,
    'message': 'Bad Credentials',
}, status=403)
