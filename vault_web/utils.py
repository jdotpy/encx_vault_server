from django.http import JsonResponse
import hashlib 

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

def hasher(text):
    message = hashlib.sha256()
    message.update(text.encode('utf-8'))
    return message.hexdigest()
