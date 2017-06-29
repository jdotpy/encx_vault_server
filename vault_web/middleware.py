from .models import User
from .utils import NOT_AUTHED, FORBIDDEN, AUTH_FAILED

def make_vault_auth_middleware(get_response):
    def vault_auth_middleware(request):
        user_name = request.META.get('HTTP_X_VAULT_USER', None)
        token = request.META.get('HTTP_X_VAULT_TOKEN', None)
        if not token or not user_name:
            return NOT_AUTHED

        try:
            user = User.objects.get(user_name=user_name)
        except User.DoesNotExist as e:
            user = None
            return AUTH_FAILED

        if not user.check_token(token):
           return AUTH_FAILED

        request.user = user
        return get_response(request)
    return vault_auth_middleware
