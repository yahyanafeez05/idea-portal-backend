from django.http import HttpResponse
from django.utils.deprecation import MiddlewareMixin
from core.models import AuthToken


class CorsMiddleware(MiddlewareMixin):
    """
    Lightweight, dependency-free CORS middleware to allow single-page apps (React, Next.js, Vue)
    and mobile applications to communicate seamlessly with this backend.
    """

    def process_request(self, request):
        if request.method == 'OPTIONS':
            response = HttpResponse()
            origin = request.headers.get('Origin', '*')
            response['Access-Control-Allow-Origin'] = origin
            response['Access-Control-Allow-Methods'] = 'GET, POST, PUT, PATCH, DELETE, OPTIONS'
            response['Access-Control-Allow-Headers'] = 'Content-Type, Authorization, X-Requested-With, X-CSRFToken, Accept, Origin'
            response['Access-Control-Allow-Credentials'] = 'true'
            response['Access-Control-Max-Age'] = '86400'
            return response
        return None

    def process_response(self, request, response):
        origin = request.headers.get('Origin', '*')
        response['Access-Control-Allow-Origin'] = origin
        response['Access-Control-Allow-Methods'] = 'GET, POST, PUT, PATCH, DELETE, OPTIONS'
        response['Access-Control-Allow-Headers'] = 'Content-Type, Authorization, X-Requested-With, X-CSRFToken, Accept, Origin'
        response['Access-Control-Allow-Credentials'] = 'true'
        return response


class TokenAuthMiddleware(MiddlewareMixin):
    """
    Middleware that parses 'Authorization: Bearer <key>' or 'Authorization: Token <key>'
    and attaches the authenticated User object to request.user.
    """

    def process_request(self, request):
        auth_header = request.headers.get('Authorization') or request.META.get('HTTP_AUTHORIZATION')
        if not auth_header:
            return None

        parts = auth_header.strip().split()
        if len(parts) == 2 and parts[0].lower() in ('bearer', 'token'):
            token_key = parts[1]
            try:
                token = AuthToken.objects.select_related('user').get(key=token_key, is_active=True)
                if token.user.is_active:
                    request.user = token.user
                    request.auth = token
            except AuthToken.DoesNotExist:
                pass
        return None
