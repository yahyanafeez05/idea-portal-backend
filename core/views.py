import json
from django.http import JsonResponse, HttpResponse
from django.views import View
from django.views.decorators.csrf import csrf_exempt
from django.utils.decorators import method_decorator
from django.contrib.auth import authenticate, login, logout, get_user_model
from django.core.validators import validate_email
from django.core.exceptions import ValidationError
from django.utils import timezone
from core.models import AccountType, AuthToken
from core.forms import AccountRegistrationForm, LoginForm

User = get_user_model()


def _extract_request_data(request):
    """
    Extracts payload data from JSON bodies, form submissions, or query params.
    """
    data = {}
    if request.method in ('POST', 'PUT', 'PATCH'):
        content_type = request.content_type or ''
        if 'application/json' in content_type:
            if request.body:
                try:
                    data = json.loads(request.body.decode('utf-8'))
                except (json.JSONDecodeError, UnicodeDecodeError):
                    data = {}
        else:
            data = request.POST.dict()
    elif request.method in ('GET', 'DELETE'):
        data = request.GET.dict()
    return data


def _format_form_errors(form):
    """
    Formats Django form errors into a structured error dictionary.
    """
    formatted = {}
    for field, error_list in form.errors.get_json_data().items():
        formatted[field] = [err['message'] for err in error_list]
    return formatted


class APIView(View):
    """
    Base Class-Based View for REST API endpoints.
    Provides:
      - Automatic CSRF exemption for REST clients.
      - Automatic request data parsing (`request.data`).
      - Token authentication resolution.
      - Explicit HTTP request methods dispatching (`get`, `post`, `options`).
      - JSON-formatted 405 Method Not Allowed handling.
      - Standardized JSON response helpers.
    """

    @method_decorator(csrf_exempt)
    def dispatch(self, request, *args, **kwargs):
        # Attach parsed data to request object
        request.data = _extract_request_data(request)

        # Authenticate via Bearer/Token header if not already authenticated
        if not getattr(request, 'user', None) or not request.user.is_authenticated:
            auth_header = request.headers.get('Authorization') or request.META.get('HTTP_AUTHORIZATION')
            if auth_header:
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

        return super().dispatch(request, *args, **kwargs)

    def http_method_not_allowed(self, request, *args, **kwargs):
        allowed = [m.upper() for m in self._allowed_methods()]
        return JsonResponse({
            'success': False,
            'code': 'METHOD_NOT_ALLOWED',
            'error': f"HTTP request method '{request.method}' is not allowed for this endpoint.",
            'request_method': request.method,
            'allowed_methods': allowed,
        }, status=405)

    def options(self, request, *args, **kwargs):
        """Handle CORS preflight options request."""
        response = HttpResponse()
        origin = request.headers.get('Origin', '*')
        response['Access-Control-Allow-Origin'] = origin
        response['Access-Control-Allow-Methods'] = ', '.join(self._allowed_methods())
        response['Access-Control-Allow-Headers'] = 'Content-Type, Authorization, X-Requested-With, X-CSRFToken, Accept, Origin'
        response['Access-Control-Allow-Credentials'] = 'true'
        response['Access-Control-Max-Age'] = '86400'
        return response


class RegisterAPIView(APIView):
    """
    API endpoint for Screen 1: 'Start with a fresh account'
    
    Supported HTTP Request Methods:
      - POST: Creates a new user account (with strict duplicate prevention).
      - GET:  Returns endpoint documentation and account type choices for frontend forms.
    """

    def post(self, request, *args, **kwargs):
        """
        Request Method: POST
        Accepts:
          - full_name (str)
          - account_type (str: 'Student', 'Faculty', 'Staff', 'Other')
          - department (str)
          - email (str)
          - password (str)
        """
        data = request.data or {}
        form = AccountRegistrationForm(data)

        if not form.is_valid():
            errors = _format_form_errors(form)
            error_data = form.errors.get_json_data()

            # Check if restriction was triggered by existing account
            is_duplicate = False
            if 'email' in error_data:
                for err in error_data['email']:
                    if err.get('code') == 'account_already_exists':
                        is_duplicate = True
                        break

            if is_duplicate:
                return JsonResponse({
                    'success': False,
                    'code': 'ACCOUNT_ALREADY_EXISTS',
                    'message': 'An account with this email address already exists. Please log in instead.',
                    'errors': errors
                }, status=409)

            return JsonResponse({
                'success': False,
                'code': 'VALIDATION_ERROR',
                'message': 'Please fix the errors below.',
                'errors': errors
            }, status=400)

        full_name = form.cleaned_data['full_name']
        account_type = form.cleaned_data['account_type']
        department = form.cleaned_data['department']
        email = form.cleaned_data['email']
        password = form.cleaned_data['password']

        # Extra safety check to restrict duplicate accounts
        if User.objects.filter(email__iexact=email).exists():
            return JsonResponse({
                'success': False,
                'code': 'ACCOUNT_ALREADY_EXISTS',
                'message': 'An account with this email address already exists. Please log in instead.',
                'errors': {'email': ['An account with this email address already exists.']}
            }, status=409)

        # Create user
        user = User.objects.create_user(
            email=email,
            password=password,
            full_name=full_name,
            department=department,
            account_type=account_type
        )

        # Generate API Token
        token = AuthToken.create_for_user(user)

        # Session login
        login(request, user, backend='core.backends.EmailAuthBackend')

        return JsonResponse({
            'success': True,
            'message': 'Account created successfully.',
            'token': token.key,
            'user': user.to_dict()
        }, status=201)

    def get(self, request, *args, **kwargs):
        """
        Request Method: GET
        Returns endpoint schema and available options for frontend forms.
        """
        return JsonResponse({
            'success': True,
            'endpoint': 'Account Registration',
            'supported_methods': ['POST', 'GET', 'OPTIONS'],
            'required_fields': ['full_name', 'department', 'email', 'password'],
            'optional_fields': ['account_type'],
            'account_types': [
                {'value': choice[0], 'label': str(choice[1])}
                for choice in AccountType.choices
            ]
        }, status=200)


class LoginAPIView(APIView):
    """
    API endpoint for Screen 2: 'Welcome back'

    Supported HTTP Request Methods:
      - POST: Authenticates credentials and logs user in.
      - GET:  Returns endpoint documentation.
    """

    def post(self, request, *args, **kwargs):
        """
        Request Method: POST
        Accepts:
          - email (str)
          - password (str)
        """
        data = request.data or {}
        form = LoginForm(data)

        if not form.is_valid():
            return JsonResponse({
                'success': False,
                'code': 'VALIDATION_ERROR',
                'message': 'Please enter a valid email and password.',
                'errors': _format_form_errors(form)
            }, status=400)

        email = form.cleaned_data['email']
        password = form.cleaned_data['password']

        # Authenticate user
        user = authenticate(request, email=email, password=password)

        if user is None:
            # Check if user exists but has been deactivated
            existing_user = User.objects.filter(email__iexact=email).first()
            if existing_user and not existing_user.is_active:
                return JsonResponse({
                    'success': False,
                    'code': 'ACCOUNT_DISABLED',
                    'message': 'This account has been deactivated or disabled. Please contact support.',
                    'errors': {
                        'non_field_errors': ['This account is inactive.']
                    }
                }, status=403)

            return JsonResponse({
                'success': False,
                'code': 'INVALID_CREDENTIALS',
                'message': 'Invalid email or password.',
                'errors': {
                    'non_field_errors': ['Invalid email or password.']
                }
            }, status=401)

        # Login session
        login(request, user, backend='core.backends.EmailAuthBackend')

        # Obtain or generate active token
        token = AuthToken.objects.filter(user=user, is_active=True).first()
        if not token:
            token = AuthToken.create_for_user(user)
        else:
            token.last_used_at = timezone.now()
            token.save(update_fields=['last_used_at'])

        return JsonResponse({
            'success': True,
            'message': 'Logged in successfully.',
            'token': token.key,
            'user': user.to_dict()
        }, status=200)

    def get(self, request, *args, **kwargs):
        """
        Request Method: GET
        Returns endpoint schema.
        """
        return JsonResponse({
            'success': True,
            'endpoint': 'Account Login',
            'supported_methods': ['POST', 'GET', 'OPTIONS'],
            'required_fields': ['email', 'password']
        }, status=200)


class CheckEmailAvailabilityAPIView(APIView):
    """
    API endpoint to check if an email is already registered.
    Allows frontend to enforce account creation restrictions in real-time.

    Supported HTTP Request Methods:
      - GET:  /api/auth/check-email/?email=user@example.com
      - POST: {'email': 'user@example.com'}
    """

    def _check_email(self, email_input):
        if not email_input:
            return JsonResponse({
                'success': False,
                'error': 'Email parameter is required.'
            }, status=400)

        email = email_input.strip().lower()
        try:
            validate_email(email)
        except ValidationError:
            return JsonResponse({
                'success': False,
                'error': 'Invalid email address format.'
            }, status=400)

        exists = User.objects.filter(email__iexact=email).exists()
        return JsonResponse({
            'success': True,
            'email': email,
            'exists': exists,
            'available': not exists,
            'message': 'An account with this email already exists. Please log in instead.' if exists else 'Email is available.'
        }, status=200)

    def get(self, request, *args, **kwargs):
        email = request.GET.get('email', '')
        return self._check_email(email)

    def post(self, request, *args, **kwargs):
        data = request.data or {}
        email = data.get('email', '')
        return self._check_email(email)


class LogoutAPIView(APIView):
    """
    API endpoint for Logout.

    Supported HTTP Request Methods:
      - POST: Logs out user and invalidates tokens.
    """

    def post(self, request, *args, **kwargs):
        if hasattr(request, 'auth') and isinstance(request.auth, AuthToken):
            request.auth.is_active = False
            request.auth.save(update_fields=['is_active'])

        if request.user.is_authenticated:
            AuthToken.objects.filter(user=request.user, is_active=True).update(is_active=False)
            logout(request)

        return JsonResponse({
            'success': True,
            'message': 'Logged out successfully.'
        }, status=200)


class UserProfileAPIView(APIView):
    """
    API endpoint for Current User Profile.

    Supported HTTP Request Methods:
      - GET: Returns the profile of the currently authenticated user.
    """

    def get(self, request, *args, **kwargs):
        if not request.user or not request.user.is_authenticated:
            return JsonResponse({
                'success': False,
                'code': 'UNAUTHORIZED',
                'message': 'Authentication credentials were not provided or are invalid.'
            }, status=401)

        return JsonResponse({
            'success': True,
            'user': request.user.to_dict()
        }, status=200)


class AccountTypesAPIView(APIView):
    """
    API endpoint returning account types for the dropdown.

    Supported HTTP Request Methods:
      - GET: Returns list of choices.
    """

    def get(self, request, *args, **kwargs):
        types = [
            {'value': choice[0], 'label': str(choice[1])}
            for choice in AccountType.choices
        ]
        return JsonResponse({
            'success': True,
            'account_types': types
        }, status=200)


class CsrfTokenAPIView(APIView):
    """
    API endpoint providing CSRF token if needed by browser clients.
    """

    def get(self, request, *args, **kwargs):
        from django.middleware.csrf import get_token
        return JsonResponse({
            'success': True,
            'csrfToken': get_token(request)
        }, status=200)


# Exported View Callables for URL routing
register_view = RegisterAPIView.as_view()
login_view = LoginAPIView.as_view()
logout_view = LogoutAPIView.as_view()
me_view = UserProfileAPIView.as_view()
account_types_view = AccountTypesAPIView.as_view()
check_email_view = CheckEmailAvailabilityAPIView.as_view()
csrf_token_view = CsrfTokenAPIView.as_view()
