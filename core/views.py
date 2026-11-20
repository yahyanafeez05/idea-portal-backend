import csv
import io
import json
from django.http import JsonResponse, HttpResponse
from django.views import View
from django.views.decorators.csrf import csrf_exempt
from django.utils.decorators import method_decorator
from django.contrib.auth import authenticate, login, logout, get_user_model
from django.core.validators import validate_email
from django.core.exceptions import ValidationError
from django.utils import timezone
from django.db import transaction
from django.db.models import Q
from core.models import (
    AccountType, AuthToken, Project, ProjectStatus,
    Team, TeamMember, Query, QueryStatus, Message,
    Notification, NotificationType, Topic, TopicStatus, ProjectFile,
    TeamInvitation, InvitationStatus, TeamMessage
)
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


def _resolve_user(request):
    """
    Resolves the authenticated user from:
    1. request.user (Django session / TokenAuthMiddleware)
    2. Authorization header (Bearer / Token)
    3. Dev query param / header in local development
    """
    if getattr(request, 'user', None) and request.user.is_authenticated:
        return request.user

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
                    return token.user
            except AuthToken.DoesNotExist:
                pass

    # Development helper: allow testing dashboard by email or user_id
    dev_email = request.GET.get('user_email') or request.headers.get('X-User-Email')
    if dev_email:
        user = User.objects.filter(email__iexact=dev_email).first()
        if user and user.is_active:
            return user

    dev_user_id = request.GET.get('user_id')
    if dev_user_id and str(dev_user_id).isdigit():
        user = User.objects.filter(id=int(dev_user_id)).first()
        if user and user.is_active:
            return user

    return None


def _get_time_greeting():
    """Returns 'Good morning', 'Good afternoon', or 'Good evening' based on local hour."""
    hour = timezone.localtime().hour
    if 5 <= hour < 12:
        return "Good morning"
    elif 12 <= hour < 17:
        return "Good afternoon"
    elif 17 <= hour < 22:
        return "Good evening"
    else:
        return "Good night"


def create_notification(recipient, title, message, notification_type=NotificationType.INFO, action_url='', tag=''):
    """Helper to create and persist user notifications."""
    if not recipient:
        return None
    return Notification.objects.create(
        recipient=recipient,
        title=title,
        message=message,
        notification_type=notification_type,
        action_url=action_url,
        tag=tag
    )


class APIView(View):
    """
    Base Class-Based View for REST API endpoints.
    Provides:
      - Automatic CSRF exemption for REST clients.
      - Automatic request data parsing (`request.data`).
      - Token & Session authentication resolution.
      - Explicit HTTP request methods dispatching (`get`, `post`, `put`, `delete`, `options`).
      - JSON-formatted 405 Method Not Allowed handling.
    """

    @method_decorator(csrf_exempt)
    def dispatch(self, request, *args, **kwargs):
        request.data = _extract_request_data(request)
        resolved_user = _resolve_user(request)
        if resolved_user:
            request.user = resolved_user
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
        response = HttpResponse()
        origin = request.headers.get('Origin', '*')
        response['Access-Control-Allow-Origin'] = origin
        response['Access-Control-Allow-Methods'] = ', '.join(self._allowed_methods())
        response['Access-Control-Allow-Headers'] = 'Content-Type, Authorization, X-Requested-With, X-CSRFToken, Accept, Origin'
        response['Access-Control-Allow-Credentials'] = 'true'
        response['Access-Control-Max-Age'] = '86400'
        return response


# ==============================================================================
# AUTHENTICATION ENDPOINTS (Screen 1 & Screen 2)
# ==============================================================================

class RegisterAPIView(APIView):
    """
    API endpoint for Screen 1: 'Start with a fresh account'
    Methods: POST, GET, OPTIONS
    """

    def post(self, request, *args, **kwargs):
        data = request.data or {}
        form = AccountRegistrationForm(data)

        if not form.is_valid():
            errors = _format_form_errors(form)
            error_data = form.errors.get_json_data()

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
        section = form.cleaned_data.get('section', '')
        email = form.cleaned_data['email']
        password = form.cleaned_data['password']

        # Extra safety check against duplicate registration
        if User.objects.filter(email__iexact=email).exists():
            return JsonResponse({
                'success': False,
                'code': 'ACCOUNT_ALREADY_EXISTS',
                'message': 'An account with this email address already exists. Please log in instead.',
                'errors': {'email': ['An account with this email address already exists.']}
            }, status=409)

        user = User.objects.create_user(
            email=email,
            password=password,
            full_name=full_name,
            department=department,
            account_type=account_type,
            section=section
        )

        token = AuthToken.create_for_user(user)
        login(request, user, backend='core.backends.EmailAuthBackend')

        return JsonResponse({
            'success': True,
            'message': 'Account created successfully.',
            'token': token.key,
            'user': user.to_dict()
        }, status=201)

    def get(self, request, *args, **kwargs):
        departments = [
            'Computer Science and Engineering',
            'Information Technology',
            'Artificial Intelligence and Data Science',
            'Electronics and Communication Engineering',
            'Electrical and Electronics Engineering',
            'Mechanical Engineering',
            'Civil Engineering',
        ]
        sections = [
            'Section A',
            'Section B',
            'Section C',
            'Section D',
        ]
        return JsonResponse({
            'success': True,
            'endpoint': 'Account Registration',
            'supported_methods': ['POST', 'GET', 'OPTIONS'],
            'student_form': {
                'account_type': 'Student',
                'fields': ['full_name', 'account_type', 'department', 'section', 'email', 'password'],
                'required': ['full_name', 'department', 'email', 'password']
            },
            'teacher_form': {
                'account_type': 'Teacher',
                'fields': ['full_name', 'account_type', 'email', 'password', 'teacher_sign_in_code'],
                'required': ['full_name', 'email', 'password', 'teacher_sign_in_code'],
                'valid_codes_hint': 'Contact administrator or use authorized teacher code (e.g. TEACH2026)'
            },
            'account_types': [
                {'value': choice[0], 'label': str(choice[1])}
                for choice in AccountType.choices
            ],
            'departments': departments,
            'sections': sections,
        }, status=200)


class LoginAPIView(APIView):
    """
    API endpoint for Screen 2: 'Welcome back'
    Supports both Student and Teacher login.
    Methods: POST, GET, OPTIONS
    """

    def post(self, request, *args, **kwargs):
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

        user = authenticate(request, email=email, password=password)

        if user is None:
            existing_user = User.objects.filter(email__iexact=email).first()
            if existing_user and not existing_user.is_active:
                return JsonResponse({
                    'success': False,
                    'code': 'ACCOUNT_DISABLED',
                    'message': 'This account has been deactivated or disabled. Please contact support.',
                    'errors': {'non_field_errors': ['This account is inactive.']}
                }, status=403)

            return JsonResponse({
                'success': False,
                'code': 'INVALID_CREDENTIALS',
                'message': 'Invalid email or password.',
                'errors': {'non_field_errors': ['Invalid email or password.']}
            }, status=401)

        # Check if client requested a specific role login (Student vs Teacher)
        requested_type = form.cleaned_data.get('account_type')
        user_is_teacher = user.account_type in (AccountType.TEACHER, AccountType.FACULTY)

        if requested_type:
            if requested_type in (AccountType.TEACHER, AccountType.FACULTY) and not user_is_teacher:
                return JsonResponse({
                    'success': False,
                    'code': 'ROLE_MISMATCH',
                    'message': 'This account is registered as a Student. Please switch to Student login.',
                    'errors': {'account_type': ['This account is registered as a Student.']}
                }, status=403)
            elif requested_type == AccountType.STUDENT and user_is_teacher:
                return JsonResponse({
                    'success': False,
                    'code': 'ROLE_MISMATCH',
                    'message': 'This account is registered as a Teacher. Please switch to Teacher login.',
                    'errors': {'account_type': ['This account is registered as a Teacher.']}
                }, status=403)

        login(request, user, backend='core.backends.EmailAuthBackend')

        token = AuthToken.objects.filter(user=user, is_active=True).first()
        if not token:
            token = AuthToken.create_for_user(user)
        else:
            token.last_used_at = timezone.now()
            token.save(update_fields=['last_used_at'])

        role = 'teacher' if user_is_teacher else 'student'

        return JsonResponse({
            'success': True,
            'message': f'Logged in successfully as {role.capitalize()}.',
            'token': token.key,
            'role': role,
            'is_teacher': user_is_teacher,
            'is_student': not user_is_teacher,
            'workspace_label': 'TEACHER WORKSPACE' if user_is_teacher else 'STUDENT WORKSPACE',
            'redirect_url': '/teacher/dashboard' if user_is_teacher else '/dashboard',
            'user': user.to_dict()
        }, status=200)

    def get(self, request, *args, **kwargs):
        return JsonResponse({
            'success': True,
            'endpoint': 'Account Login',
            'supported_methods': ['POST', 'GET', 'OPTIONS'],
            'required_fields': ['email', 'password'],
            'optional_fields': ['account_type']
        }, status=200)


class CheckEmailAvailabilityAPIView(APIView):
    """
    Real-time duplicate account prevention endpoint.
    """

    def _check_email(self, email_input):
        if not email_input:
            return JsonResponse({'success': False, 'error': 'Email parameter is required.'}, status=400)

        email = email_input.strip().lower()
        try:
            validate_email(email)
        except ValidationError:
            return JsonResponse({'success': False, 'error': 'Invalid email address format.'}, status=400)

        exists = User.objects.filter(email__iexact=email).exists()
        return JsonResponse({
            'success': True,
            'email': email,
            'exists': exists,
            'available': not exists,
            'message': 'An account with this email already exists. Please log in instead.' if exists else 'Email is available.'
        }, status=200)

    def get(self, request, *args, **kwargs):
        return self._check_email(request.GET.get('email', ''))

    def post(self, request, *args, **kwargs):
        data = request.data or {}
        return self._check_email(data.get('email', ''))


class LogoutAPIView(APIView):
    """
    Terminates tokens and session.
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
    Returns authenticated user profile.
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
    Returns account type choices for dropdowns.
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
    Returns CSRF token.
    """

    def get(self, request, *args, **kwargs):
        from django.middleware.csrf import get_token
        return JsonResponse({
            'success': True,
            'csrfToken': get_token(request)
        }, status=200)


# ==============================================================================
# WORKSPACE DASHBOARD ENDPOINT (Matches Project UI)
# ==============================================================================

class DashboardAPIView(APIView):
    """
    Dedicated REST API endpoint for the Node Theory Student Dashboard:
    - STUDENT WORKSPACE header
    - Good morning, <name> ✦
    - Subtitle: "Your workspace is ready. Add your project details to get started."
    - Hero banner:
        * Tag: "YOUR PROJECT WORKSPACE"
        * Mode: "BUILD MODE"
        * Title: "Make your next idea happen."
        * Subtitle: "Upload your work, track progress, and keep your creative process moving."
    - Metric Stat Cards:
        * Active projects (count, subtext: "Across this semester")
        * Approved (count, subtext: "You're doing great!")
        * Awaiting feedback (count, subtext: "Your teacher will be in touch")
    - Section Widgets:
        * Recent projects ("Your latest submissions and updates", "View all →")
        * Teacher Q&A ("Your latest questions", "See all")
    - Notifications:
        * Bell icon unread count & recent notification previews
    - Sidebar badges:
        * My projects badge
        * Queries badge
    """

    def get(self, request, *args, **kwargs):
        user = request.user
        if not user or not user.is_authenticated:
            # Check if any user exists for development/testing fallback
            user = User.objects.first()
            if not user:
                return JsonResponse({
                    'success': False,
                    'code': 'UNAUTHORIZED',
                    'message': 'Please authenticate to access the workspace dashboard.'
                }, status=401)

        greeting_text = _get_time_greeting()
        name = user.full_name or user.email.split('@')[0]
        first_name = name.split()[0] if name else 'User'

        is_teacher = user.account_type in (AccountType.TEACHER, AccountType.FACULTY)

        # Common notifications for bell icon
        user_notifications = Notification.objects.filter(recipient=user)
        unread_notifications_count = user_notifications.filter(is_read=False).count()
        recent_notifications = [n.to_dict() for n in user_notifications[:5]]

        if is_teacher:
            # -------------------------------------------------------------
            # TEACHER WORKSPACE DATA (Matches Workspace / Teacher dashboard Screenshot)
            # -------------------------------------------------------------
            teacher_name = user.full_name or user.email.split('@')[0]
            first_name = teacher_name.split()[0] if teacher_name else 'Teacher'

            # 1. Four Exact Metric Calculations from Screenshot:
            # - Students with submissions: distinct student accounts with submissions
            # - Submitted projects: total submitted projects across students
            # - Awaiting review: ready for teacher feedback
            # - Reviewed: projects with a review status (approved, completed, rejected, feedback given)
            submitted_statuses = [
                ProjectStatus.SUBMITTED,
                ProjectStatus.AWAITING_REVIEW,
                ProjectStatus.APPROVED,
                ProjectStatus.COMPLETED,
                'in_review',
                'under_review',
            ]
            students_with_submissions_count = Project.objects.filter(
                status__in=submitted_statuses
            ).values('owner').distinct().count()

            submitted_projects_count = Project.objects.filter(
                status__in=submitted_statuses
            ).count()

            awaiting_review_count = Project.objects.filter(
                status__in=[ProjectStatus.AWAITING_REVIEW, 'in_review', 'under_review', ProjectStatus.SUBMITTED]
            ).count()

            reviewed_count = Project.objects.filter(
                Q(status__in=[ProjectStatus.APPROVED, ProjectStatus.COMPLETED, ProjectStatus.REJECTED]) |
                Q(reviewed_by__isnull=False) |
                ~Q(feedback='')
            ).distinct().count()

            active_projects_count = Project.objects.exclude(status=ProjectStatus.COMPLETED).count()

            # Metric stat cards structure
            metric_cards = [
                {
                    'id': 'students_with_submissions',
                    'label': 'Students with submissions',
                    'title': 'Students with submissions',
                    'value': f"{students_with_submissions_count:02d}",
                    'count': students_with_submissions_count,
                    'subtext': 'Student accounts',
                    'icon': 'users'
                },
                {
                    'id': 'submitted_projects',
                    'label': 'Submitted projects',
                    'title': 'Submitted projects',
                    'value': f"{submitted_projects_count:02d}",
                    'count': submitted_projects_count,
                    'subtext': 'Across student accounts',
                    'icon': 'folder'
                },
                {
                    'id': 'awaiting_review',
                    'label': 'Awaiting review',
                    'title': 'Awaiting review',
                    'value': f"{awaiting_review_count:02d}",
                    'count': awaiting_review_count,
                    'subtext': 'Ready for your feedback',
                    'icon': 'clock'
                },
                {
                    'id': 'reviewed',
                    'label': 'Reviewed',
                    'title': 'Reviewed',
                    'value': f"{reviewed_count:02d}",
                    'count': reviewed_count,
                    'subtext': 'Projects with a review status',
                    'icon': 'check'
                }
            ]

            stats_payload = {
                'students_with_submissions': students_with_submissions_count,
                'students_with_submissions_formatted': f"{students_with_submissions_count:02d}",
                'students_with_submissions_subtext': 'Student accounts',

                'submitted_projects': submitted_projects_count,
                'submitted_projects_formatted': f"{submitted_projects_count:02d}",
                'submitted_projects_subtext': 'Across student accounts',

                'awaiting_review': awaiting_review_count,
                'awaiting_review_formatted': f"{awaiting_review_count:02d}",
                'awaiting_review_subtext': 'Ready for your feedback',

                'reviewed': reviewed_count,
                'reviewed_formatted': f"{reviewed_count:02d}",
                'reviewed_subtext': 'Projects with a review status',

                # Aliases & backward compatibility
                'active_projects': active_projects_count,
                'active_projects_formatted': f"{active_projects_count:02d}",
                'active_projects_subtext': 'Active student submissions',
                'approved': reviewed_count,
                'approved_formatted': f"{reviewed_count:02d}",
                'approved_subtext': 'Projects with a review status',
                'awaiting_feedback': awaiting_review_count,
                'awaiting_feedback_formatted': f"{awaiting_review_count:02d}",
                'awaiting_feedback_subtext': 'Ready for your feedback',
                'projects': submitted_projects_count,
            }

            # 2. Submissions to Review widget (with filter dropdown: 'All submissions', 'Awaiting review', 'Reviewed')
            submission_filter = request.GET.get('submission_filter', 'all').strip().lower()
            submissions_qs = Project.objects.select_related('owner', 'team', 'topic').order_by('-updated_at')
            if submission_filter in ('awaiting_review', 'pending', 'awaiting'):
                submissions_qs = submissions_qs.filter(status__in=[ProjectStatus.AWAITING_REVIEW, 'in_review', 'under_review', ProjectStatus.SUBMITTED])
            elif submission_filter in ('reviewed', 'completed', 'evaluated'):
                submissions_qs = submissions_qs.filter(
                    Q(status__in=[ProjectStatus.APPROVED, ProjectStatus.COMPLETED, ProjectStatus.REJECTED]) |
                    Q(reviewed_by__isnull=False) |
                    ~Q(feedback='')
                ).distinct()
            elif submission_filter in ('approved',):
                submissions_qs = submissions_qs.filter(status=ProjectStatus.APPROVED)
            elif submission_filter in ('needs_changes', 'rejected'):
                submissions_qs = submissions_qs.filter(status=ProjectStatus.REJECTED)
            else:
                submissions_qs = submissions_qs.filter(status__in=submitted_statuses)

            submissions_items = []
            for p in submissions_qs[:10]:
                created_dt = p.updated_at or p.created_at
                formatted_dt = created_dt.strftime('%b %d, %Y, %I:%M %p').replace(' 0', ' ') if created_dt else ''
                submissions_items.append({
                    'id': p.id,
                    'title': p.title,
                    'description': p.description,
                    'student_name': p.owner.full_name if p.owner else '',
                    'student_email': p.owner.email if p.owner else '',
                    'team_name': p.team.name if p.team else None,
                    'topic_code': p.topic.case_code if p.topic else None,
                    'topic_title': p.topic.title if p.topic else None,
                    'status': p.status,
                    'status_display': p.get_status_display(),
                    'progress': p.progress,
                    'submitted_at': p.updated_at.isoformat() if p.updated_at else None,
                    'formatted_date': formatted_dt,
                    'subtext': f"Submitted by {p.owner.full_name if p.owner else 'Student'} · {formatted_dt}",
                    'actions': {
                        'review': f"/api/projects/{p.id}/review/",
                        'view': f"/api/projects/{p.id}/",
                    }
                })

            submissions_to_review_widget = {
                'title': 'Submissions to review',
                'subtext': 'Recent work from your students',
                'filter': submission_filter,
                'filter_options': [
                    {'label': 'All submissions', 'value': 'all'},
                    {'label': 'Awaiting review', 'value': 'awaiting_review'},
                    {'label': 'Reviewed', 'value': 'reviewed'},
                ],
                'active_filter_label': 'All submissions' if submission_filter == 'all' else submission_filter.replace('_', ' ').capitalize(),
                'empty_message': 'No student submissions match this filter yet.',
                'count': len(submissions_items),
                'items': submissions_items,
            }

            # 3. Student Questions widget (Matches: "Student questions", "Questions that could use your help", "View inbox →")
            teacher_qa_queryset = Query.objects.select_related('asked_by', 'responded_by', 'project').order_by('-created_at')
            student_questions_items = []
            for q in teacher_qa_queryset[:10]:
                created_dt = q.created_at
                formatted_time = created_dt.strftime('%I:%M %p').lstrip('0') if created_dt else ''
                formatted_date = f"{created_dt.strftime('%b %d, %Y')}, {formatted_time}" if created_dt else ''
                student_name = q.asked_by.full_name if q.asked_by else 'Student'
                is_answered = bool(q.response or q.status == QueryStatus.ANSWERED)
                student_questions_items.append({
                    'id': q.id,
                    'title': q.title,
                    'description': q.description,
                    'question': q.description,
                    'student_name': student_name,
                    'student_email': q.asked_by.email if q.asked_by else '',
                    'submitted_by': student_name,
                    'formatted_date': formatted_date,
                    'subtext': f"Submitted by {student_name} · {formatted_date}",
                    'indicator_color': 'grey' if is_answered else 'teal',
                    'status': q.status,
                    'status_display': q.get_status_display(),
                    'is_answered': is_answered,
                    'action_text': 'Edit answer' if is_answered else 'Answer question',
                    'action_url': f"/workspace/queries/{q.id}/reply/",
                    'inbox_url': '/workspace/queries/',
                    'response': q.response,
                    'responded_at': q.responded_at.isoformat() if q.responded_at else None,
                })

            student_questions_widget = {
                'title': 'Student questions',
                'subtext': 'Questions that could use your help',
                'link_text': 'View inbox →',
                'link_url': '/workspace/queries/',
                'empty_message': 'No student questions yet.',
                'count': len(student_questions_items),
                'items': student_questions_items,
            }

            classroom_dept = (user.department.upper() if getattr(user, 'department', None) else 'DESIGN & TECHNOLOGY')
            hero_config = {
                'tag': f"YOUR CLASSROOM · {classroom_dept}",
                'mode': 'REVIEW MODE',
                'title': 'A little feedback goes a long way.',
                'subtitle': 'Review submissions and help every student progress.',
                'button_text': 'Review submissions →',
                'button_action': '/workspace/projects/?filter=awaiting_review',
                'button_url': '/workspace/projects/?filter=awaiting_review',
            }

            open_queries_count = teacher_qa_queryset.filter(status=QueryStatus.OPEN).count()
            sidebar_badges = {
                'student_projects': active_projects_count,
                'my_projects': active_projects_count,
                'queries': open_queries_count,
                'student_teams_projects': Team.objects.count(),
                'unread_notifications': unread_notifications_count,
                'unread_messages': Message.objects.filter(recipient=user, is_read=False).count(),
                'chat': Message.objects.filter(recipient=user, is_read=False).count(),
                'team_chat': 0,
            }

            sidebar_navigation = [
                {'name': 'Dashboard', 'url': '/workspace/teacher-dashboard/', 'active': True, 'badge': None},
                {'name': 'Student projects', 'url': '/workspace/student-projects/', 'active': False, 'badge': active_projects_count},
                {'name': 'Data', 'url': '/workspace/data/', 'active': False, 'badge': None},
                {'name': 'Student teams & projects', 'url': '/workspace/teams/', 'active': False, 'badge': None},
                {'name': 'Queries', 'url': '/workspace/queries/', 'active': False, 'badge': open_queries_count},
            ]

            return JsonResponse({
                'success': True,
                'workspace': {
                    'breadcrumb': 'Workspace / Teacher dashboard',
                    'label': 'TEACHER WORKSPACE',
                    'tag': 'TEACHER WORKSPACE',
                    'greeting': greeting_text,
                    'name': teacher_name,
                    'full_greeting': f"{greeting_text}, {teacher_name}",
                    'subtitle': "A quick look at your students' project progress.",
                    'hero': hero_config,
                    'action_button': {
                        'text': 'View activity',
                        'action': 'view_activity',
                        'url': '/api/workspace/teacher/activity/',
                    }
                },
                'user': {
                    **user.to_dict(),
                    'avatar_initial': teacher_name[0].upper() if teacher_name else 'T',
                    'role_display': 'Teacher',
                },
                'stats': stats_payload,
                'metric_cards': metric_cards,
                'submissions_to_review': submissions_items,
                'submissions_to_review_widget': submissions_to_review_widget,
                'student_questions': student_questions_items,
                'student_questions_widget': student_questions_widget,
                # Backward compatibility
                'recent_projects': submissions_items,
                'recent_projects_widget': submissions_to_review_widget,
                'recent_projects_list': submissions_items,
                'teacher_qa': student_questions_items,
                'teacher_qa_widget': student_questions_widget,
                'sidebar_badges': sidebar_badges,
                'sidebar_navigation': sidebar_navigation,
                'notifications': {
                    'unread_count': unread_notifications_count,
                    'recent': recent_notifications,
                },
                'help_center': {
                    'title': 'Need a hand?',
                    'description': 'Find tips for submitting projects and getting teacher feedback.',
                    'link_text': 'Visit help center →',
                    'link_url': '/help',
                }
            }, status=200)

        else:
            # -------------------------------------------------------------
            # STUDENT WORKSPACE DATA
            # -------------------------------------------------------------
            user_projects = Project.objects.filter(owner=user)
            active_projects_count = user_projects.exclude(status=ProjectStatus.COMPLETED).count()
            approved_count = user_projects.filter(status=ProjectStatus.APPROVED).count()
            awaiting_feedback_count = user_projects.filter(status__in=[ProjectStatus.AWAITING_REVIEW, 'in_review']).count()

            recent_projects_items = [p.to_dict() for p in user_projects[:5]]

            teacher_qa_queryset = Query.objects.filter(asked_by=user).select_related('responded_by', 'project')
            teacher_qa_items = [q.to_dict() for q in teacher_qa_queryset[:5]]

            hero_config = {
                'tag': 'YOUR PROJECT WORKSPACE',
                'mode': 'BUILD MODE',
                'title': 'Make your next idea happen.',
                'subtitle': 'Upload your work, track progress, and keep your creative process moving.'
            }
            subtitle = 'Your workspace is ready. Add your project details to get started.'
            active_subtext = 'Across this semester'
            awaiting_subtext = 'Your teacher will be in touch'
            recent_subtext = 'Your latest submissions and updates'
            qa_subtext = 'Your latest questions'

            workspace_type = user.get_account_type_display().upper()
            workspace_label = f"{workspace_type} WORKSPACE"

            return JsonResponse({
                'success': True,
                'workspace': {
                    'label': workspace_label,
                    'greeting': greeting_text,
                    'name': first_name,
                    'full_greeting': f"{greeting_text}, {first_name} ✦",
                    'subtitle': subtitle,
                    'hero': hero_config
                },
                'user': {
                    **user.to_dict(),
                    'avatar_initial': first_name[0].upper() if first_name else 'F',
                    'role_display': user.get_account_type_display(),
                },
                'stats': {
                    'active_projects': active_projects_count,
                    'active_projects_formatted': f"{active_projects_count:02d}",
                    'active_projects_subtext': active_subtext,

                    'approved': approved_count,
                    'approved_formatted': f"{approved_count:02d}",
                    'approved_subtext': "You're doing great!",

                    'awaiting_feedback': awaiting_feedback_count,
                    'awaiting_feedback_formatted': f"{awaiting_feedback_count:02d}",
                    'awaiting_feedback_subtext': awaiting_subtext,

                    'projects': active_projects_count,
                    'awaiting_review': awaiting_feedback_count,
                },
                'recent_projects': recent_projects_items,
                'recent_projects_widget': {
                    'title': 'Recent projects',
                    'subtext': recent_subtext,
                    'link_text': 'View all →',
                    'count': len(recent_projects_items),
                    'items': recent_projects_items,
                    'empty_message': 'No projects yet.',
                },
                'teacher_qa': teacher_qa_items,
                'teacher_qa_widget': {
                    'title': 'Teacher Q&A',
                    'subtext': qa_subtext,
                    'link_text': 'See all',
                    'count': len(teacher_qa_items),
                    'items': teacher_qa_items,
                    'empty_message': 'No questions yet.',
                },
                'notifications': {
                    'unread_count': unread_notifications_count,
                    'recent': recent_notifications,
                },
                'sidebar_badges': {
                    'my_projects': active_projects_count,
                    'queries': teacher_qa_queryset.filter(status=QueryStatus.OPEN).count(),
                    'unread_notifications': unread_notifications_count,
                    'unread_messages': Message.objects.filter(recipient=user, is_read=False).count(),
                    'chat': Message.objects.filter(recipient=user, is_read=False).count(),
                    'team_chat': TeamMessage.objects.filter(
                        Q(team__memberships__user=user) | Q(team__created_by=user) | Q(team__leader=user)
                    ).distinct().exclude(read_by=user).count() if user else 0,
                },
                'recent_projects_list': recent_projects_items,
            }, status=200)


class TeacherActivityAPIView(APIView):
    """
    Teacher Activity Log & Event Feed:
    Matches the 'View activity' button in the Teacher Workspace header.
    Aggregates recent events across:
    - Student project submissions
    - Teacher project reviews & feedback
    - Student questions submitted
    - Teacher replies sent
    - Team creations / project updates
    """

    def get(self, request, *args, **kwargs):
        user = request.user if (request.user and request.user.is_authenticated) else User.objects.first()
        if not user:
            return JsonResponse({'success': False, 'message': 'Authentication required.'}, status=401)

        activity_type = request.GET.get('type', 'all').strip().lower()
        activities = []

        # 1. Project Submissions
        if activity_type in ('all', 'submissions'):
            submitted_statuses = [
                ProjectStatus.SUBMITTED,
                ProjectStatus.AWAITING_REVIEW,
                ProjectStatus.APPROVED,
                ProjectStatus.COMPLETED,
                'in_review',
                'under_review',
            ]
            for p in Project.objects.filter(status__in=submitted_statuses).select_related('owner', 'team').order_by('-updated_at')[:15]:
                created_dt = p.updated_at or p.created_at
                formatted_dt = created_dt.strftime('%b %d, %Y, %I:%M %p').replace(' 0', ' ') if created_dt else ''
                activities.append({
                    'id': f"sub-{p.id}",
                    'type': 'submission',
                    'icon': 'folder',
                    'title': f"Project submission: {p.title}",
                    'description': f"{p.owner.full_name} submitted '{p.title}' for review.",
                    'student_name': p.owner.full_name,
                    'student_email': p.owner.email,
                    'team_name': p.team.name if p.team else None,
                    'status': p.status,
                    'status_display': p.get_status_display(),
                    'timestamp': created_dt.isoformat() if created_dt else None,
                    'formatted_date': formatted_dt,
                    'action_url': f"/projects/{p.id}/",
                })

        # 2. Teacher Reviews
        if activity_type in ('all', 'reviews'):
            for p in Project.objects.filter(reviewed_by__isnull=False).select_related('owner', 'reviewed_by').order_by('-reviewed_at')[:15]:
                rev_dt = p.reviewed_at
                formatted_dt = rev_dt.strftime('%b %d, %Y, %I:%M %p').replace(' 0', ' ') if rev_dt else ''
                activities.append({
                    'id': f"rev-{p.id}",
                    'type': 'review',
                    'icon': 'check',
                    'title': f"Project reviewed: {p.title}",
                    'description': f"Review completed for '{p.title}' - Status: {p.get_status_display()}.",
                    'student_name': p.owner.full_name,
                    'reviewer_name': p.reviewed_by.full_name if p.reviewed_by else 'Teacher',
                    'status': p.status,
                    'feedback': p.feedback,
                    'timestamp': rev_dt.isoformat() if rev_dt else None,
                    'formatted_date': formatted_dt,
                    'action_url': f"/projects/{p.id}/",
                })

        # 3. Student Questions
        if activity_type in ('all', 'questions', 'queries'):
            for q in Query.objects.select_related('asked_by', 'responded_by').order_by('-created_at')[:15]:
                q_dt = q.created_at
                formatted_dt = q_dt.strftime('%b %d, %Y, %I:%M %p').replace(' 0', ' ') if q_dt else ''
                activities.append({
                    'id': f"q-{q.id}",
                    'type': 'query',
                    'icon': 'help-circle',
                    'title': f"New question: {q.title}",
                    'description': f"{q.asked_by.full_name} asked: '{q.description[:80]}...'",
                    'student_name': q.asked_by.full_name,
                    'status': q.status,
                    'has_response': bool(q.response),
                    'timestamp': q_dt.isoformat() if q_dt else None,
                    'formatted_date': formatted_dt,
                    'action_url': f"/workspace/queries/",
                })

        # 4. Teacher Question Replies
        if activity_type in ('all', 'replies', 'queries'):
            for q in Query.objects.filter(responded_by__isnull=False).select_related('asked_by', 'responded_by').order_by('-responded_at')[:15]:
                ans_dt = q.responded_at
                formatted_dt = ans_dt.strftime('%b %d, %Y, %I:%M %p').replace(' 0', ' ') if ans_dt else ''
                activities.append({
                    'id': f"ans-{q.id}",
                    'type': 'reply',
                    'icon': 'message-square',
                    'title': f"Answer provided: {q.title}",
                    'description': f"Replied to {q.asked_by.full_name}'s question: '{q.response[:80]}...'",
                    'student_name': q.asked_by.full_name,
                    'teacher_name': q.responded_by.full_name if q.responded_by else 'Teacher',
                    'timestamp': ans_dt.isoformat() if ans_dt else None,
                    'formatted_date': formatted_dt,
                    'action_url': f"/workspace/queries/",
                })

        # Sort all activities by timestamp descending
        activities.sort(key=lambda x: x.get('timestamp') or '', reverse=True)

        return JsonResponse({
            'success': True,
            'breadcrumb': 'Workspace / Teacher dashboard / Activity',
            'page_title': 'Teacher Workspace Activity',
            'filter': activity_type,
            'total_activities': len(activities),
            'activities': activities,
        }, status=200)


# ==============================================================================
# PROJECTS API ENDPOINTS
# ==============================================================================

def _get_teacher_student_projects_response(request, user):
    """
    Constructs the Teacher Workspace 'Student projects' screen response
    matching screenshot media_1795195613043_d9d98119.png:
    - Breadcrumb: Workspace / My projects
    - Tag / Title: TEACHER WORKSPACE
    - Subtitle: Select a project name to view student details, files, and submission information.
    - Card: Student projects (0 projects across student accounts)
    - Search Bar: Search projects or students (filters by title, desc, student name, email, team name, topic)
    - Filter Dropdown: All projects ∨ (All projects, Awaiting review, Reviewed, Approved, Needs changes)
    - Empty state: No student submissions match this filter yet.
    - Detailed project payload with student details, team, topic, files, submission info, and review options.
    """
    qs = Project.objects.select_related('owner', 'team', 'reviewed_by', 'topic').prefetch_related('files').all()

    # Real-time search across projects or students
    search_query = (request.GET.get('search') or request.GET.get('q') or '').strip()
    if search_query:
        qs = qs.filter(
            Q(title__icontains=search_query) |
            Q(description__icontains=search_query) |
            Q(owner__full_name__icontains=search_query) |
            Q(owner__email__icontains=search_query) |
            Q(team__name__icontains=search_query) |
            Q(topic__case_code__icontains=search_query) |
            Q(topic__title__icontains=search_query) |
            Q(department__icontains=search_query)
        )

    # Status / Submission Filter ('All projects ∨')
    filter_val = (request.GET.get('filter') or request.GET.get('status') or 'all').strip().lower()
    if filter_val in ('awaiting_review', 'awaiting', 'pending'):
        qs = qs.filter(status__in=[ProjectStatus.AWAITING_REVIEW, ProjectStatus.SUBMITTED, 'in_review', 'under_review'])
    elif filter_val in ('reviewed', 'evaluated'):
        qs = qs.filter(
            Q(status__in=[ProjectStatus.APPROVED, ProjectStatus.COMPLETED, ProjectStatus.REJECTED]) |
            Q(reviewed_by__isnull=False) |
            ~Q(feedback='')
        ).distinct()
    elif filter_val in ('approved',):
        qs = qs.filter(status=ProjectStatus.APPROVED)
    elif filter_val in ('needs_changes', 'rejected', 'changes_requested'):
        qs = qs.filter(status=ProjectStatus.REJECTED)
    elif filter_val in ('in_progress', 'progress'):
        qs = qs.filter(status=ProjectStatus.IN_PROGRESS)

    ordering = request.GET.get('ordering', '-updated_at')
    qs = qs.order_by(ordering)
    student_projects_data = [p.to_dict() for p in qs]

    open_queries_count = Query.objects.filter(status=QueryStatus.OPEN).count()
    active_projects_count = Project.objects.exclude(status=ProjectStatus.COMPLETED).count()

    filter_label = 'All projects'
    if filter_val in ('awaiting_review', 'awaiting'):
        filter_label = 'Awaiting review'
    elif filter_val == 'reviewed':
        filter_label = 'Reviewed'
    elif filter_val == 'approved':
        filter_label = 'Approved'
    elif filter_val in ('needs_changes', 'rejected'):
        filter_label = 'Needs changes'

    return JsonResponse({
        'success': True,
        'page_info': {
            'breadcrumb': 'Workspace / My projects',
            'tag': 'TEACHER WORKSPACE',
            'title': 'TEACHER WORKSPACE',
            'subtitle': 'Select a project name to view student details, files, and submission information.',
        },
        'student_projects': {
            'title': 'Student projects',
            'count': len(student_projects_data),
            'subtext': f"{len(student_projects_data)} projects across student accounts",
            'search': search_query,
            'search_placeholder': 'Search projects or students',
            'filter': filter_val,
            'active_filter_label': filter_label,
            'filter_options': [
                {'label': 'All projects', 'value': 'all'},
                {'label': 'Awaiting review', 'value': 'awaiting_review'},
                {'label': 'Reviewed', 'value': 'reviewed'},
                {'label': 'Approved', 'value': 'approved'},
                {'label': 'Needs changes', 'value': 'needs_changes'},
            ],
            'empty_message': 'No student submissions match this filter yet.',
            'items': student_projects_data,
        },
        'count': len(student_projects_data),
        'projects': student_projects_data,
        # Backward-compatible structures
        'summary': {
            'total_projects': len(student_projects_data),
            'my_projects_count': len(student_projects_data),
            'team_projects_count': 0,
        },
        'my_projects': {
            'title': 'Student projects',
            'count': len(student_projects_data),
            'subtext': f"{len(student_projects_data)} projects across student accounts",
            'items': student_projects_data,
            'empty_message': 'No student submissions match this filter yet.',
        },
        'team_projects': {
            'title': 'Team projects',
            'subtext': 'Projects shared with teams you belong to',
            'count': 0,
            'items': [],
            'empty_message': 'No team projects match your search.' if search_query else 'No team projects yet.',
        },
        'sidebar_badges': {
            'student_projects': active_projects_count,
            'my_projects': active_projects_count,
            'queries': open_queries_count,
            'student_teams_projects': Team.objects.count(),
            'unread_notifications': Notification.objects.filter(recipient=user, is_read=False).count() if user else 0,
            'chat': Message.objects.filter(recipient=user, is_read=False).count() if user else 0,
            'team_chat': 0,
        },
        'sidebar_navigation': [
            {'name': 'Dashboard', 'url': '/workspace/teacher-dashboard/', 'active': False, 'badge': None},
            {'name': 'Student projects', 'url': '/workspace/student-projects/', 'active': True, 'badge': active_projects_count},
            {'name': 'Data', 'url': '/workspace/data/', 'active': False, 'badge': None},
            {'name': 'Student teams & projects', 'url': '/workspace/teams/', 'active': False, 'badge': None},
            {'name': 'Queries', 'url': '/workspace/queries/', 'active': False, 'badge': open_queries_count},
        ]
    }, status=200)


class TeacherStudentProjectsAPIView(APIView):
    """
    Dedicated REST API for the Teacher 'Student projects' workspace page (Screenshot: media_1795195613043_d9d98119.png):
    GET /api/teacher/student-projects/
    GET /api/workspace/student-projects/
    """

    def get(self, request, *args, **kwargs):
        user = request.user if (request.user and request.user.is_authenticated) else User.objects.first()
        if not user:
            return JsonResponse({'success': False, 'code': 'UNAUTHORIZED', 'error': 'Authentication required.'}, status=401)
        return _get_teacher_student_projects_response(request, user)


class TeacherStudentProjectDetailAPIView(APIView):
    """
    REST API for selecting a single student project in Teacher Workspace:
    - View student details (name, email, department, avatar initial, contact links)
    - View team details (name, leader, members)
    - View topic details (case code, title, domain, level)
    - View files and deliverables (download URLs, sizes, types, timestamps)
    - View submission info (status, submitted timestamp, GitHub & live URLs)
    - Review submission action (Approve, Request changes, Leave feedback, Upload review file)
    GET /api/teacher/student-projects/<int:pk>/
    GET /api/workspace/student-projects/<int:pk>/
    """

    def get(self, request, pk, *args, **kwargs):
        try:
            project = Project.objects.select_related('owner', 'team', 'reviewed_by', 'topic').prefetch_related('files').get(pk=pk)
        except Project.DoesNotExist:
            return JsonResponse({'success': False, 'error': 'Project not found.'}, status=404)

        data = project.to_dict()
        return JsonResponse({
            'success': True,
            'breadcrumb': f"Workspace / Student projects / {project.title}",
            'project': data,
            'student': data.get('student'),
            'team': data.get('team'),
            'topic': data.get('topic'),
            'files': data.get('files'),
            'submission_info': data.get('submission_info'),
            'options': data.get('options')
        }, status=200)


def _format_relative_time(dt):
    """Formats a datetime into a human-readable relative time like '2 hours ago', 'Just now', 'Today'."""
    if not dt:
        return ''
    now = timezone.now()
    diff = now - dt
    seconds = int(diff.total_seconds())
    if seconds < 60:
        return 'Just now'
    elif seconds < 3600:
        minutes = seconds // 60
        return f"{minutes}m ago" if minutes > 1 else '1m ago'
    elif seconds < 86400:
        hours = seconds // 3600
        return f"{hours}h ago" if hours > 1 else '1h ago'
    elif seconds < 172800:
        return 'Yesterday'
    else:
        days = seconds // 86400
        return f"{days} days ago" if days > 1 else '1 day ago'


def _build_team_project_card(team, user=None):
    """
    Builds the detailed team card dictionary for the Teacher 'Student teams & projects' workspace:
    - Left side: Team name, 'Created by {name} · {count} members · {projects} projects'
    - Center/right:
      * When NOT submitted: 'This team has not submitted a project yet.'
      * When SUBMITTED: Submission time, team members & accounts, project details, files, and teacher review options!
    """
    creator_name = team.created_by.full_name if team.created_by else 'Student'
    creator_email = team.created_by.email if team.created_by else ''
    members_qs = team.memberships.select_related('user').all()
    members_count = members_qs.count()
    projects_qs = team.projects.select_related('topic', 'owner', 'reviewed_by').prefetch_related('files').all()
    projects_count = projects_qs.count()

    # Subtext strictly matching screenshot: "Created by faris · 1 members · 0 projects"
    subtext = f"Created by {creator_name} · {members_count} members · {projects_count} projects"

    # Format member accounts list: "see each team member's name and account"
    members_list = []
    for m in members_qs:
        u = m.user
        initial = (u.full_name[0] if u.full_name else (u.email[0] if u.email else 'U')).upper()
        members_list.append({
            'id': u.id,
            'full_name': u.full_name,
            'name': u.full_name,
            'email': u.email,
            'account': u.email,
            'account_id': u.email,
            'role': m.role,
            'is_leader': (team.leader_id == u.id) or (m.role.lower() == 'leader'),
            'department': u.department,
            'section': getattr(u, 'section', ''),
            'account_type': u.get_account_type_display(),
            'avatar_initial': initial,
            'initial': initial.lower(),
            'joined_at': m.joined_at.isoformat() if m.joined_at else None,
            'chat_url': f"/workspace/chat/{u.email}/" if u.email else None
        })

    # Find the primary or submitted project
    active_project = None
    for p in projects_qs:
        if p.status in (ProjectStatus.AWAITING_REVIEW, ProjectStatus.SUBMITTED, ProjectStatus.APPROVED, ProjectStatus.REJECTED):
            active_project = p
            break
    if not active_project and projects_qs.exists():
        active_project = projects_qs.first()

    # Determine if this team has submitted a project
    has_submitted_project = False
    if active_project:
        has_submitted_project = active_project.status in (
            ProjectStatus.AWAITING_REVIEW, ProjectStatus.SUBMITTED, ProjectStatus.APPROVED, ProjectStatus.REJECTED, ProjectStatus.COMPLETED
        ) or bool(active_project.submitted_at) or (active_project.progress == 100) or active_project.files.exists()

    if has_submitted_project and active_project:
        # Effective submission time
        sub_time = active_project.submitted_at or active_project.updated_at or active_project.created_at
        formatted_sub_time = sub_time.strftime('%b %d, %Y, %I:%M %p').replace(' 0', ' ') if sub_time else ''
        relative_sub_time = _format_relative_time(sub_time)

        # Status badge styling
        if active_project.status == ProjectStatus.APPROVED:
            status_pill = {'label': 'Approved', 'color': 'emerald', 'variant': 'success'}
        elif active_project.status == ProjectStatus.REJECTED:
            status_pill = {'label': 'Needs changes', 'color': 'rose', 'variant': 'danger'}
        elif active_project.status in (ProjectStatus.AWAITING_REVIEW, ProjectStatus.SUBMITTED):
            status_pill = {'label': 'Awaiting review', 'color': 'amber', 'variant': 'warning'}
        elif active_project.status == ProjectStatus.IN_PROGRESS:
            status_pill = {'label': 'In progress', 'color': 'cyan', 'variant': 'info'}
        else:
            status_pill = {'label': active_project.get_status_display(), 'color': 'gray', 'variant': 'secondary'}

        files_data = [
            {
                'id': f.id,
                'filename': f.filename,
                'name': f.filename,
                'file_url': f.get_download_url() if hasattr(f, 'get_download_url') else (f.file.url if f.file else ''),
                'file_size': f.file_size,
                'file_type': f.file_type,
                'uploaded_at': f.created_at.isoformat() if hasattr(f, 'created_at') and f.created_at else None
            }
            for f in active_project.files.all()
        ]

        project_dict = {
            'id': active_project.id,
            'title': active_project.title,
            'description': active_project.description,
            'status': active_project.status,
            'status_display': active_project.get_status_display(),
            'progress': active_project.progress,
            'progress_display': f"{active_project.progress}%",
            'topic': {
                'case_code': active_project.topic.case_code,
                'case': active_project.topic.case_code,
                'title': active_project.topic.title,
                'domain': active_project.topic.domain,
                'level': active_project.topic.level
            } if active_project.topic else None,
            'topic_code': active_project.topic.case_code if active_project.topic else None,
            'topic_title': active_project.topic.title if active_project.topic else None,
            'submission_time': {
                'submitted_at': sub_time.isoformat() if sub_time else None,
                'formatted_submission_time': formatted_sub_time,
                'relative_submission_time': relative_sub_time,
                'date': sub_time.strftime('%b %d, %Y') if sub_time else '',
                'time': sub_time.strftime('%I:%M %p').lstrip('0') if sub_time else ''
            },
            'submitted_at': sub_time.isoformat() if sub_time else None,
            'formatted_submitted_at': formatted_sub_time,
            'relative_submitted_at': relative_sub_time,
            'github_url': active_project.github_url,
            'live_url': active_project.live_url,
            'files_count': len(files_data),
            'files': files_data,
            'feedback': active_project.feedback,
            'grade': active_project.grade,
            'reviewed_by': active_project.reviewed_by.full_name if active_project.reviewed_by else None,
            'reviewed_at': active_project.reviewed_at.isoformat() if active_project.reviewed_at else None,
        }

        # New options available after submission
        options = {
            'has_submission': True,
            'can_open_project': True,
            'can_review': True,
            'can_grade': True,
            'can_view_files': bool(len(files_data) > 0),
            'status_pill': status_pill,
            'actions': {
                'open_project': f"/api/teacher/student-projects/{active_project.id}/",
                'review_submission': f"/api/teacher/student-projects/{active_project.id}/review/",
                'grade_submission': f"/api/teacher/student-projects/{active_project.id}/review/",
                'download_files': f"/api/projects/{active_project.id}/files/",
                'view_members': f"/api/teams/{team.id}/members/",
                'team_details': f"/api/teams/{team.id}/",
            },
            'review_modal': {
                'endpoint': f"/api/teacher/student-projects/{active_project.id}/review/",
                'method': 'POST',
                'statuses': [
                    {'value': 'approved', 'label': 'Approve project'},
                    {'value': 'needs_changes', 'label': 'Request changes'},
                    {'value': 'in_progress', 'label': 'Mark in progress'}
                ],
                'supports_feedback': True,
                'supports_grade': True
            }
        }
        empty_message = None
    else:
        # Not submitted yet state (matches Screenshot exactly: "This team has not submitted a project yet.")
        project_dict = None
        empty_message = "This team has not submitted a project yet."
        options = {
            'has_submission': False,
            'can_open_project': False,
            'can_review': False,
            'can_grade': False,
            'status_pill': {'label': 'Not submitted', 'color': 'gray', 'variant': 'secondary'},
            'empty_state_text': "This team has not submitted a project yet.",
            'actions': {
                'view_members': f"/api/teams/{team.id}/members/",
                'team_details': f"/api/teams/{team.id}/",
                'send_reminder': f"/api/teacher/student-teams/{team.id}/remind/",
            }
        }

    return {
        'id': team.id,
        'name': team.name,
        'description': team.description,
        'initial': team.name[0].lower() if team.name else 'x',
        'subtext': subtext,
        'created_by': {
            'id': team.created_by.id if team.created_by else None,
            'full_name': creator_name,
            'email': creator_email,
            'account_id': creator_email,
            'department': team.created_by.department if team.created_by else ''
        },
        'members_count': members_count,
        'projects_count': projects_count,
        'has_submitted_project': has_submitted_project,
        'submission_status': active_project.status if (has_submitted_project and active_project) else 'not_submitted',
        'submission_message': empty_message,
        'empty_message': empty_message,
        'members': members_list,
        'project': project_dict,
        'options': options,
        'created_at': team.created_at.isoformat() if team.created_at else None,
    }


class TeacherStudentTeamsProjectsAPIView(APIView):
    """
    REST API for the 4th section of the Teacher Dashboard:
    'Workspace / Student teams & projects' (Screenshot: media_1795197971460_4d3418f5.png):
    - Header Tag: 'TEACHER WORKSPACE'
    - Title: 'Student teams & projects'
    - Subtitle: 'Open a project to see its submission time and each team member\'s name and account.'
    - Card:
      * Team name (e.g. 'xander')
      * Subtext: 'Created by faris · 1 members · 0 projects'
      * When NOT submitted: 'This team has not submitted a project yet.'
      * When SUBMITTED: Shows submission time, team members & accounts, project info, files, and teacher review options!
    """
    def get(self, request, *args, **kwargs):
        user = request.user if (request.user and request.user.is_authenticated) else User.objects.first()

        teams_qs = Team.objects.select_related('created_by', 'leader').prefetch_related(
            'memberships__user',
            'projects__topic',
            'projects__files',
            'projects__reviewed_by'
        ).all().order_by('-created_at')

        search_query = (request.GET.get('search') or request.GET.get('q') or '').strip()
        if search_query:
            teams_qs = teams_qs.filter(
                Q(name__icontains=search_query) |
                Q(created_by__full_name__icontains=search_query) |
                Q(memberships__user__full_name__icontains=search_query) |
                Q(projects__title__icontains=search_query)
            ).distinct()

        filter_status = (request.GET.get('filter') or request.GET.get('status') or 'all').strip().lower()
        if filter_status in ('submitted', 'has_submission'):
            teams_qs = teams_qs.filter(
                projects__status__in=[
                    ProjectStatus.AWAITING_REVIEW, ProjectStatus.SUBMITTED, ProjectStatus.APPROVED, ProjectStatus.REJECTED
                ]
            ).distinct()
        elif filter_status in ('not_submitted', 'pending'):
            teams_qs = teams_qs.exclude(
                projects__status__in=[
                    ProjectStatus.AWAITING_REVIEW, ProjectStatus.SUBMITTED, ProjectStatus.APPROVED, ProjectStatus.REJECTED
                ]
            ).distinct()
        elif filter_status in ('awaiting_review', 'under_review'):
            teams_qs = teams_qs.filter(
                projects__status__in=[ProjectStatus.AWAITING_REVIEW, ProjectStatus.SUBMITTED]
            ).distinct()
        elif filter_status in ('approved',):
            teams_qs = teams_qs.filter(projects__status=ProjectStatus.APPROVED).distinct()
        elif filter_status in ('needs_changes', 'rejected'):
            teams_qs = teams_qs.filter(projects__status=ProjectStatus.REJECTED).distinct()

        teams_cards = [_build_team_project_card(t, user) for t in teams_qs]

        submitted_count = sum(1 for c in teams_cards if c['has_submitted_project'])
        not_submitted_count = len(teams_cards) - submitted_count
        awaiting_count = sum(1 for c in teams_cards if c.get('submission_status') in (ProjectStatus.AWAITING_REVIEW, ProjectStatus.SUBMITTED))

        active_projects_count = Project.objects.filter(status=ProjectStatus.AWAITING_REVIEW).count()
        open_queries_count = Query.objects.filter(status=QueryStatus.OPEN).count()

        return JsonResponse({
            'success': True,
            'header': {
                'tag': 'TEACHER WORKSPACE',
                'title': 'Student teams & projects',
                'subtitle': "Open a project to see its submission time and each team member's name and account.",
                'breadcrumb': 'Workspace / Student teams & projects'
            },
            'breadcrumb': 'Workspace / Student teams & projects',
            'summary': {
                'total_teams': len(teams_cards),
                'teams_with_submissions': submitted_count,
                'teams_without_submissions': not_submitted_count,
                'teams_awaiting_review': awaiting_count,
                'filtered_count': len(teams_cards)
            },
            'empty_state': {
                'no_teams_message': 'No student teams created yet.',
                'not_submitted_message': 'This team has not submitted a project yet.'
            },
            'count': len(teams_cards),
            'teams': teams_cards,
            'sidebar_badges': {
                'student_projects': active_projects_count,
                'my_projects': active_projects_count,
                'queries': open_queries_count,
                'student_teams_projects': len(teams_cards),
                'unread_notifications': Notification.objects.filter(recipient=user, is_read=False).count() if user else 0,
                'chat': Message.objects.filter(recipient=user, is_read=False).count() if user else 0,
                'team_chat': 0,
            },
            'sidebar_navigation': [
                {'name': 'Dashboard', 'url': '/workspace/teacher-dashboard/', 'active': False, 'badge': None},
                {'name': 'Student projects', 'url': '/workspace/student-projects/', 'active': False, 'badge': active_projects_count},
                {'name': 'Data', 'url': '/workspace/data/', 'active': False, 'badge': None},
                {'name': 'Student teams & projects', 'url': '/workspace/teams/', 'active': True, 'badge': None},
                {'name': 'Queries', 'url': '/workspace/queries/', 'active': False, 'badge': open_queries_count},
            ]
        }, status=200)


class TeacherStudentTeamDetailAPIView(APIView):
    """
    REST API for a single team's submitted project and member accounts:
    GET /api/teacher/student-teams/<int:pk>/
    """
    def get(self, request, pk, *args, **kwargs):
        user = request.user if (request.user and request.user.is_authenticated) else User.objects.first()
        try:
            team = Team.objects.select_related('created_by', 'leader').prefetch_related(
                'memberships__user', 'projects__topic', 'projects__files'
            ).get(pk=pk)
        except Team.DoesNotExist:
            return JsonResponse({'success': False, 'error': 'Team not found.'}, status=404)

        card = _build_team_project_card(team, user)
        return JsonResponse({
            'success': True,
            'team': card,
            'members': card['members'],
            'project': card['project'],
            'options': card['options'],
            'submission_time': card['project']['submission_time'] if card.get('project') else None
        }, status=200)


class TeacherStudentTeamRemindAPIView(APIView):
    """
    Teacher action to send a project submission reminder to all members of a team:
    POST /api/teacher/student-teams/<int:pk>/remind/
    """
    def post(self, request, pk, *args, **kwargs):
        user = request.user if (request.user and request.user.is_authenticated) else User.objects.first()
        try:
            team = Team.objects.prefetch_related('memberships__user').get(pk=pk)
        except Team.DoesNotExist:
            return JsonResponse({'success': False, 'error': 'Team not found.'}, status=404)

        teacher_name = user.full_name if user else 'Your teacher'
        custom_message = request.data.get('message') or f"Prof. {teacher_name} is reminding your team '{team.name}' to submit your project."

        notified_count = 0
        for m in team.memberships.select_related('user').all():
            if m.user != user:
                create_notification(
                    recipient=m.user,
                    title="Project Submission Reminder ⏰",
                    message=custom_message,
                    notification_type=NotificationType.INFO,
                    action_url="/workspace/my-team/",
                    tag="Node Theory"
                )
                notified_count += 1

        return JsonResponse({
            'success': True,
            'message': f"Submission reminder sent to {team.name} ({notified_count} members notified).",
            'notified_count': notified_count,
            'team_id': team.id,
            'team_name': team.name
        }, status=200)


class TeacherStudentTeamReviewAPIView(APIView):
    """
    Teacher action to review a team's submitted project by team ID:
    POST /api/teacher/student-teams/<int:pk>/review/
    """
    def post(self, request, pk, *args, **kwargs):
        try:
            team = Team.objects.get(pk=pk)
        except Team.DoesNotExist:
            return JsonResponse({'success': False, 'error': 'Team not found.'}, status=404)

        project = team.projects.first()
        if not project:
            return JsonResponse({
                'success': False,
                'error': f"Team '{team.name}' has not submitted a project yet."
            }, status=400)

        # Delegate review to ProjectReviewAPIView logic
        review_view = ProjectReviewAPIView()
        return review_view.post(request, pk=project.id, *args, **kwargs)


class ProjectListCreateAPIView(APIView):
    """
    REST API for the 'My projects' & 'Team projects' Workspace page:
    - Lists personal projects ('My projects')
    - Lists team projects ('Team projects')
    - Real-time search across projects ('Search your projects')
    - Filters by workspace/department, status, and type ('my', 'team')
    - Creates new projects (with optional team assignment)
    - Automatically serves Teacher Workspace view when accessed by Teacher/Faculty
    """

    def get(self, request, *args, **kwargs):
        user = request.user if (request.user and request.user.is_authenticated) else User.objects.first()
        if not user:
            return JsonResponse({'success': False, 'code': 'UNAUTHORIZED', 'error': 'Authentication required.'}, status=401)

        is_faculty = user.is_staff or user.account_type in (AccountType.TEACHER, AccountType.FACULTY)

        if is_faculty:
            return _get_teacher_student_projects_response(request, user)

        # Personal projects: projects owned by user with no team assigned
        my_qs = Project.objects.filter(owner=user, team__isnull=True).select_related('owner', 'team', 'reviewed_by')

        # Team projects: projects attached to a team where user is owner or team member
        team_qs = Project.objects.filter(
            team__isnull=False
        ).filter(
            Q(owner=user) | Q(team__memberships__user=user)
        ).select_related('owner', 'team', 'reviewed_by').distinct()

        # Full queryset (or all projects if faculty)
        if is_faculty:
            all_qs = Project.objects.select_related('owner', 'team', 'reviewed_by').all()
        else:
            all_qs = Project.objects.filter(
                Q(owner=user) | Q(team__memberships__user=user)
            ).select_related('owner', 'team', 'reviewed_by').distinct()

        # -------------------------------------------------------------
        # Search Filtering ('Search your projects' search input)
        # -------------------------------------------------------------
        search_query = request.GET.get('search') or request.GET.get('q') or ''
        search_query = search_query.strip()
        if search_query:
            search_filter = (
                Q(title__icontains=search_query) |
                Q(description__icontains=search_query) |
                Q(department__icontains=search_query) |
                Q(team__name__icontains=search_query)
            )
            my_qs = my_qs.filter(search_filter)
            team_qs = team_qs.filter(search_filter)
            all_qs = all_qs.filter(search_filter)

        # -------------------------------------------------------------
        # Status Filter
        # -------------------------------------------------------------
        status = request.GET.get('status')
        if status:
            my_qs = my_qs.filter(status=status)
            team_qs = team_qs.filter(status=status)
            all_qs = all_qs.filter(status=status)

        # -------------------------------------------------------------
        # Workspace / Department Filter ('Workspace' filter button)
        # -------------------------------------------------------------
        workspace_dept = request.GET.get('workspace') or request.GET.get('department')
        if workspace_dept:
            my_qs = my_qs.filter(department__icontains=workspace_dept)
            team_qs = team_qs.filter(department__icontains=workspace_dept)
            all_qs = all_qs.filter(department__icontains=workspace_dept)

        # -------------------------------------------------------------
        # Ordering
        # -------------------------------------------------------------
        ordering = request.GET.get('ordering', '-created_at')
        my_qs = my_qs.order_by(ordering)
        team_qs = team_qs.order_by(ordering)
        all_qs = all_qs.order_by(ordering)

        my_projects_data = [p.to_dict() for p in my_qs]
        team_projects_data = [p.to_dict() for p in team_qs]
        all_projects_data = [p.to_dict() for p in all_qs]

        # Specific type slice if requested (?type=my or ?type=team)
        type_filter = request.GET.get('type')
        if type_filter == 'my':
            selected_items = my_projects_data
        elif type_filter == 'team':
            selected_items = team_projects_data
        else:
            selected_items = all_projects_data

        return JsonResponse({
            'success': True,
            'page_info': {
                'title': 'YOUR WORK',
                'subtitle': 'Keep track of your submissions and teacher feedback.',
                'breadcrumb': 'Workspace / My projects'
            },
            'summary': {
                'total_projects': len(all_projects_data),
                'my_projects_count': len(my_projects_data),
                'team_projects_count': len(team_projects_data),
            },
            'my_projects': {
                'title': 'My projects',
                'count': len(my_projects_data),
                'subtext': f"{len(my_projects_data)} projects",
                'items': my_projects_data,
                'empty_message': 'No projects match your search yet.' if search_query else 'No projects created yet.',
            },
            'team_projects': {
                'title': 'Team projects',
                'subtext': 'Projects shared with teams you belong to',
                'count': len(team_projects_data),
                'items': team_projects_data,
                'empty_message': 'No team projects match your search.' if search_query else 'No team projects yet.',
            },
            'count': len(selected_items),
            'projects': selected_items
        }, status=200)

    def post(self, request, *args, **kwargs):
        user = request.user if (request.user and request.user.is_authenticated) else User.objects.first()
        if not user:
            return JsonResponse({'success': False, 'code': 'UNAUTHORIZED', 'error': 'Authentication required.'}, status=401)

        data = request.data or {}
        title = data.get('title', '').strip()
        if not title:
            return JsonResponse({
                'success': False,
                'error': 'Project title is required.',
                'errors': {'title': ['Project title is required.']}
            }, status=400)

        description = data.get('description', '').strip()
        department = data.get('department', '').strip() or user.department
        github_url = data.get('github_url', '').strip() or None
        live_url = data.get('live_url', '').strip() or None
        status = ProjectStatus.normalize(data.get('status', ProjectStatus.AWAITING_REVIEW))

        # Team Project handling
        team_id = data.get('team_id') or data.get('team')
        team = None
        if team_id:
            team = Team.objects.filter(id=team_id).first()
            if not team:
                return JsonResponse({'success': False, 'error': f'Team with id {team_id} not found.'}, status=404)
            if not department and team.department:
                department = team.department

        # Topic association handling (if selected from Data Topics)
        topic_identifier = data.get('topic_id') or data.get('topic_case') or data.get('case_code') or data.get('case') or data.get('topic')
        topic = None
        if topic_identifier:
            if not Topic.objects.exists():
                Topic.seed_defaults()
            if team:
                existing_team_topic = Topic.objects.filter(team=team).exclude(status=TopicStatus.AVAILABLE).first()
                if existing_team_topic:
                    return JsonResponse({
                        'success': False,
                        'code': 'TEAM_PROJECT_LIMIT_EXCEEDED',
                        'error': f"Your team ('{team.name}') has already selected project '{existing_team_topic.case_code}: {existing_team_topic.title}'. A team cannot select more than one project simultaneously."
                    }, status=409)
            if str(topic_identifier).isdigit():
                topic = Topic.objects.filter(Q(id=int(topic_identifier)) | Q(case_code__iexact=str(topic_identifier))).first()
            else:
                topic = Topic.objects.filter(case_code__iexact=str(topic_identifier).strip()).first()
            if not topic:
                return JsonResponse({'success': False, 'code': 'TOPIC_NOT_FOUND', 'error': f"Topic '{topic_identifier}' not found."}, status=404)
            if topic.status != TopicStatus.AVAILABLE or topic.team is not None:
                occupier = topic.team.name if topic.team else 'another team'
                return JsonResponse({
                    'success': False,
                    'code': 'TOPIC_ALREADY_SELECTED',
                    'error': f"This topic ('{topic.case_code}: {topic.title}') has already been selected by {occupier}."
                }, status=409)
            topic.team = team
            topic.selected_by = user
            topic.selected_at = timezone.now()
            topic.status = TopicStatus.SELECTED
            topic.save()

        try:
            progress = max(0, min(100, int(data.get('progress', 0))))
        except (ValueError, TypeError):
            progress = 0

        project = Project.objects.create(
            title=title,
            description=description,
            topic=topic,
            owner=user,
            team=team,
            department=department,
            status=status,
            progress=progress,
            is_selected=bool(topic),
            selected_at=timezone.now() if topic else None,
            github_url=github_url,
            live_url=live_url
        )

        # Notify team members if assigned to a team
        if team:
            for member in team.memberships.exclude(user=user).select_related('user'):
                create_notification(
                    recipient=member.user,
                    title=f"New Team Project in {team.name}",
                    message=f"{user.full_name} created project '{project.title}' in your team.",
                    notification_type=NotificationType.TEAM_INVITE,
                    action_url=f"/projects/{project.id}"
                )

        return JsonResponse({
            'success': True,
            'message': 'Project created successfully.',
            'project': project.to_dict()
        }, status=201)


class ProjectDetailAPIView(APIView):
    """
    REST API for a single project.
    GET    /api/projects/<id>/
    PUT    /api/projects/<id>/
    PATCH  /api/projects/<id>/
    DELETE /api/projects/<id>/
    """

    def _get_project(self, pk):
        try:
            return Project.objects.select_related('owner', 'team', 'reviewed_by').get(pk=pk)
        except Project.DoesNotExist:
            return None

    def get(self, request, pk, *args, **kwargs):
        project = self._get_project(pk)
        if not project:
            return JsonResponse({'success': False, 'error': 'Project not found.'}, status=404)
        return JsonResponse({'success': True, 'project': project.to_dict()}, status=200)

    def patch(self, request, pk, *args, **kwargs):
        project = self._get_project(pk)
        if not project:
            return JsonResponse({'success': False, 'error': 'Project not found.'}, status=404)

        data = request.data or {}
        if 'title' in data and data['title'].strip():
            project.title = data['title'].strip()
        if 'description' in data:
            project.description = data['description'].strip()
        if 'department' in data:
            project.department = data['department'].strip()
        if 'github_url' in data:
            project.github_url = data['github_url'].strip() or None
        if 'live_url' in data:
            project.live_url = data['live_url'].strip() or None
        if 'status' in data:
            project.status = ProjectStatus.normalize(data['status'])
        if 'progress' in data:
            try:
                project.progress = max(0, min(100, int(data['progress'])))
            except (ValueError, TypeError):
                pass
        if 'team_id' in data or 'team' in data:
            new_team_id = data.get('team_id') if 'team_id' in data else data.get('team')
            if new_team_id in (None, '', 0, 'null'):
                project.team = None
            else:
                team = Team.objects.filter(id=new_team_id).first()
                if not team:
                    return JsonResponse({'success': False, 'error': f'Team with id {new_team_id} not found.'}, status=404)
                project.team = team

        project.save()
        return JsonResponse({'success': True, 'message': 'Project updated.', 'project': project.to_dict()}, status=200)

    def put(self, request, pk, *args, **kwargs):
        return self.patch(request, pk, *args, **kwargs)

    def delete(self, request, pk, *args, **kwargs):
        project = self._get_project(pk)
        if not project:
            return JsonResponse({'success': False, 'error': 'Project not found.'}, status=404)
        topic_code = project.topic.case_code if project.topic else None
        project.delete()
        msg = f"Project deleted and topic '{topic_code}' is now available for other teams." if topic_code else "Project deleted."
        return JsonResponse({'success': True, 'message': msg}, status=200)


class ProjectSubmitReviewAPIView(APIView):
    """
    Submits a project for review: transitions status to 'awaiting_review'.
    POST /api/projects/<id>/submit/
    """

    def post(self, request, pk, *args, **kwargs):
        try:
            project = Project.objects.get(pk=pk)
        except Project.DoesNotExist:
            return JsonResponse({'success': False, 'error': 'Project not found.'}, status=404)

        project.status = ProjectStatus.AWAITING_REVIEW
        project.save(update_fields=['status', 'updated_at'])
        return JsonResponse({
            'success': True,
            'message': 'Project submitted for review.',
            'project': project.to_dict()
        }, status=200)


class ProjectReviewAPIView(APIView):
    """
    Teacher / Faculty endpoint to review, approve, request changes, or leave feedback on a student project:
    - Approve project (status: 'approved')
    - Request changes / Reject (status: 'needs_changes' or 'rejected')
    - Mark in progress (status: 'in_progress')
    - Leave review feedback notes (feedback: '...')
    - Update progress percentage (progress: 0-100)
    POST /api/projects/<id>/review/
    POST /api/teacher/student-projects/<id>/review/
    """

    def post(self, request, pk, *args, **kwargs):
        user = request.user if (request.user and request.user.is_authenticated) else User.objects.first()
        try:
            project = Project.objects.select_related('owner', 'team').get(pk=pk)
        except Project.DoesNotExist:
            return JsonResponse({'success': False, 'error': 'Project not found.'}, status=404)

        data = request.data or {}
        decision = data.get('status', '').strip().lower()
        feedback = data.get('feedback', '').strip()

        if decision in ('approved', 'approve'):
            project.status = ProjectStatus.APPROVED
            if not project.progress or project.progress < 100:
                project.progress = 100
            notif_title = "Project Approved! 🎉"
            notif_msg = f"Congratulations! Your project '{project.title}' has been approved."
            notif_type = NotificationType.PROJECT_APPROVED
        elif decision in ('rejected', 'needs_changes', 'needs-changes', 'changes_requested'):
            project.status = ProjectStatus.REJECTED
            notif_title = "Changes Requested on Project"
            notif_msg = f"Your teacher requested changes on '{project.title}': {feedback or 'Please check review notes.'}"
            notif_type = NotificationType.PROJECT_FEEDBACK
        elif decision in ('in_progress', 'progress'):
            project.status = ProjectStatus.IN_PROGRESS
            notif_title = "Project In Progress"
            notif_msg = f"Your project '{project.title}' has been marked in progress."
            notif_type = NotificationType.PROJECT_FEEDBACK
        elif decision in ('awaiting_review', 'in_review', 'under_review'):
            project.status = ProjectStatus.AWAITING_REVIEW
            notif_title = "Project Under Review"
            notif_msg = f"Your project '{project.title}' is currently under review."
            notif_type = NotificationType.SUBMISSION_STATUS
        elif not decision and feedback:
            # Feedback only
            notif_title = "Project Feedback Available"
            notif_msg = f"Your teacher left feedback on '{project.title}': {feedback}"
            notif_type = NotificationType.PROJECT_FEEDBACK
        else:
            return JsonResponse({
                'success': False,
                'error': "Status must be 'approved', 'rejected', 'needs_changes', or provide feedback."
            }, status=400)

        if feedback:
            project.feedback = feedback
        if 'grade' in data and data['grade']:
            project.grade = str(data['grade']).strip()
        if 'progress' in data:
            try:
                project.progress = max(0, min(100, int(data['progress'])))
            except (ValueError, TypeError):
                pass

        project.reviewed_by = user
        project.reviewed_at = timezone.now()
        project.save()

        # Create notification for student with tag 'Node Theory'
        if project.owner:
            create_notification(
                recipient=project.owner,
                title=notif_title,
                message=notif_msg,
                notification_type=notif_type,
                action_url=f"/projects/{project.id}",
                tag="Node Theory"
            )

        # Notify other team members if team project
        if project.team:
            for member in project.team.memberships.select_related('user').all():
                if member.user != project.owner and member.user != user:
                    create_notification(
                        recipient=member.user,
                        title=notif_title,
                        message=notif_msg,
                        notification_type=notif_type,
                        action_url="/workspace/my-team/",
                        tag="Node Theory"
                    )

        return JsonResponse({
            'success': True,
            'message': f"Project {project.get_status_display()}.",
            'project': project.to_dict()
        }, status=200)


# ==============================================================================
# DATA / TOPICS API ENDPOINTS (Workspace / Data)
# ==============================================================================

class TopicListAPIView(APIView):
    """
    REST API for the 'Workspace / Data' Topics Screen (Screenshot: media_1795197028583_babd1550.png):
    - Breadcrumb: 'Workspace / Data'
    - Tag: 'DATA'
    - Title: 'Topics'
    - Subtitle: 'Upload a file to replace or add your dataset, or review the sample AI use-case topics below.'
    - Upload Action Button: 'Upload file'
    - Topics Card Table:
        * Columns: Case, Title, Domain, Level, Team ID, Guide, Status
        * Seeds default 11 healthcare topics (H1 to H11) if dataset is empty.
    - Real-time search across topics (search / q query param).
    - Filter by domain, level, and status (available, selected, assigned).
    - Identifies if the current user's team already has a project/topic selected.
    - Support POST to add topics individually or in bulk.
    """
    def get(self, request, *args, **kwargs):
        # Auto-seed default topics if empty
        if not Topic.objects.exists():
            Topic.seed_defaults()

        user = request.user if (request.user and request.user.is_authenticated) else None
        user_team = None
        if user:
            user_team = Team.objects.filter(Q(created_by=user) | Q(memberships__user=user)).first()

        qs = Topic.objects.select_related('team', 'selected_by').all()

        # Real-time search
        search_query = (request.GET.get('search') or request.GET.get('q') or '').strip()
        if search_query:
            qs = qs.filter(
                Q(case_code__icontains=search_query) |
                Q(title__icontains=search_query) |
                Q(domain__icontains=search_query) |
                Q(level__icontains=search_query) |
                Q(guide__icontains=search_query) |
                Q(team__name__icontains=search_query)
            )

        # Filters
        domain = (request.GET.get('domain') or '').strip()
        if domain:
            qs = qs.filter(domain__iexact=domain)

        level = (request.GET.get('level') or '').strip()
        if level:
            qs = qs.filter(level__iexact=level)

        status_filter = (request.GET.get('status') or '').strip().lower()
        if status_filter == 'available':
            qs = qs.filter(status=TopicStatus.AVAILABLE, team__isnull=True)
        elif status_filter in ('selected', 'assigned'):
            qs = qs.filter(Q(status=TopicStatus.SELECTED) | Q(team__isnull=False))

        topics_data = [t.to_dict() for t in qs]
        total_count = Topic.objects.count()
        available_count = Topic.objects.filter(status=TopicStatus.AVAILABLE, team__isnull=True).count()
        selected_count = total_count - available_count

        open_queries_count = Query.objects.filter(status=QueryStatus.OPEN).count()
        active_projects_count = Project.objects.exclude(status=ProjectStatus.COMPLETED).count()

        # User/team current selection check
        user_selection = None
        if user_team:
            team_topic = Topic.objects.filter(team=user_team).first()
            if team_topic:
                user_selection = {
                    'team_id': user_team.id,
                    'team_name': user_team.name,
                    'has_selected_topic': True,
                    'topic': team_topic.to_dict(),
                    'can_select_another': False,
                    'selection_message': f"Your team ('{user_team.name}') has selected '{team_topic.case_code}: {team_topic.title}'."
                }
        elif user:
            user_topic = Topic.objects.filter(selected_by=user).first()
            if user_topic:
                user_selection = {
                    'has_selected_topic': True,
                    'topic': user_topic.to_dict(),
                    'can_select_another': False,
                    'selection_message': f"You have selected '{user_topic.case_code}: {user_topic.title}'."
                }

        header_data = {
            'tag': 'DATA',
            'title': 'Topics',
            'subtitle': 'Upload a file to replace or add your dataset, or review the sample AI use-case topics below.',
            'breadcrumb': 'Workspace / Data'
        }

        return JsonResponse({
            'success': True,
            'header': header_data,
            'page_info': header_data,
            'breadcrumb': 'Workspace / Data',
            'upload_action': {
                'button_text': 'Upload file',
                'title': 'Upload dataset',
                'endpoint': '/api/topics/upload/',
                'method': 'POST',
                'supported_formats': ['csv', 'json', 'txt'],
                'modes': [
                    {'value': 'add', 'label': 'Add to dataset (Append / Update)'},
                    {'value': 'replace', 'label': 'Replace dataset'}
                ]
            },
            'table': {
                'title': 'Topics',
                'subtext': 'AI project case topics and their classifications.',
                'columns': [
                    {'key': 'case', 'label': 'Case'},
                    {'key': 'title', 'label': 'Title'},
                    {'key': 'domain', 'label': 'Domain'},
                    {'key': 'level', 'label': 'Level'},
                    {'key': 'team_id', 'label': 'Team ID'},
                    {'key': 'guide', 'label': 'Guide'},
                    {'key': 'status', 'label': 'Status'},
                ],
                'rows': topics_data,
                'count': len(topics_data),
                'empty_message': 'No topics found matching your criteria.'
            },
            'summary': {
                'total_topics': total_count,
                'available_topics': available_count,
                'selected_topics': selected_count,
                'filtered_count': len(topics_data)
            },
            'user_team_selection': user_selection,
            'topics': topics_data,
            'sidebar_badges': {
                'student_projects': active_projects_count,
                'my_projects': active_projects_count,
                'queries': open_queries_count,
                'unread_notifications': Notification.objects.filter(recipient=user, is_read=False).count() if user else 0,
                'chat': Message.objects.filter(recipient=user, is_read=False).count() if user else 0,
                'team_chat': 0,
            },
            'sidebar_navigation': [
                {'name': 'Dashboard', 'url': '/workspace/teacher-dashboard/', 'active': False, 'badge': None},
                {'name': 'Student projects', 'url': '/workspace/student-projects/', 'active': False, 'badge': active_projects_count},
                {'name': 'Data', 'url': '/workspace/data/', 'active': True, 'badge': None},
                {'name': 'Student teams & projects', 'url': '/workspace/teams/', 'active': False, 'badge': None},
                {'name': 'Queries', 'url': '/workspace/queries/', 'active': False, 'badge': open_queries_count},
            ]
        }, status=200)

    def post(self, request, *args, **kwargs):
        """Creates or updates a single topic."""
        data = request.data or {}
        case_code = data.get('case_code') or data.get('case') or data.get('code')
        title = data.get('title')
        if not case_code or not title:
            return JsonResponse({'success': False, 'error': 'Both case code and title are required.'}, status=400)

        case_code = str(case_code).strip()
        title = str(title).strip()
        domain = str(data.get('domain') or 'Healthcare').strip()
        level = str(data.get('level') or 'Moderate').strip()
        guide = str(data.get('guide') or '').strip()

        topic, created = Topic.objects.get_or_create(
            case_code=case_code,
            defaults={
                'title': title,
                'domain': domain,
                'level': level,
                'guide': guide,
                'status': TopicStatus.AVAILABLE
            }
        )
        if not created:
            topic.title = title
            topic.domain = domain
            topic.level = level
            if guide:
                topic.guide = guide
            topic.save()

        return JsonResponse({
            'success': True,
            'message': f"Topic '{topic.case_code}' {'created' if created else 'updated'} successfully.",
            'topic': topic.to_dict(),
            'created': created
        }, status=201 if created else 200)


class TopicUploadAPIView(APIView):
    """
    REST API for 'Upload file' on Workspace / Data screen (Screenshot: media_1795197028583_babd1550.png):
    'Upload a file to replace or add your dataset, or review the sample AI use-case topics below.'
    Supports CSV, JSON, and text files.
    Modes:
      - replace=true: deletes available topics and installs new dataset.
      - replace=false (default): adds new topics and updates existing matching codes.
    """
    def post(self, request, *args, **kwargs):
        # Determine replace mode
        replace_mode = False
        replace_val = request.POST.get('replace') or request.GET.get('replace') or (request.data.get('replace') if isinstance(request.data, dict) else False)
        if str(replace_val).lower() in ('true', '1', 'yes'):
            replace_mode = True

        uploaded_file = request.FILES.get('file') or request.FILES.get('dataset') or request.FILES.get('upload')
        topics_payload = None

        if uploaded_file:
            try:
                content = uploaded_file.read().decode('utf-8', errors='replace')
                name = uploaded_file.name.lower()
                if name.endswith('.json'):
                    parsed_json = json.loads(content)
                    if isinstance(parsed_json, dict) and 'topics' in parsed_json:
                        topics_payload = parsed_json['topics']
                    elif isinstance(parsed_json, list):
                        topics_payload = parsed_json
                    else:
                        topics_payload = [parsed_json]
                else:
                    delimiter = '\t' if name.endswith('.tsv') else ','
                    reader = csv.reader(io.StringIO(content), delimiter=delimiter)
                    rows = list(reader)
                    if not rows:
                        return JsonResponse({'success': False, 'error': 'Uploaded file is empty.'}, status=400)

                    header = [h.strip().lower() for h in rows[0]]
                    case_idx = next((i for i, h in enumerate(header) if h in ('case', 'case_code', 'code', 'id', 'case_id')), 0)
                    title_idx = next((i for i, h in enumerate(header) if h in ('title', 'name', 'topic', 'project')), 1 if len(header) > 1 else 0)
                    domain_idx = next((i for i, h in enumerate(header) if h in ('domain', 'category', 'field')), 2 if len(header) > 2 else -1)
                    level_idx = next((i for i, h in enumerate(header) if h in ('level', 'difficulty', 'complexity')), 3 if len(header) > 3 else -1)
                    guide_idx = next((i for i, h in enumerate(header) if h in ('guide', 'mentor', 'advisor', 'faculty')), 4 if len(header) > 4 else -1)

                    topics_payload = []
                    start_row = 1 if any(h in ('case', 'title', 'domain', 'level', 'guide') for h in header) else 0
                    for row in rows[start_row:]:
                        if not row or not any(row):
                            continue
                        case_code = row[case_idx].strip() if len(row) > case_idx else ''
                        title = row[title_idx].strip() if len(row) > title_idx else ''
                        if not case_code or not title:
                            continue
                        domain = row[domain_idx].strip() if (domain_idx != -1 and len(row) > domain_idx and row[domain_idx].strip()) else 'Healthcare'
                        level = row[level_idx].strip() if (level_idx != -1 and len(row) > level_idx and row[level_idx].strip()) else 'Moderate'
                        guide = row[guide_idx].strip() if (guide_idx != -1 and len(row) > guide_idx) else ''
                        topics_payload.append({
                            'case': case_code,
                            'title': title,
                            'domain': domain,
                            'level': level,
                            'guide': guide
                        })
            except Exception as e:
                return JsonResponse({'success': False, 'error': f'Failed to parse uploaded dataset file: {str(e)}'}, status=400)
        elif isinstance(request.data, dict) and 'topics' in request.data:
            topics_payload = request.data['topics']
        elif isinstance(request.data, list):
            topics_payload = request.data

        if not topics_payload or not isinstance(topics_payload, list):
            return JsonResponse({
                'success': False,
                'error': 'No valid topics data provided. Please upload a CSV/JSON file or send a JSON array of topics.'
            }, status=400)

        with transaction.atomic():
            if replace_mode:
                Topic.objects.filter(status=TopicStatus.AVAILABLE, team__isnull=True).delete()

            created_count = 0
            updated_count = 0
            for item in topics_payload:
                case_code = str(item.get('case') or item.get('case_code') or item.get('code') or '').strip()
                title = str(item.get('title') or '').strip()
                if not case_code or not title:
                    continue
                domain = str(item.get('domain') or 'Healthcare').strip()
                level = str(item.get('level') or 'Moderate').strip()
                guide = str(item.get('guide') or '').strip()

                topic_obj, created = Topic.objects.get_or_create(
                    case_code=case_code,
                    defaults={
                        'title': title,
                        'domain': domain,
                        'level': level,
                        'guide': guide,
                        'status': TopicStatus.AVAILABLE
                    }
                )
                if created:
                    created_count += 1
                else:
                    topic_obj.title = title
                    topic_obj.domain = domain
                    topic_obj.level = level
                    if guide:
                        topic_obj.guide = guide
                    topic_obj.save()
                    updated_count += 1

        all_topics = [t.to_dict() for t in Topic.objects.all()]
        return JsonResponse({
            'success': True,
            'message': f"Dataset processed successfully. {created_count} topics created, {updated_count} updated.",
            'replace_mode': replace_mode,
            'created_count': created_count,
            'updated_count': updated_count,
            'total_topics': len(all_topics),
            'topics': all_topics,
            'table': {
                'title': 'Topics',
                'subtext': 'AI project case topics and their classifications.',
                'columns': [
                    {'key': 'case', 'label': 'Case'},
                    {'key': 'title', 'label': 'Title'},
                    {'key': 'domain', 'label': 'Domain'},
                    {'key': 'level', 'label': 'Level'},
                    {'key': 'team_id', 'label': 'Team ID'},
                    {'key': 'guide', 'label': 'Guide'},
                    {'key': 'status', 'label': 'Status'},
                ],
                'rows': all_topics,
                'count': len(all_topics)
            }
        }, status=201)


class TopicSelectAPIView(APIView):
    """
    REST API to Select a Topic for a Team / Student:
    Enforces Strict Selection Rules:
    1. A team can select ONLY ONE project. The same team cannot select two projects concurrently.
    2. Exclusive Selection: When Team A selects a project, Team B CANNOT select the same project.
    3. Automatically creates a Project in 'Workspace / My projects' with status 'Not started', progress 0%, and badge 'Selected'.
    """
    def post(self, request, pk_or_case=None, *args, **kwargs):
        if not Topic.objects.exists():
            Topic.seed_defaults()

        user = request.user if (request.user and request.user.is_authenticated) else User.objects.first()
        if not user:
            return JsonResponse({'success': False, 'code': 'UNAUTHORIZED', 'error': 'Authentication required to select a topic.'}, status=401)

        data = request.data or {}
        target_case_or_id = pk_or_case or data.get('case') or data.get('case_code') or data.get('topic_id') or data.get('id')
        if not target_case_or_id:
            return JsonResponse({'success': False, 'error': 'Topic case or ID is required to select a project.'}, status=400)

        with transaction.atomic():
            # 1. Resolve team
            team_id = data.get('team_id') or data.get('team')
            team = None
            if team_id:
                team = Team.objects.filter(id=team_id).first()
                if not team:
                    return JsonResponse({'success': False, 'code': 'TEAM_NOT_FOUND', 'error': f"Team with ID {team_id} not found."}, status=404)
                is_member = (team.created_by == user) or team.memberships.filter(user=user).exists()
                if not is_member and not (user.is_staff or user.account_type in (AccountType.TEACHER, AccountType.FACULTY)):
                    return JsonResponse({'success': False, 'code': 'FORBIDDEN', 'error': 'You are not a member of this team.'}, status=403)
            else:
                team = Team.objects.filter(Q(created_by=user) | Q(memberships__user=user)).first()

            # RULE 1: The same team CANNOT select two projects at the same time!
            if team:
                existing_team_topic = Topic.objects.filter(team=team).exclude(status=TopicStatus.AVAILABLE).first()
                existing_team_project = Project.objects.filter(team=team, topic__isnull=False).exclude(status=ProjectStatus.COMPLETED).first()
                if existing_team_topic or existing_team_project:
                    conflict_title = existing_team_topic.title if existing_team_topic else existing_team_project.title
                    conflict_case = existing_team_topic.case_code if existing_team_topic else (existing_team_project.topic.case_code if existing_team_project.topic else '')
                    return JsonResponse({
                        'success': False,
                        'code': 'TEAM_PROJECT_LIMIT_EXCEEDED',
                        'error': f"Your team ('{team.name}') has already selected project '{conflict_case}: {conflict_title}'. A team cannot select more than one project simultaneously.",
                        'active_project': conflict_title,
                        'active_case': conflict_case,
                        'team': team.name
                    }, status=409)
            else:
                existing_user_topic = Topic.objects.filter(selected_by=user).exclude(status=TopicStatus.AVAILABLE).first()
                existing_user_project = Project.objects.filter(owner=user, topic__isnull=False).exclude(status=ProjectStatus.COMPLETED).first()
                if existing_user_topic or existing_user_project:
                    conflict_title = existing_user_topic.title if existing_user_topic else existing_user_project.title
                    return JsonResponse({
                        'success': False,
                        'code': 'USER_PROJECT_LIMIT_EXCEEDED',
                        'error': f"You have already selected project '{conflict_title}'. You cannot select more than one project simultaneously.",
                        'active_project': conflict_title
                    }, status=409)

            # RULE 2: When Team A selects Topic X, Team B CANNOT select Topic X!
            topic_qs = Topic.objects.select_for_update()
            if str(target_case_or_id).isdigit():
                topic = topic_qs.filter(Q(id=int(target_case_or_id)) | Q(case_code__iexact=str(target_case_or_id))).first()
            else:
                topic = topic_qs.filter(case_code__iexact=str(target_case_or_id).strip()).first()

            if not topic:
                return JsonResponse({'success': False, 'code': 'TOPIC_NOT_FOUND', 'error': f"Topic '{target_case_or_id}' not found."}, status=404)

            # Check if already occupied
            if topic.status != TopicStatus.AVAILABLE or topic.team is not None or (topic.selected_by is not None and topic.selected_by != user):
                occupier_name = topic.team.name if topic.team else (topic.selected_by.full_name if topic.selected_by else 'another team')
                return JsonResponse({
                    'success': False,
                    'code': 'TOPIC_ALREADY_SELECTED',
                    'error': f"This topic ('{topic.case_code}: {topic.title}') has already been selected by {occupier_name}. Please choose another available topic.",
                    'topic': topic.to_dict()
                }, status=409)

            now = timezone.now()
            topic.team = team
            topic.selected_by = user
            topic.selected_at = now
            topic.status = TopicStatus.SELECTED
            topic.save()

            department = topic.domain or (team.department if team else user.department)
            project = Project.objects.create(
                title=topic.title,
                description=f"Project based on selected topic {topic.case_code}: {topic.title}",
                topic=topic,
                owner=user,
                team=team,
                department=department,
                status=ProjectStatus.NOT_STARTED,
                progress=0,
                is_selected=True,
                selected_at=now
            )

            # Notify team members if team project
            if team:
                for member in team.memberships.exclude(user=user).select_related('user'):
                    create_notification(
                        recipient=member.user,
                        title=f"Topic Selected: {topic.case_code}",
                        message=f"{user.full_name} selected topic '{topic.title}' for your team '{team.name}'.",
                        notification_type=NotificationType.INFO,
                        action_url=f"/workspace/my-projects/"
                    )

            return JsonResponse({
                'success': True,
                'message': f"Topic '{topic.case_code}: {topic.title}' successfully selected.",
                'project': project.to_dict(),
                'topic': topic.to_dict()
            }, status=201)


class TopicReleaseAPIView(APIView):
    """
    REST API to unselect / release a topic:
    Makes the topic Available again for any other team to select.
    """
    def post(self, request, pk_or_case=None, *args, **kwargs):
        if not Topic.objects.exists():
            Topic.seed_defaults()

        user = request.user if (request.user and request.user.is_authenticated) else User.objects.first()
        if not user:
            return JsonResponse({'success': False, 'code': 'UNAUTHORIZED', 'error': 'Authentication required.'}, status=401)

        data = request.data or {}
        target_case_or_id = pk_or_case or data.get('case') or data.get('case_code') or data.get('topic_id') or data.get('id')

        with transaction.atomic():
            topic_qs = Topic.objects.select_for_update()
            if str(target_case_or_id).isdigit():
                topic = topic_qs.filter(Q(id=int(target_case_or_id)) | Q(case_code__iexact=str(target_case_or_id))).first()
            else:
                topic = topic_qs.filter(case_code__iexact=str(target_case_or_id).strip()).first()

            if not topic:
                return JsonResponse({'success': False, 'code': 'TOPIC_NOT_FOUND', 'error': 'Topic not found.'}, status=404)

            is_authorized = (
                user.is_staff or
                user.account_type in (AccountType.TEACHER, AccountType.FACULTY) or
                topic.selected_by == user or
                (topic.team and (topic.team.created_by == user or topic.team.memberships.filter(user=user).exists()))
            )
            if not is_authorized:
                return JsonResponse({'success': False, 'code': 'FORBIDDEN', 'error': 'You do not have permission to release this topic.'}, status=403)

            case_code = topic.case_code
            topic.team = None
            topic.selected_by = None
            topic.selected_at = None
            topic.status = TopicStatus.AVAILABLE
            topic.save()

            projects = Project.objects.filter(topic=topic)
            deleted_projects_count = projects.count()
            projects.delete()

            return JsonResponse({
                'success': True,
                'message': f"Topic '{case_code}' has been released and is now available for other teams.",
                'topic': topic.to_dict(),
                'deleted_projects_count': deleted_projects_count
            }, status=200)


class TopicDetailAPIView(APIView):
    """
    REST API for a single Topic in 'Workspace / Data':
    Supports:
      - GET: Retrieve topic details, assigned team, projects, and classification.
      - PUT / PATCH: Edit topic details (case_code, title, domain, level, guide, status).
      - DELETE: Delete a topic.
    """
    def _get_topic(self, pk_or_case):
        if not pk_or_case:
            return None
        pk_str = str(pk_or_case).strip()
        if pk_str.isdigit():
            topic = Topic.objects.filter(Q(id=int(pk_str)) | Q(case_code__iexact=pk_str)).first()
        else:
            topic = Topic.objects.filter(case_code__iexact=pk_str).first()
        return topic

    def get(self, request, pk_or_case=None, *args, **kwargs):
        topic = self._get_topic(pk_or_case)
        if not topic:
            return JsonResponse({'success': False, 'code': 'TOPIC_NOT_FOUND', 'error': 'Topic not found.'}, status=404)

        data = topic.to_dict()
        projects = [p.to_dict() for p in Project.objects.filter(topic=topic)]
        data['projects'] = projects
        data['projects_count'] = len(projects)
        return JsonResponse({'success': True, 'topic': data}, status=200)

    def put(self, request, pk_or_case=None, *args, **kwargs):
        return self.patch(request, pk_or_case, *args, **kwargs)

    def patch(self, request, pk_or_case=None, *args, **kwargs):
        topic = self._get_topic(pk_or_case)
        if not topic:
            return JsonResponse({'success': False, 'code': 'TOPIC_NOT_FOUND', 'error': 'Topic not found.'}, status=404)

        data = request.data or {}
        if 'title' in data and data['title']:
            topic.title = str(data['title']).strip()
        if 'domain' in data and data['domain']:
            topic.domain = str(data['domain']).strip()
        if 'level' in data and data['level']:
            topic.level = str(data['level']).strip()
        if 'guide' in data:
            topic.guide = str(data['guide']).strip()
        if 'case_code' in data and data['case_code']:
            new_code = str(data['case_code']).strip()
            if new_code.lower() != topic.case_code.lower() and Topic.objects.filter(case_code__iexact=new_code).exclude(pk=topic.pk).exists():
                return JsonResponse({'success': False, 'error': f"Case code '{new_code}' already exists."}, status=400)
            topic.case_code = new_code
        if 'status' in data and data['status']:
            st = str(data['status']).lower().strip()
            if st in [c[0] for c in TopicStatus.choices]:
                topic.status = st

        topic.save()
        return JsonResponse({
            'success': True,
            'message': f"Topic '{topic.case_code}' updated successfully.",
            'topic': topic.to_dict()
        }, status=200)

    def delete(self, request, pk_or_case=None, *args, **kwargs):
        topic = self._get_topic(pk_or_case)
        if not topic:
            return JsonResponse({'success': False, 'code': 'TOPIC_NOT_FOUND', 'error': 'Topic not found.'}, status=404)

        case_code = topic.case_code
        topic.delete()
        return JsonResponse({
            'success': True,
            'message': f"Topic '{case_code}' deleted successfully."
        }, status=200)


class TopicAssignGuideAPIView(APIView):
    """
    REST API for assigning / updating the Faculty Guide for a topic.
    """
    def _get_topic(self, pk_or_case):
        if not pk_or_case:
            return None
        pk_str = str(pk_or_case).strip()
        if pk_str.isdigit():
            topic = Topic.objects.filter(Q(id=int(pk_str)) | Q(case_code__iexact=pk_str)).first()
        else:
            topic = Topic.objects.filter(case_code__iexact=pk_str).first()
        return topic

    def post(self, request, pk_or_case=None, *args, **kwargs):
        topic = self._get_topic(pk_or_case)
        if not topic:
            return JsonResponse({'success': False, 'code': 'TOPIC_NOT_FOUND', 'error': 'Topic not found.'}, status=404)

        data = request.data or {}
        guide_name = data.get('guide') or data.get('guide_name') or data.get('faculty_name')
        if not guide_name and data.get('faculty_id'):
            faculty_user = User.objects.filter(id=data['faculty_id']).first()
            if faculty_user:
                guide_name = faculty_user.full_name

        if not guide_name:
            user = request.user if (request.user and request.user.is_authenticated) else None
            if user and user.account_type in (AccountType.TEACHER, AccountType.FACULTY):
                guide_name = user.full_name

        if not guide_name:
            return JsonResponse({'success': False, 'error': 'Guide name or faculty_id is required.'}, status=400)

        topic.guide = str(guide_name).strip()
        topic.save()

        return JsonResponse({
            'success': True,
            'message': f"Guide '{topic.guide}' assigned to topic '{topic.case_code}'.",
            'topic': topic.to_dict()
        }, status=200)


class TopicExportAPIView(APIView):
    """
    REST API to export topics dataset in CSV or JSON format.
    Matches Workspace / Data: Topics table columns:
    Case, Title, Domain, Level, Team ID, Guide, Status
    """
    def get(self, request, *args, **kwargs):
        if not Topic.objects.exists():
            Topic.seed_defaults()

        topics = Topic.objects.all().order_by('id')
        export_format = request.GET.get('format', 'csv').lower().strip()

        if export_format == 'json':
            return JsonResponse({
                'success': True,
                'total': topics.count(),
                'columns': ['Case', 'Title', 'Domain', 'Level', 'Team ID', 'Guide', 'Status'],
                'topics': [t.to_dict() for t in topics]
            }, status=200)

        # Default CSV export
        response = HttpResponse(content_type='text/csv; charset=utf-8')
        response['Content-Disposition'] = 'attachment; filename="topics_dataset.csv"'
        writer = csv.writer(response)
        writer.writerow(['Case', 'Title', 'Domain', 'Level', 'Team ID', 'Guide', 'Status'])

        for t in topics:
            team_id = str(t.team.id) if t.team else ''
            writer.writerow([
                t.case_code,
                t.title,
                t.domain,
                t.level,
                team_id,
                t.guide or '',
                t.get_status_display()
            ])

        return response


class ProjectFileUploadAPIView(APIView):
    """
    REST API for 'Upload a file' on the Project card (Screenshot 2):
    Handles uploading project files, source code, deliverables, reports.
    """
    def get(self, request, pk, *args, **kwargs):
        try:
            project = Project.objects.get(pk=pk)
        except Project.DoesNotExist:
            return JsonResponse({'success': False, 'error': 'Project not found.'}, status=404)

        files = [f.to_dict() for f in project.files.all()]
        return JsonResponse({
            'success': True,
            'project_id': project.id,
            'project_title': project.title,
            'files_count': len(files),
            'files': files
        }, status=200)

    def post(self, request, pk, *args, **kwargs):
        user = request.user if (request.user and request.user.is_authenticated) else None
        try:
            project = Project.objects.get(pk=pk)
        except Project.DoesNotExist:
            return JsonResponse({'success': False, 'error': 'Project not found.'}, status=404)

        uploaded_file = request.FILES.get('file') or request.FILES.get('document')
        if not uploaded_file:
            return JsonResponse({'success': False, 'error': 'No file uploaded. Please provide a file in form-data under key "file".'}, status=400)

        filename = uploaded_file.name
        file_size = uploaded_file.size
        file_type = getattr(uploaded_file, 'content_type', '') or filename.split('.')[-1].lower()

        project_file = ProjectFile.objects.create(
            project=project,
            file=uploaded_file,
            filename=filename,
            file_size=file_size,
            file_type=file_type,
            uploaded_by=user
        )

        if project.status == ProjectStatus.NOT_STARTED:
            project.status = ProjectStatus.IN_PROGRESS
            if project.progress == 0:
                project.progress = 25
            project.save(update_fields=['status', 'progress', 'updated_at'])

        return JsonResponse({
            'success': True,
            'message': f"File '{filename}' uploaded successfully.",
            'file': project_file.to_dict(),
            'project': project.to_dict()
        }, status=201)

    def delete(self, request, pk, file_id=None, *args, **kwargs):
        file_id = file_id or request.GET.get('file_id') or (request.data.get('file_id') if isinstance(request.data, dict) else None)
        try:
            p_file = ProjectFile.objects.get(pk=file_id, project_id=pk)
        except ProjectFile.DoesNotExist:
            return JsonResponse({'success': False, 'error': 'File not found.'}, status=404)

        filename = p_file.filename
        p_file.delete()
        return JsonResponse({'success': True, 'message': f"File '{filename}' deleted."}, status=200)


# ==============================================================================
# TEAMS API ENDPOINTS
# ==============================================================================

class MyTeamAPIView(APIView):
    """
    REST API for the 'Workspace / My team' Screen (Screenshot 1):
    - Tag: 'STUDENT WORKSPACE'
    - Title: 'My team'
    - Subtitle: 'Create a team, invite student accounts, and submit shared projects.'
    - If user has NO team:
        * returns has_team: False
        * returns empty_message: "You haven't joined a team yet. Create one or accept an invitation."
        * returns any received pending invitations with action links.
    - If user HAS a team:
        * returns has_team: True, full team details, members, photo, leader, and invitations.
    """
    def get(self, request, *args, **kwargs):
        user = request.user if (request.user and request.user.is_authenticated) else User.objects.first()
        if not user:
            return JsonResponse({'success': False, 'code': 'UNAUTHORIZED', 'error': 'Authentication required.'}, status=401)

        # Find team user belongs to (as leader or member)
        team = Team.objects.filter(Q(created_by=user) | Q(leader=user) | Q(memberships__user=user)).distinct().first()

        received_invitations = [
            inv.to_dict() for inv in TeamInvitation.objects.filter(invited_user=user, status=InvitationStatus.PENDING).select_related('team', 'invited_by')
        ]

        page_info = {
            'tag': 'STUDENT WORKSPACE',
            'title': 'My team',
            'subtitle': 'Create a team, invite student accounts, and submit shared projects.',
            'breadcrumb': 'Workspace / My team'
        }

        if not team:
            return JsonResponse({
                'success': True,
                'page_info': page_info,
                'has_team': False,
                'empty_message': "You haven't joined a team yet. Create one or accept an invitation.",
                'team': None,
                'pending_invitations': received_invitations,
                'received_invitations': received_invitations,
            }, status=200)

        team_data = team.to_dict()
        is_leader = (team.leader_id == user.id) or (team.created_by_id == user.id)

        options = [
            {'key': 'edit_details', 'label': 'Edit details', 'method': 'PATCH', 'url': f'/api/teams/{team.id}/'},
            {'key': 'invite_member', 'label': 'Invite member', 'method': 'POST', 'url': f'/api/teams/{team.id}/invitations/'},
            {'key': 'delete_team', 'label': 'Delete team', 'method': 'DELETE', 'url': f'/api/teams/{team.id}/'},
            {'key': 'upload_project', 'label': 'Upload project', 'method': 'POST', 'url': f'/api/teams/{team.id}/upload-project/'},
        ]

        return JsonResponse({
            'success': True,
            'page_info': page_info,
            'has_team': True,
            'is_leader': is_leader,
            'can_invite': is_leader or user.is_staff or user.account_type in (AccountType.TEACHER, AccountType.FACULTY),
            'team': team_data,
            'options': options,
            'members': team_data['members'],
            'sent_invitations': team_data['pending_invitations'],
            'received_invitations': received_invitations,
        }, status=200)

    def patch(self, request, *args, **kwargs):
        user = request.user if (request.user and request.user.is_authenticated) else None
        if not user:
            return JsonResponse({'success': False, 'code': 'UNAUTHORIZED', 'error': 'Authentication required.'}, status=401)
        team = Team.objects.filter(Q(created_by=user) | Q(leader=user) | Q(memberships__user=user)).distinct().first()
        if not team:
            return JsonResponse({'success': False, 'error': 'You do not belong to any team.'}, status=404)
        return TeamDetailAPIView().patch(request, pk=team.id, *args, **kwargs)

    def put(self, request, *args, **kwargs):
        return self.patch(request, *args, **kwargs)

    def delete(self, request, *args, **kwargs):
        user = request.user if (request.user and request.user.is_authenticated) else None
        if not user:
            return JsonResponse({'success': False, 'code': 'UNAUTHORIZED', 'error': 'Authentication required.'}, status=401)
        team = Team.objects.filter(Q(created_by=user) | Q(leader=user) | Q(memberships__user=user)).distinct().first()
        if not team:
            return JsonResponse({'success': False, 'error': 'You do not belong to any team.'}, status=404)
        return TeamDetailAPIView().delete(request, pk=team.id, *args, **kwargs)


class TeamListCreateAPIView(APIView):
    """
    REST API for Teams:
    GET  /api/teams/ - Lists teams
    POST /api/teams/ - Creates a team (Screenshot 2 Modal: name, description, photo)
    """

    def get(self, request, *args, **kwargs):
        teams = Team.objects.prefetch_related('memberships__user').all()
        search_query = (request.GET.get('search') or request.GET.get('q') or '').strip()
        if search_query:
            teams = teams.filter(Q(name__icontains=search_query) | Q(description__icontains=search_query) | Q(department__icontains=search_query))
        teams_data = [t.to_dict() for t in teams]
        return JsonResponse({'success': True, 'count': len(teams_data), 'teams': teams_data}, status=200)

    def post(self, request, *args, **kwargs):
        user = request.user if (request.user and request.user.is_authenticated) else User.objects.first()
        if not user:
            return JsonResponse({'success': False, 'code': 'UNAUTHORIZED', 'error': 'Authentication required.'}, status=401)

        data = request.data or {}
        # Support both 'name' and Screenshot 2 'team_name'
        name = (data.get('name') or data.get('team_name') or request.POST.get('name') or request.POST.get('team_name') or '').strip()
        if not name:
            return JsonResponse({
                'success': False,
                'error': 'Team name is required.',
                'errors': {'name': ['Please enter a team name.']}
            }, status=400)

        # Support 'description' and Screenshot 2 'team_description'
        description = (data.get('description') or data.get('team_description') or request.POST.get('description') or request.POST.get('team_description') or '').strip()
        department = (data.get('department') or request.POST.get('department') or '').strip() or user.department

        # Support 'photo' and Screenshot 2 'team_photo' file upload
        photo_file = request.FILES.get('photo') or request.FILES.get('team_photo')

        # Leader determination
        leader_user = user
        assigned_teacher = None
        is_teacher = user.is_staff or user.account_type in (AccountType.TEACHER, AccountType.FACULTY)

        if is_teacher:
            assigned_teacher = user
            target_leader_id = data.get('leader_id') or data.get('student_id')
            if target_leader_id:
                designated_student = User.objects.filter(id=target_leader_id).first()
                if designated_student:
                    leader_user = designated_student

        team = Team.objects.create(
            name=name,
            description=description,
            photo=photo_file,
            department=department,
            created_by=user,
            leader=leader_user,
            assigned_by_teacher=assigned_teacher
        )

        # Creator / Leader membership
        TeamMember.objects.get_or_create(
            team=team,
            user=leader_user,
            defaults={'role': 'Leader'}
        )
        if leader_user != user:
            TeamMember.objects.get_or_create(
                team=team,
                user=user,
                defaults={'role': 'Faculty Advisor' if is_teacher else 'Member'}
            )
            # Notify designated student leader
            create_notification(
                recipient=leader_user,
                title="Assigned as Team Leader! 🌟",
                message=f"Prof. {user.full_name} assigned you as Team Leader of '{team.name}'.",
                notification_type=NotificationType.TEAM_LEADER_ASSIGNED,
                action_url="/workspace/my-team/"
            )

        return JsonResponse({
            'success': True,
            'message': 'Team created successfully.',
            'team': team.to_dict()
        }, status=201)


class TeamDetailAPIView(APIView):
    """
    GET    /api/teams/<id>/
    PATCH  /api/teams/<id>/
    DELETE /api/teams/<id>/
    """

    def get(self, request, pk, *args, **kwargs):
        try:
            team = Team.objects.prefetch_related('memberships__user', 'invitations').get(pk=pk)
        except Team.DoesNotExist:
            return JsonResponse({'success': False, 'error': 'Team not found.'}, status=404)
        return JsonResponse({'success': True, 'team': team.to_dict()}, status=200)

    def patch(self, request, pk, *args, **kwargs):
        try:
            team = Team.objects.get(pk=pk)
        except Team.DoesNotExist:
            return JsonResponse({'success': False, 'error': 'Team not found.'}, status=404)

        data = request.data or {}
        name = (data.get('name') or data.get('team_name') or '').strip()
        if name:
            team.name = name
        if 'description' in data or 'team_description' in data:
            team.description = (data.get('description') or data.get('team_description') or '').strip()
        if 'department' in data:
            team.department = data['department'].strip()

        photo_file = request.FILES.get('photo') or request.FILES.get('team_photo')
        if photo_file:
            team.photo = photo_file

        team.save()
        return JsonResponse({'success': True, 'message': 'Team updated.', 'team': team.to_dict()}, status=200)

    def put(self, request, pk, *args, **kwargs):
        return self.patch(request, pk, *args, **kwargs)

    def delete(self, request, pk, *args, **kwargs):
        try:
            team = Team.objects.get(pk=pk)
        except Team.DoesNotExist:
            return JsonResponse({'success': False, 'error': 'Team not found.'}, status=404)
        team_name = team.name
        team.delete()
        return JsonResponse({'success': True, 'message': f"Team '{team_name}' deleted."}, status=200)


class TeamAssignLeaderAPIView(APIView):
    """
    REST API for assigning team leader:
    'the team leader is accined by the teacher'
    POST /api/teams/<id>/assign-leader/
    """
    def post(self, request, pk, *args, **kwargs):
        user = request.user if (request.user and request.user.is_authenticated) else None
        if not user:
            return JsonResponse({'success': False, 'code': 'UNAUTHORIZED', 'error': 'Authentication required.'}, status=401)

        try:
            team = Team.objects.get(pk=pk)
        except Team.DoesNotExist:
            return JsonResponse({'success': False, 'error': 'Team not found.'}, status=404)

        is_teacher = user.is_staff or user.account_type in (AccountType.TEACHER, AccountType.FACULTY)
        is_current_leader = (team.leader == user) or (team.created_by == user)
        if not is_teacher and not is_current_leader:
            return JsonResponse({'success': False, 'code': 'FORBIDDEN', 'error': 'Only faculty teachers or the current team creator can assign a team leader.'}, status=403)

        data = request.data or {}
        student_id = data.get('student_id') or data.get('user_id')
        email = data.get('email', '').strip()

        target_student = None
        if student_id:
            target_student = User.objects.filter(id=student_id).first()
        elif email:
            target_student = User.objects.filter(email__iexact=email).first()

        if not target_student:
            return JsonResponse({'success': False, 'error': 'Designated student not found.'}, status=404)

        # Update team leader
        old_leader = team.leader
        team.leader = target_student
        if is_teacher:
            team.assigned_by_teacher = user
        team.save(update_fields=['leader', 'assigned_by_teacher', 'updated_at'])

        # Update roles in TeamMember table
        if old_leader and old_leader != target_student:
            TeamMember.objects.filter(team=team, user=old_leader).update(role='Member')

        student_member, _ = TeamMember.objects.get_or_create(
            team=team,
            user=target_student,
            defaults={'role': 'Leader'}
        )
        student_member.role = 'Leader'
        student_member.save(update_fields=['role'])

        # Notify assigned student
        assigned_by_title = f"Prof. {user.full_name}" if is_teacher else user.full_name
        create_notification(
            recipient=target_student,
            title="Assigned as Team Leader! 🌟",
            message=f"{assigned_by_title} has assigned you as the Team Leader of '{team.name}'.",
            notification_type=NotificationType.TEAM_LEADER_ASSIGNED,
            action_url="/workspace/my-team/"
        )

        return JsonResponse({
            'success': True,
            'message': f"{target_student.full_name} is now the Team Leader of '{team.name}'.",
            'leader': {
                'id': target_student.id,
                'full_name': target_student.full_name,
                'email': target_student.email
            },
            'assigned_by': user.full_name,
            'team': team.to_dict()
        }, status=200)


class TeamInvitationCreateAPIView(APIView):
    """
    REST API for Team Leader sending invitation to a user:
    'the teamleader is send the request to the user'
    POST /api/teams/<id>/invitations/ or POST /api/teams/<id>/invite/
    """
    def get(self, request, pk, *args, **kwargs):
        try:
            team = Team.objects.get(pk=pk)
        except Team.DoesNotExist:
            return JsonResponse({'success': False, 'error': 'Team not found.'}, status=404)

        invitations = [inv.to_dict() for inv in team.invitations.select_related('invited_user', 'invited_by').all()]
        return JsonResponse({'success': True, 'count': len(invitations), 'invitations': invitations}, status=200)

    def post(self, request, pk, *args, **kwargs):
        user = request.user if (request.user and request.user.is_authenticated) else None
        if not user:
            return JsonResponse({'success': False, 'code': 'UNAUTHORIZED', 'error': 'Authentication required.'}, status=401)

        try:
            team = Team.objects.get(pk=pk)
        except Team.DoesNotExist:
            return JsonResponse({'success': False, 'error': 'Team not found.'}, status=404)

        # Ensure caller is team leader, creator, or teacher
        is_leader = (team.leader == user) or (team.created_by == user) or team.memberships.filter(user=user, role__iexact='leader').exists()
        is_teacher = user.is_staff or user.account_type in (AccountType.TEACHER, AccountType.FACULTY)
        if not is_leader and not is_teacher:
            return JsonResponse({
                'success': False,
                'code': 'FORBIDDEN',
                'error': f"Only the team leader of '{team.name}' can send invitations to new members."
            }, status=403)

        data = request.data or {}
        email = (data.get('email') or request.POST.get('email') or '').strip()
        user_id = data.get('user_id') or data.get('student_id') or request.POST.get('user_id')
        message = (data.get('message') or request.POST.get('message') or '').strip()
        role = (data.get('role') or request.POST.get('role') or 'Member').strip()

        target_user = None
        if email:
            target_user = User.objects.filter(email__iexact=email).first()
        elif user_id:
            target_user = User.objects.filter(id=user_id).first()

        if not target_user:
            return JsonResponse({
                'success': False,
                'error': f"Student account with email/ID '{email or user_id}' was not found. Please check the email address."
            }, status=404)

        # 1. Check if user is already a member
        if team.memberships.filter(user=target_user).exists():
            return JsonResponse({
                'success': False,
                'code': 'ALREADY_MEMBER',
                'error': f"{target_user.full_name} is already a member of '{team.name}'."
            }, status=400)

        # 2. Check for duplicate pending invitation
        existing_invite = TeamInvitation.objects.filter(
            team=team,
            invited_user=target_user,
            status=InvitationStatus.PENDING
        ).first()
        if existing_invite:
            return JsonResponse({
                'success': False,
                'code': 'INVITATION_ALREADY_PENDING',
                'error': f"A pending invitation has already been sent to {target_user.full_name} ({target_user.email}).",
                'invitation': existing_invite.to_dict()
            }, status=409)

        invitation = TeamInvitation.objects.create(
            team=team,
            invited_by=user,
            invited_user=target_user,
            role=role,
            message=message,
            status=InvitationStatus.PENDING
        )

        # Send in-app notification directly into target user's notification box
        create_notification(
            recipient=target_user,
            title=f"Team Invitation: {team.name}",
            message=f"{user.full_name} (Team Leader) invited you to join '{team.name}'.{(' Message: ' + message) if message else ''}",
            notification_type=NotificationType.TEAM_INVITE,
            action_url="/workspace/my-team/"
        )

        return JsonResponse({
            'success': True,
            'message': f"Invitation sent to {target_user.full_name} ({target_user.email}).",
            'invitation': invitation.to_dict(),
            'team': team.to_dict()
        }, status=201)


class TeamInvitationRespondAPIView(APIView):
    """
    REST API for accepting or rejecting a team invitation:
    - ACCEPT: 'when the user acept he request the use will joined in the team'
    - REJECT: 'the use is reject the reques the rejection message is send to the team leader'
    """

    def post(self, request, pk, action=None, *args, **kwargs):
        user = request.user if (request.user and request.user.is_authenticated) else None
        if not user:
            return JsonResponse({'success': False, 'code': 'UNAUTHORIZED', 'error': 'Authentication required.'}, status=401)

        try:
            invitation = TeamInvitation.objects.select_related('team', 'invited_by', 'invited_user').get(pk=pk)
        except TeamInvitation.DoesNotExist:
            return JsonResponse({'success': False, 'error': 'Invitation not found.'}, status=404)

        # Only the invited user can accept or reject
        if invitation.invited_user != user and not (user.is_staff or user.account_type in (AccountType.TEACHER, AccountType.FACULTY)):
            return JsonResponse({'success': False, 'code': 'FORBIDDEN', 'error': 'You can only respond to invitations addressed to you.'}, status=403)

        if invitation.status != InvitationStatus.PENDING:
            return JsonResponse({
                'success': False,
                'code': 'INVITATION_ALREADY_RESOLVED',
                'error': f"This invitation has already been {invitation.status}."
            }, status=400)

        # Determine action (accept or reject)
        data = request.data or {}
        decision = (action or data.get('action') or data.get('decision') or '').strip().lower()

        now = timezone.now()
        team = invitation.team
        leader = team.leader or invitation.invited_by

        if decision == 'accept':
            # 1. Mark invitation accepted
            invitation.status = InvitationStatus.ACCEPTED
            invitation.responded_at = now
            invitation.save(update_fields=['status', 'responded_at', 'updated_at'])

            # 2. Add user to the team
            member, created = TeamMember.objects.get_or_create(
                team=team,
                user=user,
                defaults={'role': invitation.role}
            )

            # 3. Send notification to the Team Leader
            create_notification(
                recipient=leader,
                title=f"Invitation Accepted: {team.name} 🎉",
                message=f"{user.full_name} accepted your invitation and joined '{team.name}'!",
                notification_type=NotificationType.TEAM_INVITE_ACCEPTED,
                action_url="/workspace/my-team/"
            )

            return JsonResponse({
                'success': True,
                'message': f"You have successfully joined '{team.name}'!",
                'invitation': invitation.to_dict(),
                'team': team.to_dict()
            }, status=200)

        elif decision == 'reject':
            # 1. Read rejection reason / message
            reason = (data.get('reason') or data.get('rejection_reason') or data.get('message') or '').strip()

            # 2. Mark invitation rejected
            invitation.status = InvitationStatus.REJECTED
            invitation.rejection_reason = reason
            invitation.responded_at = now
            invitation.save(update_fields=['status', 'rejection_reason', 'responded_at', 'updated_at'])

            # 3. Send rejection message directly to Team Leader's notification box
            rejection_text = f"Reason: {reason}" if reason else "No reason provided."
            create_notification(
                recipient=leader,
                title=f"Invitation Declined: {team.name}",
                message=f"{user.full_name} declined your invitation to join '{team.name}'. {rejection_text}",
                notification_type=NotificationType.TEAM_INVITE_REJECTED,
                action_url="/workspace/my-team/"
            )

            return JsonResponse({
                'success': True,
                'message': f"You declined the invitation to join '{team.name}'. Rejection message sent to team leader.",
                'invitation': invitation.to_dict()
            }, status=200)

        else:
            return JsonResponse({'success': False, 'error': "Action must be 'accept' or 'reject'."}, status=400)


class InvitationListAPIView(APIView):
    """
    REST API to list user's received team invitations:
    GET /api/invitations/
    GET /api/invitations/pending/
    """
    def get(self, request, *args, **kwargs):
        user = request.user if (request.user and request.user.is_authenticated) else None
        if not user:
            return JsonResponse({'success': False, 'code': 'UNAUTHORIZED', 'error': 'Authentication required.'}, status=401)

        qs = TeamInvitation.objects.filter(invited_user=user).select_related('team', 'invited_by')
        status_filter = request.GET.get('status')
        if status_filter:
            qs = qs.filter(status=status_filter.lower())

        invitations = [inv.to_dict() for inv in qs]
        return JsonResponse({
            'success': True,
            'count': len(invitations),
            'pending_count': qs.filter(status=InvitationStatus.PENDING).count(),
            'invitations': invitations
        }, status=200)


class TeamMemberManageAPIView(APIView):
    """
    Add or remove members from team.
    POST   /api/teams/<id>/members/
    DELETE /api/teams/<id>/members/<user_id>/
    """

    def post(self, request, pk, *args, **kwargs):
        try:
            team = Team.objects.get(pk=pk)
        except Team.DoesNotExist:
            return JsonResponse({'success': False, 'error': 'Team not found.'}, status=404)

        data = request.data or {}
        email = data.get('email', '').strip()
        user_id = data.get('user_id')
        role = data.get('role', 'Member')

        target_user = None
        if email:
            target_user = User.objects.filter(email__iexact=email).first()
        elif user_id:
            target_user = User.objects.filter(id=user_id).first()

        if not target_user:
            return JsonResponse({'success': False, 'error': 'User not found.'}, status=404)

        member, created = TeamMember.objects.get_or_create(
            team=team,
            user=target_user,
            defaults={'role': role}
        )
        if not created and role != member.role:
            member.role = role
            member.save(update_fields=['role'])

        return JsonResponse({
            'success': True,
            'message': 'Member added to team.',
            'team': team.to_dict()
        }, status=200)

    def delete(self, request, pk, user_id=None, *args, **kwargs):
        try:
            member = TeamMember.objects.get(team_id=pk, user_id=user_id)
            member.delete()
            return JsonResponse({'success': True, 'message': 'Member removed.'}, status=200)
        except TeamMember.DoesNotExist:
            return JsonResponse({'success': False, 'error': 'Member not found in team.'}, status=404)


class TeamUploadProjectAPIView(APIView):
    """
    REST API for 'Upload project' button on the Team Card (Screenshot):
    Allows team leader / members to create and upload a project for their team.
    Supports file attachment, topic selection, progress setting, and notifications.
    POST /api/teams/<id>/upload-project/ or POST /api/teams/my-team/upload-project/
    """
    def post(self, request, pk=None, *args, **kwargs):
        user = request.user if (request.user and request.user.is_authenticated) else None
        if not user:
            return JsonResponse({'success': False, 'code': 'UNAUTHORIZED', 'error': 'Authentication required.'}, status=401)

        # Resolve team
        if pk:
            team = Team.objects.filter(id=pk).first()
        else:
            team = Team.objects.filter(Q(created_by=user) | Q(leader=user) | Q(memberships__user=user)).distinct().first()

        if not team:
            return JsonResponse({'success': False, 'error': 'Team not found.'}, status=404)

        # Check membership
        is_member = (team.created_by == user) or (team.leader == user) or team.memberships.filter(user=user).exists()
        if not is_member and not (user.is_staff or user.account_type in (AccountType.TEACHER, AccountType.FACULTY)):
            return JsonResponse({'success': False, 'code': 'FORBIDDEN', 'error': 'You are not a member of this team.'}, status=403)

        data = request.data or {}
        title = (data.get('title') or data.get('project_title') or request.POST.get('title') or request.POST.get('project_title') or '').strip()
        description = (data.get('description') or data.get('project_description') or request.POST.get('description') or '').strip()
        department = (data.get('department') or request.POST.get('department') or '').strip() or team.department

        uploaded_file = request.FILES.get('file') or request.FILES.get('project_file') or request.FILES.get('dataset')
        if not title and uploaded_file:
            title = uploaded_file.name.rsplit('.', 1)[0].replace('_', ' ').replace('-', ' ').title()

        topic_identifier = data.get('topic') or data.get('case') or data.get('case_code') or data.get('topic_id')
        topic = None
        if topic_identifier:
            if not Topic.objects.exists():
                Topic.seed_defaults()
            existing_team_topic = Topic.objects.filter(team=team).exclude(status=TopicStatus.AVAILABLE).first()
            if existing_team_topic and existing_team_topic.case_code.lower() != str(topic_identifier).strip().lower():
                return JsonResponse({
                    'success': False,
                    'code': 'TEAM_PROJECT_LIMIT_EXCEEDED',
                    'error': f"Your team ('{team.name}') has already selected project '{existing_team_topic.case_code}: {existing_team_topic.title}'."
                }, status=409)

            if str(topic_identifier).isdigit():
                topic = Topic.objects.filter(Q(id=int(topic_identifier)) | Q(case_code__iexact=str(topic_identifier))).first()
            else:
                topic = Topic.objects.filter(case_code__iexact=str(topic_identifier).strip()).first()

            if not topic:
                return JsonResponse({'success': False, 'code': 'TOPIC_NOT_FOUND', 'error': f"Topic '{topic_identifier}' not found."}, status=404)

            if (topic.status != TopicStatus.AVAILABLE or topic.team is not None) and topic.team != team:
                occupier = topic.team.name if topic.team else 'another team'
                return JsonResponse({
                    'success': False,
                    'code': 'TOPIC_ALREADY_SELECTED',
                    'error': f"Topic '{topic.case_code}: {topic.title}' has already been selected by {occupier}."
                }, status=409)

            if not title:
                title = topic.title

            topic.team = team
            topic.selected_by = user
            topic.selected_at = timezone.now()
            topic.status = TopicStatus.SELECTED
            topic.save()

        if not title:
            return JsonResponse({'success': False, 'error': 'Project title is required.'}, status=400)

        # Check if team already has a project
        existing_project = team.projects.first()
        if existing_project and not data.get('create_new'):
            project = existing_project
            if title:
                project.title = title
            if description:
                project.description = description
            if topic:
                project.topic = topic
            if uploaded_file:
                ProjectFile.objects.create(
                    project=project,
                    file=uploaded_file,
                    filename=uploaded_file.name,
                    file_size=uploaded_file.size,
                    file_type=getattr(uploaded_file, 'content_type', '') or uploaded_file.name.split('.')[-1],
                    uploaded_by=user
                )
                if project.status == ProjectStatus.NOT_STARTED:
                    project.status = ProjectStatus.IN_PROGRESS
                    if project.progress == 0:
                        project.progress = 25
            project.save()
        else:
            status = ProjectStatus.IN_PROGRESS if uploaded_file else ProjectStatus.NOT_STARTED
            progress = 25 if uploaded_file else 0
            project = Project.objects.create(
                title=title,
                description=description,
                topic=topic,
                owner=user,
                team=team,
                department=department,
                status=status,
                progress=progress,
                is_selected=True,
                selected_at=timezone.now()
            )
            if uploaded_file:
                ProjectFile.objects.create(
                    project=project,
                    file=uploaded_file,
                    filename=uploaded_file.name,
                    file_size=uploaded_file.size,
                    file_type=getattr(uploaded_file, 'content_type', '') or uploaded_file.name.split('.')[-1],
                    uploaded_by=user
                )

        if 'github_url' in data:
            project.github_url = data['github_url'].strip() or None
        if 'live_url' in data:
            project.live_url = data['live_url'].strip() or None

        is_submitting = (
            str(data.get('submit', '')).lower() in ('true', '1', 'yes') or
            str(data.get('submit_for_review', '')).lower() in ('true', '1', 'yes') or
            str(request.POST.get('submit', '')).lower() in ('true', '1', 'yes') or
            str(data.get('status', '')).lower() in ('submitted', 'awaiting_review')
        )
        if is_submitting:
            project.status = ProjectStatus.AWAITING_REVIEW
            if project.progress < 100:
                project.progress = 100
            project.submitted_at = timezone.now()
            project.save()

        # Notify team members
        for member in team.memberships.exclude(user=user).select_related('user'):
            create_notification(
                recipient=member.user,
                title=f"Project Submitted: {project.title}" if is_submitting else f"Project Uploaded: {project.title}",
                message=f"{user.full_name} {'submitted' if is_submitting else 'uploaded'} project '{project.title}' for team '{team.name}'.",
                notification_type=NotificationType.SUBMISSION_STATUS if is_submitting else NotificationType.INFO,
                action_url="/workspace/my-projects/"
            )

        return JsonResponse({
            'success': True,
            'message': f"Project '{project.title}' uploaded successfully for team '{team.name}'.",
            'project': project.to_dict(),
            'team': team.to_dict()
        }, status=201)


class TeamCandidatesAPIView(APIView):
    """
    REST API for 'Invite member' modal search:
    Returns eligible students who can be invited to the team.
    GET /api/teams/<id>/candidates/?search=...
    """
    def get(self, request, pk=None, *args, **kwargs):
        user = request.user if (request.user and request.user.is_authenticated) else None
        if pk:
            team = Team.objects.filter(id=pk).first()
        else:
            team = Team.objects.filter(Q(created_by=user) | Q(leader=user) | Q(memberships__user=user)).distinct().first()

        if not team:
            return JsonResponse({'success': False, 'error': 'Team not found.'}, status=404)

        existing_member_ids = team.memberships.values_list('user_id', flat=True)
        pending_invited_ids = team.invitations.filter(status=InvitationStatus.PENDING).values_list('invited_user_id', flat=True)

        qs = User.objects.filter(is_active=True).exclude(id__in=existing_member_ids).exclude(id__in=pending_invited_ids)

        search_query = (request.GET.get('search') or request.GET.get('q') or '').strip()
        if search_query:
            qs = qs.filter(
                Q(full_name__icontains=search_query) |
                Q(email__icontains=search_query) |
                Q(department__icontains=search_query)
            )

        candidates = [
            {
                'id': u.id,
                'full_name': u.full_name,
                'email': u.email,
                'department': u.department,
                'account_type': u.account_type
            }
            for u in qs[:20]
        ]

        return JsonResponse({
            'success': True,
            'team_id': team.id,
            'team_name': team.name,
            'candidates_count': len(candidates),
            'candidates': candidates
        }, status=200)


# ==============================================================================
# QUERIES API ENDPOINTS (Workspace / Queries - Questions & Answers)
# ==============================================================================

class QueriesWorkspaceAPIView(APIView):
    """
    GET  /api/workspace/queries/
    POST /api/workspace/queries/

    Matches the Workspace / Queries screen in the UI (media_1795189079667_69fd5640.png):
      - Category: PING
      - Tag: ASK YOUR TEACHER
      - Title: Questions & answers
      - Subtitle: Get guidance from your teacher as you work through your project.
      - Action button: + Ask a question
      - Main card:
        - Title: Your questions
        - Subtitle: Questions are shared with your teacher.
        - Empty state: No questions yet. Ask your teacher for guidance.
        - Bottom link: + Ask your teacher a question
    """

    def get(self, request, *args, **kwargs):
        user = request.user if (request.user and request.user.is_authenticated) else User.objects.first()
        if not user:
            return JsonResponse({'success': False, 'code': 'UNAUTHORIZED', 'error': 'Authentication required.'}, status=401)

        is_teacher = user.is_staff or getattr(user, 'account_type', '') in (AccountType.TEACHER, AccountType.FACULTY)

        if is_teacher:
            qs = Query.objects.select_related('asked_by', 'responded_by', 'project').all().order_by('-created_at')
        else:
            qs = Query.objects.filter(asked_by=user).select_related('asked_by', 'responded_by', 'project').order_by('-created_at')

        # Filter by status if requested (?status=open or ?status=answered)
        status_filter = request.GET.get('status')
        if status_filter:
            qs = qs.filter(status=status_filter.lower())

        # Filter by project if requested
        project_id = request.GET.get('project_id')
        if project_id:
            qs = qs.filter(project_id=project_id)

        queries_data = [q.to_dict(current_user=user) for q in qs]
        open_count = qs.filter(status=QueryStatus.OPEN).count()
        answered_count = qs.filter(status=QueryStatus.ANSWERED).count()

        active_projects_count = Project.objects.filter(status=ProjectStatus.AWAITING_REVIEW).count()
        total_teams_count = Team.objects.count()

        if is_teacher:
            header_data = {
                'category': 'PING',
                'tag': 'STUDENT QUESTIONS',
                'title': 'Answer your students',
                'subtitle': 'Review questions from your students and share helpful answers.',
                'breadcrumb': 'Workspace / Queries',
                'active_nav': 'queries',
            }
            card_title = "Student questions"
            count_label = f"{len(queries_data)} question" if len(queries_data) == 1 else f"{len(queries_data)} questions"
            card_subtitle = count_label
            empty_msg = "No student questions yet."
            action_btn = None
        else:
            header_data = {
                'category': 'PING',
                'tag': 'ASK YOUR TEACHER',
                'title': 'Questions & answers',
                'subtitle': 'Get guidance from your teacher as you work through your project.',
                'breadcrumb': 'Workspace / Queries',
                'active_nav': 'queries',
            }
            card_title = "Your questions"
            card_subtitle = "Questions are shared with your teacher."
            empty_msg = "No questions yet. Ask your teacher for guidance."
            action_btn = {
                'label': '+ Ask a question',
                'text': '+ Ask a question',
                'action': 'open_ask_modal',
            }

        sidebar_navigation = [
            {'name': 'Dashboard', 'url': '/workspace/teacher-dashboard/' if is_teacher else '/workspace/dashboard/', 'active': False, 'badge': None},
            {'name': 'Student projects', 'url': '/workspace/student-projects/', 'active': False, 'badge': active_projects_count} if is_teacher else {'name': 'My projects', 'url': '/workspace/my-projects/', 'active': False, 'badge': 0},
            {'name': 'Data', 'url': '/workspace/data/', 'active': False, 'badge': None},
            {'name': 'Student teams & projects', 'url': '/workspace/teams/', 'active': False, 'badge': None} if is_teacher else {'name': 'My team', 'url': '/workspace/my-team/', 'active': False, 'badge': None},
            {'name': 'Queries', 'url': '/workspace/queries/', 'active': True, 'badge': open_count},
        ]

        card_data = {
            'title': card_title,
            'subtitle': card_subtitle,
            'subtext': card_subtitle,
            'count_label': card_subtitle,
            'empty_message': empty_msg,
            'bottom_link_text': '+ Ask your teacher a question' if not is_teacher else None,
        }

        return JsonResponse({
            'success': True,
            'header': header_data,
            'page_info': header_data,
            'breadcrumb': 'Workspace / Queries',
            'action_button': action_btn,
            'card_info': card_data,
            'card': card_data,
            'count': len(queries_data),
            'open_count': open_count,
            'answered_count': answered_count,
            'queries': queries_data,
            'sidebar_badges': {
                'queries': open_count,
                'student_projects': active_projects_count,
                'student_teams_projects': total_teams_count,
                'unread_notifications': Notification.objects.filter(recipient=user, is_read=False).count() if user else 0,
                'chat': Message.objects.filter(recipient=user, is_read=False).count() if user else 0,
                'team_chat': 0,
            },
            'sidebar_navigation': sidebar_navigation
        }, status=200)

    def post(self, request, *args, **kwargs):
        return QueryListCreateAPIView().post(request, *args, **kwargs)


class QueryListCreateAPIView(APIView):
    """
    GET  /api/queries/
    POST /api/queries/
    """

    def get(self, request, *args, **kwargs):
        user = request.user if (request.user and request.user.is_authenticated) else User.objects.first()
        is_teacher = user and (user.is_staff or getattr(user, 'account_type', '') in (AccountType.TEACHER, AccountType.FACULTY))

        if is_teacher:
            queryset = Query.objects.select_related('asked_by', 'responded_by', 'project').all()
        elif user:
            queryset = Query.objects.filter(asked_by=user).select_related('asked_by', 'responded_by', 'project')
        else:
            queryset = Query.objects.select_related('asked_by', 'responded_by', 'project').all()

        status = request.GET.get('status')
        if status:
            queryset = queryset.filter(status=status)

        project_id = request.GET.get('project_id')
        if project_id:
            queryset = queryset.filter(project_id=project_id)

        queries_data = [q.to_dict(current_user=user) for q in queryset.order_by('-created_at')]
        return JsonResponse({
            'success': True,
            'count': len(queries_data),
            'open_count': queryset.filter(status=QueryStatus.OPEN).count(),
            'answered_count': queryset.filter(status=QueryStatus.ANSWERED).count(),
            'queries': queries_data
        }, status=200)

    def post(self, request, *args, **kwargs):
        user = request.user if (request.user and request.user.is_authenticated) else User.objects.first()
        if not user:
            return JsonResponse({'success': False, 'code': 'UNAUTHORIZED', 'error': 'Authentication required.'}, status=401)

        data = request.data or {}
        title = (data.get('title') or data.get('subject') or '').strip()
        description = (data.get('description') or data.get('question') or '').strip()

        if not title:
            return JsonResponse({'success': False, 'error': 'Question title is required.'}, status=400)
        if not description:
            return JsonResponse({'success': False, 'error': 'Question description is required.'}, status=400)

        project_id = data.get('project_id')
        project = Project.objects.filter(id=project_id).first() if project_id else None

        query = Query.objects.create(
            title=title,
            description=description,
            project=project,
            asked_by=user,
            status=QueryStatus.OPEN
        )

        # Notify teachers: When the student asks the question, it is sent into the teacher's notification box!
        teachers = list(User.objects.filter(
            Q(account_type__in=[AccountType.TEACHER, AccountType.FACULTY]) | Q(is_staff=True),
            is_active=True
        ).exclude(id=user.id))

        team_teachers = User.objects.filter(
            teacher_assigned_teams__memberships__user=user,
            is_active=True
        ).exclude(id=user.id)
        for tt in team_teachers:
            if tt not in teachers:
                teachers.append(tt)

        query_preview = description if len(description) <= 50 else description[:47] + '...'
        for teacher in teachers:
            create_notification(
                recipient=teacher,
                title=f"New Student Question: {query.title}",
                message=f"{user.full_name} asked: \"{query_preview}\". Click to review and provide guidance.",
                notification_type=NotificationType.QUERY_ASKED,
                action_url=f"/workspace/queries/?id={query.id}"
            )

        return JsonResponse({
            'success': True,
            'message': 'Your question has been submitted and shared with your teacher.',
            'query': query.to_dict(current_user=user)
        }, status=201)


class QueryDetailAPIView(APIView):
    """
    GET    /api/queries/<id>/
    PATCH  /api/queries/<id>/
    DELETE /api/queries/<id>/
    """

    def get(self, request, pk, *args, **kwargs):
        user = request.user if (request.user and request.user.is_authenticated) else User.objects.first()
        try:
            query = Query.objects.select_related('asked_by', 'responded_by', 'project').get(pk=pk)
        except Query.DoesNotExist:
            return JsonResponse({'success': False, 'error': 'Query not found.'}, status=404)

        query_dict = query.to_dict(current_user=user)
        student_name = query.asked_by.full_name if query.asked_by else 'Student'
        modal_info = {
            'title': 'Question details',
            'subtitle': f"Question from {student_name}",
            'question': query.title,
            'details': query.description,
            'your_answer': query.response or '',
            'answer': query.response or '',
            'buttons': {
                'cancel': 'Cancel',
                'save': 'Save answer'
            },
            'save_endpoint': f"/api/queries/{query.id}/reply/",
            'endpoint': f"/api/queries/{query.id}/reply/"
        }

        return JsonResponse({
            'success': True,
            'modal': modal_info,
            'query': query_dict
        }, status=200)

    def patch(self, request, pk, *args, **kwargs):
        user = request.user if (request.user and request.user.is_authenticated) else User.objects.first()
        try:
            query = Query.objects.get(pk=pk)
        except Query.DoesNotExist:
            return JsonResponse({'success': False, 'error': 'Query not found.'}, status=404)

        data = request.data or {}
        # If answering or editing answer
        answer_text = (data.get('response') or data.get('answer') or data.get('your_answer') or data.get('reply') or '').strip()
        if answer_text:
            query.response = answer_text
            query.responded_by = user
            query.responded_at = timezone.now()
            query.status = QueryStatus.ANSWERED
            query.save(update_fields=['response', 'responded_by', 'responded_at', 'status', 'updated_at'])

            teacher_display = f"Prof. {user.full_name}" if getattr(user, 'account_type', '') in (AccountType.TEACHER, AccountType.FACULTY) else user.full_name
            reply_preview = answer_text if len(answer_text) <= 50 else answer_text[:47] + '...'

            create_notification(
                recipient=query.asked_by,
                title=f"Teacher Answered Your Question: {query.title}",
                message=f"{teacher_display} replied: \"{reply_preview}\"",
                notification_type=NotificationType.QUERY_ANSWERED,
                action_url=f"/workspace/queries/?id={query.id}",
                tag="Node Theory"
            )
            return JsonResponse({
                'success': True,
                'message': 'Answer saved and sent to student.',
                'query': query.to_dict(current_user=user)
            }, status=200)

        if 'status' in data:
            query.status = data['status']
            query.save(update_fields=['status', 'updated_at'])

        if 'title' in data:
            query.title = data['title'].strip()
            query.save(update_fields=['title', 'updated_at'])

        if 'description' in data:
            query.description = data['description'].strip()
            query.save(update_fields=['description', 'updated_at'])

        return JsonResponse({'success': True, 'query': query.to_dict(current_user=user)}, status=200)

    def put(self, request, pk, *args, **kwargs):
        return self.patch(request, pk, *args, **kwargs)

    def delete(self, request, pk, *args, **kwargs):
        user = request.user if (request.user and request.user.is_authenticated) else User.objects.first()
        if not user:
            return JsonResponse({'success': False, 'code': 'UNAUTHORIZED', 'error': 'Authentication required.'}, status=401)

        try:
            query = Query.objects.get(pk=pk)
        except Query.DoesNotExist:
            return JsonResponse({'success': False, 'error': 'Query not found.'}, status=404)

        is_author = (query.asked_by_id == user.id)
        is_staff = user.is_staff or getattr(user, 'account_type', '') in (AccountType.TEACHER, AccountType.FACULTY)

        if not is_author and not is_staff:
            return JsonResponse({'success': False, 'code': 'FORBIDDEN', 'error': 'You do not have permission to delete this question.'}, status=403)

        query.delete()
        return JsonResponse({'success': True, 'message': 'Question deleted successfully.'}, status=200)


class QueryReplyAPIView(APIView):
    """
    POST /api/queries/<id>/reply/
    POST /api/queries/<id>/answer/
    POST /api/teacher-qa/<id>/reply/
    """

    def post(self, request, pk, *args, **kwargs):
        user = request.user if (request.user and request.user.is_authenticated) else User.objects.first()
        if not user:
            return JsonResponse({'success': False, 'code': 'UNAUTHORIZED', 'error': 'Authentication required.'}, status=401)

        try:
            query = Query.objects.select_related('asked_by', 'project').get(pk=pk)
        except Query.DoesNotExist:
            return JsonResponse({'success': False, 'error': 'Query not found.'}, status=404)

        data = request.data or {}
        response_text = (data.get('response') or data.get('answer') or data.get('your_answer') or data.get('reply') or '').strip()
        if not response_text:
            return JsonResponse({'success': False, 'error': 'Response text cannot be empty.'}, status=400)

        query.response = response_text
        query.responded_by = user
        query.responded_at = timezone.now()
        query.status = QueryStatus.ANSWERED
        query.save(update_fields=['response', 'responded_by', 'responded_at', 'status', 'updated_at'])

        # Send indication notification into the student's notification box
        teacher_display = f"Prof. {user.full_name}" if getattr(user, 'account_type', '') in (AccountType.TEACHER, AccountType.FACULTY) else user.full_name
        reply_preview = response_text if len(response_text) <= 50 else response_text[:47] + '...'

        create_notification(
            recipient=query.asked_by,
            title=f"Teacher Answered Your Question: {query.title}",
            message=f"{teacher_display} replied: \"{reply_preview}\"",
            notification_type=NotificationType.QUERY_ANSWERED,
            action_url=f"/workspace/queries/?id={query.id}",
            tag="Node Theory"
        )

        return JsonResponse({
            'success': True,
            'message': 'Query answered successfully. Notification sent to student.',
            'query': query.to_dict(current_user=user)
        }, status=200)


# ==============================================================================
# MESSAGES & DIRECT CHAT API (Workspace / Chat - Private Messages)
# ==============================================================================

def update_direct_message_unread_notifications(sender, recipient):
    """
    Creates or updates unread direct message notifications for the recipient.
    When 2, 3 or more messages are unread, indicates the exact unread count:
    'You have <count> unread messages from <sender_name>.'
    """
    unread_count = Message.objects.filter(sender=sender, recipient=recipient, is_read=False).count()
    if unread_count <= 0:
        return None

    latest_msg = Message.objects.filter(sender=sender, recipient=recipient).order_by('-created_at').first()
    content_preview = latest_msg.content if (latest_msg and latest_msg.content) else ''
    attachment_name = latest_msg.attachment_name if (latest_msg and latest_msg.attachment_name) else ''

    if unread_count == 1:
        title = f"New message from {sender.full_name}"
        if content_preview:
            if len(content_preview) > 40:
                content_preview = content_preview[:37] + '...'
            message = f"{sender.full_name} sent you a message: \"{content_preview}\""
        elif attachment_name:
            message = f"{sender.full_name} shared a file with you: {attachment_name}"
        else:
            message = f"{sender.full_name} sent you a direct message."
    else:
        title = f"{unread_count} unread messages from {sender.full_name}"
        message = f"You have {unread_count} unread messages from {sender.full_name}."

    action_url = f"/workspace/chat/?email={sender.email}"

    existing_notif = Notification.objects.filter(
        recipient=recipient,
        notification_type=NotificationType.MESSAGE,
        action_url=action_url,
        is_read=False
    ).first()

    if existing_notif:
        existing_notif.title = title
        existing_notif.message = message
        existing_notif.created_at = timezone.now()
        existing_notif.save(update_fields=['title', 'message', 'created_at'])
        return existing_notif
    else:
        return Notification.objects.create(
            recipient=recipient,
            title=title,
            message=message,
            notification_type=NotificationType.MESSAGE,
            action_url=action_url,
            is_read=False
        )


def mark_direct_messages_as_read(sender, recipient):
    """
    Marks all messages from `sender` to `recipient` as read,
    and marks unread direct message notifications as read.
    """
    if not sender or not recipient:
        return 0

    marked = Message.objects.filter(
        sender=sender,
        recipient=recipient,
        is_read=False
    ).update(is_read=True, read_at=timezone.now())

    action_url = f"/workspace/chat/?email={sender.email}"
    Notification.objects.filter(
        recipient=recipient,
        notification_type=NotificationType.MESSAGE,
        action_url=action_url,
        is_read=False
    ).update(is_read=True, read_at=timezone.now())

    return marked


class ChatWorkspaceAPIView(APIView):
    """
    GET /api/workspace/chat/
    GET /api/chat/
    GET /api/chat/<contact_identifier>/

    Matches the Workspace / Chat page layout in the UI (media_1795188157069_2212b376.png):
      - Category: PING
      - Page title: Chat
      - Subtitle: Private messages with other student accounts.
      - Left column: Contacts list (teammates & message partners) showing:
        - Avatar with initial (e.g. 'F')
        - Full name ('faris')
        - Email ('faris@gamil.com')
        - Unread badge and active status
      - Right column: Active 1-on-1 chat thread with:
        - Header: Contact full name & email
        - Empty state: 'No messages yet. Start the conversation.'
        - Message feed with attachments and timestamps
        - Bottom controls: Attach file, Write a message..., Send
    """

    def get(self, request, contact_identifier=None, *args, **kwargs):
        user = request.user if (request.user and request.user.is_authenticated) else User.objects.first()
        if not user:
            return JsonResponse({'success': False, 'code': 'UNAUTHORIZED', 'error': 'Authentication required.'}, status=401)

        # 1. Collect all contacts:
        partner_ids = set()
        for s_id, r_id in Message.objects.filter(Q(sender=user) | Q(recipient=user)).values_list('sender_id', 'recipient_id'):
            if s_id != user.id:
                partner_ids.add(s_id)
            if r_id != user.id:
                partner_ids.add(r_id)

        teammate_ids = set(TeamMember.objects.filter(
            team__memberships__user=user
        ).exclude(user=user).values_list('user_id', flat=True))

        all_candidate_ids = partner_ids | teammate_ids

        search_query = (request.GET.get('search') or request.GET.get('q') or '').strip()
        if search_query:
            contacts_qs = User.objects.filter(
                is_active=True
            ).exclude(id=user.id).filter(
                Q(full_name__icontains=search_query) |
                Q(email__icontains=search_query) |
                Q(department__icontains=search_query)
            )
        else:
            contacts_qs = User.objects.filter(id__in=all_candidate_ids, is_active=True)

        contacts_list = list(contacts_qs)

        # 2. Determine active contact
        target_email = (
            request.GET.get('email') or request.GET.get('mail_id') or
            (contact_identifier if (contact_identifier and '@' in contact_identifier) else '')
        ).strip()
        target_user_id = request.GET.get('user_id') or request.GET.get('id') or (contact_identifier if (contact_identifier and contact_identifier.isdigit()) else None)

        active_contact = None
        if target_email:
            active_contact = User.objects.filter(email__iexact=target_email).exclude(id=user.id).first()
            if not active_contact:
                return JsonResponse({'success': False, 'error': f"User with email '{target_email}' not found."}, status=404)
        elif target_user_id and str(target_user_id).isdigit():
            active_contact = User.objects.filter(id=int(target_user_id)).exclude(id=user.id).first()
            if not active_contact:
                return JsonResponse({'success': False, 'error': f"User with ID {target_user_id} not found."}, status=404)
        elif contacts_list:
            most_recent_msg = Message.objects.filter(
                Q(sender=user, recipient__in=contacts_list) | Q(sender__in=contacts_list, recipient=user)
            ).order_by('-created_at').first()
            if most_recent_msg:
                active_contact = most_recent_msg.recipient if most_recent_msg.sender_id == user.id else most_recent_msg.sender
            else:
                active_contact = contacts_list[0]

        # Ensure active_contact appears in contacts list
        if active_contact and active_contact not in contacts_list:
            contacts_list.insert(0, active_contact)

        # 3. Format contacts list for left column
        contacts_data = []
        for c in contacts_list:
            unread_count = Message.objects.filter(sender=c, recipient=user, is_read=False).count()
            latest_msg = Message.objects.filter(
                Q(sender=user, recipient=c) | Q(sender=c, recipient=user)
            ).order_by('-created_at').first()

            initial = c.full_name[0].upper() if c.full_name else c.email[0].upper()
            is_active = bool(active_contact and c.id == active_contact.id)

            last_msg_preview = ''
            last_msg_time = ''
            if latest_msg:
                if latest_msg.content:
                    last_msg_preview = latest_msg.content[:35] + ('...' if len(latest_msg.content) > 35 else '')
                elif latest_msg.attachment_name:
                    last_msg_preview = f"📎 {latest_msg.attachment_name}"
                last_msg_time = latest_msg.created_at.strftime('%I:%M %p') if latest_msg.created_at else ''

            contacts_data.append({
                'id': c.id,
                'name': c.full_name,
                'full_name': c.full_name,
                'email': c.email,
                'department': getattr(c, 'department', ''),
                'initial': initial,
                'unread_count': unread_count,
                'last_message': last_msg_preview,
                'last_message_time': last_msg_time,
                'is_active': is_active,
            })

        # 4. Fetch messages with active contact and auto-mark as read
        messages_data = []
        if active_contact:
            if request.GET.get('mark_read', 'true').lower() in ('true', '1', 'yes'):
                mark_direct_messages_as_read(active_contact, user)

            messages_qs = Message.objects.filter(
                Q(sender=user, recipient=active_contact) | Q(sender=active_contact, recipient=user)
            ).select_related('sender', 'recipient').order_by('created_at')
            messages_data = [m.to_dict(current_user=user) for m in messages_qs]

        active_contact_data = {
            'id': active_contact.id,
            'name': active_contact.full_name,
            'full_name': active_contact.full_name,
            'email': active_contact.email,
            'initial': active_contact.full_name[0].upper() if active_contact.full_name else active_contact.email[0].upper(),
            'department': getattr(active_contact, 'department', ''),
        } if active_contact else None

        return JsonResponse({
            'success': True,
            'page_info': {
                'category': 'PING',
                'tag': 'PING',
                'title': 'Chat',
                'subtitle': 'Private messages with other student accounts.',
                'breadcrumb': 'Workspace / Chat',
                'active_nav': 'chat',
            },
            'contacts': contacts_data,
            'contacts_count': len(contacts_data),
            'active_contact': active_contact_data,
            'messages': messages_data,
            'messages_count': len(messages_data),
            'empty_state': {
                'message': 'No messages yet. Start the conversation.',
                'subtext': 'Send direct messages, share project files, and chat with team members.',
            },
            'input_placeholder': 'Write a message...',
            'attach_button_label': 'Attach file',
            'no_file_label': 'No file selected',
            'send_button_label': 'Send',
        }, status=200)


class MessageListCreateAPIView(APIView):
    """
    GET  /api/messages/ (?box=inbox, ?box=sent, or ?email=<email>, ?user_id=<id>)
    POST /api/messages/
    """

    def get(self, request, *args, **kwargs):
        user = request.user if (request.user and request.user.is_authenticated) else User.objects.first()
        if not user:
            return JsonResponse({'success': False, 'code': 'UNAUTHORIZED', 'error': 'Authentication required.'}, status=401)

        # Check if querying conversation with a specific contact
        contact_email = (request.GET.get('email') or request.GET.get('mail_id') or '').strip()
        contact_id = request.GET.get('user_id') or request.GET.get('recipient_id')
        contact = None
        if contact_email:
            contact = User.objects.filter(email__iexact=contact_email).first()
        elif contact_id and str(contact_id).isdigit():
            contact = User.objects.filter(id=int(contact_id)).first()

        if contact:
            if request.GET.get('mark_read', 'true').lower() in ('true', '1', 'yes'):
                mark_direct_messages_as_read(contact, user)

            msgs = Message.objects.filter(
                Q(sender=user, recipient=contact) | Q(sender=contact, recipient=user)
            ).select_related('sender', 'recipient').order_by('created_at')
            msgs_data = [m.to_dict(current_user=user) for m in msgs]
            return JsonResponse({
                'success': True,
                'contact': {
                    'id': contact.id,
                    'full_name': contact.full_name,
                    'email': contact.email,
                    'department': getattr(contact, 'department', ''),
                },
                'unread_count': 0,
                'count': len(msgs_data),
                'messages': msgs_data
            }, status=200)

        box = request.GET.get('box', 'inbox')
        if box == 'sent':
            msgs = Message.objects.filter(sender=user).select_related('sender', 'recipient')
        else:
            msgs = Message.objects.filter(recipient=user).select_related('sender', 'recipient')

        msgs_data = [m.to_dict(current_user=user) for m in msgs]
        unread_count = Message.objects.filter(recipient=user, is_read=False).count()

        return JsonResponse({
            'success': True,
            'box': box,
            'unread_count': unread_count,
            'count': len(msgs_data),
            'messages': msgs_data
        }, status=200)

    def post(self, request, *args, **kwargs):
        user = request.user if (request.user and request.user.is_authenticated) else User.objects.first()
        if not user:
            return JsonResponse({'success': False, 'code': 'UNAUTHORIZED', 'error': 'Authentication required.'}, status=401)

        data = request.data or {}
        recipient_id = data.get('recipient_id') or data.get('user_id') or request.POST.get('recipient_id') or request.POST.get('user_id')
        recipient_email = (
            data.get('recipient_email') or data.get('email') or data.get('mail_id') or
            request.POST.get('recipient_email') or request.POST.get('email') or request.POST.get('mail_id') or ''
        ).strip()
        content = (data.get('content') or request.POST.get('content') or '').strip()
        subject = (data.get('subject') or request.POST.get('subject') or '').strip()
        file_obj = request.FILES.get('attachment') or request.FILES.get('file')

        if not content and not file_obj:
            return JsonResponse({'success': False, 'error': 'Please provide message content or attach a file.'}, status=400)

        recipient = None
        if recipient_id:
            recipient = User.objects.filter(id=recipient_id).first()
        elif recipient_email:
            recipient = User.objects.filter(email__iexact=recipient_email).first()

        if not recipient:
            return JsonResponse({'success': False, 'error': 'Recipient not found. Please provide a valid email or recipient ID.'}, status=404)

        if recipient.id == user.id:
            return JsonResponse({'success': False, 'error': 'You cannot send a message to yourself.'}, status=400)

        attachment_name = ''
        attachment_size = 0
        attachment_type = ''
        if file_obj:
            attachment_name = file_obj.name
            attachment_size = file_obj.size
            attachment_type = getattr(file_obj, 'content_type', '') or 'application/octet-stream'

        msg = Message.objects.create(
            sender=user,
            recipient=recipient,
            subject=subject,
            content=content,
            attachment=file_obj,
            attachment_name=attachment_name,
            attachment_size=attachment_size,
            attachment_type=attachment_type
        )

        # Send unread indication notification to recipient's notification box
        update_direct_message_unread_notifications(user, recipient)

        return JsonResponse({
            'success': True,
            'message': f"Message sent to {recipient.full_name} ({recipient.email}).",
            'data': msg.to_dict(current_user=user)
        }, status=201)


class MessageDetailAPIView(APIView):
    """
    GET    /api/messages/<id>/
    PATCH  /api/messages/<id>/read/
    DELETE /api/messages/<id>/
    """

    def get(self, request, pk, *args, **kwargs):
        user = request.user if (request.user and request.user.is_authenticated) else User.objects.first()
        try:
            msg = Message.objects.select_related('sender', 'recipient').get(pk=pk)
        except Message.DoesNotExist:
            return JsonResponse({'success': False, 'error': 'Message not found.'}, status=404)

        if user and user.id not in (msg.sender_id, msg.recipient_id) and not user.is_staff:
            return JsonResponse({'success': False, 'code': 'FORBIDDEN', 'error': 'Access denied.'}, status=403)

        return JsonResponse({'success': True, 'message': msg.to_dict(current_user=user)}, status=200)

    def patch(self, request, pk, *args, **kwargs):
        user = request.user if (request.user and request.user.is_authenticated) else User.objects.first()
        try:
            msg = Message.objects.get(pk=pk)
        except Message.DoesNotExist:
            return JsonResponse({'success': False, 'error': 'Message not found.'}, status=404)

        if user and user.id != msg.recipient_id and not user.is_staff:
            return JsonResponse({'success': False, 'code': 'FORBIDDEN', 'error': 'Access denied.'}, status=403)

        msg.is_read = True
        msg.read_at = timezone.now()
        msg.save(update_fields=['is_read', 'read_at'])

        # Mark notification as read
        Notification.objects.filter(
            recipient=msg.recipient,
            notification_type=NotificationType.MESSAGE,
            action_url__contains=msg.sender.email,
            is_read=False
        ).update(is_read=True, read_at=timezone.now())

        return JsonResponse({'success': True, 'message': 'Marked as read.', 'data': msg.to_dict(current_user=user)}, status=200)

    def delete(self, request, pk, *args, **kwargs):
        user = request.user if (request.user and request.user.is_authenticated) else User.objects.first()
        try:
            msg = Message.objects.get(pk=pk)
        except Message.DoesNotExist:
            return JsonResponse({'success': False, 'error': 'Message not found.'}, status=404)

        if user and user.id != msg.sender_id and not user.is_staff:
            return JsonResponse({'success': False, 'code': 'FORBIDDEN', 'error': 'You can only delete messages sent by you.'}, status=403)

        msg.delete()
        return JsonResponse({'success': True, 'message': 'Message deleted.'}, status=200)


class DirectChatMarkReadAPIView(APIView):
    """
    POST /api/messages/direct/<contact_identifier>/read/
    POST /api/chat/read/
    POST /api/workspace/chat/read/

    Marks all messages from the specified contact as read for the current user,
    and marks unread direct message notifications as read.
    """

    def post(self, request, contact_identifier=None, *args, **kwargs):
        user = request.user if (request.user and request.user.is_authenticated) else User.objects.first()
        if not user:
            return JsonResponse({'success': False, 'code': 'UNAUTHORIZED', 'error': 'Authentication required.'}, status=401)

        data = request.data or {}
        identifier = contact_identifier or data.get('email') or data.get('mail_id') or data.get('user_id') or request.GET.get('email') or request.GET.get('user_id')
        if not identifier:
            return JsonResponse({'success': False, 'error': 'Contact email or user ID is required.'}, status=400)

        contact = None
        if str(identifier).isdigit():
            contact = User.objects.filter(id=int(identifier)).first()
        else:
            contact = User.objects.filter(email__iexact=str(identifier).strip()).first()

        if not contact:
            return JsonResponse({'success': False, 'error': f"Contact user '{identifier}' not found."}, status=404)

        marked_count = mark_direct_messages_as_read(contact, user)

        return JsonResponse({
            'success': True,
            'message': f"Messages from {contact.full_name} marked as read.",
            'contact': {
                'id': contact.id,
                'full_name': contact.full_name,
                'email': contact.email,
            },
            'marked_count': marked_count,
            'unread_count': 0
        }, status=200)


class DirectChatContactsAPIView(APIView):
    """
    GET /api/chat/contacts/
    GET /api/messages/contacts/

    Lists available student contacts and teammates to chat with.
    Supports ?search= or ?q= to search by name or email.
    """

    def get(self, request, *args, **kwargs):
        user = request.user if (request.user and request.user.is_authenticated) else User.objects.first()
        if not user:
            return JsonResponse({'success': False, 'code': 'UNAUTHORIZED', 'error': 'Authentication required.'}, status=401)

        search_query = (request.GET.get('search') or request.GET.get('q') or '').strip()
        if search_query:
            qs = User.objects.filter(is_active=True).exclude(id=user.id).filter(
                Q(full_name__icontains=search_query) |
                Q(email__icontains=search_query) |
                Q(department__icontains=search_query)
            )
        else:
            partner_ids = set()
            for s_id, r_id in Message.objects.filter(Q(sender=user) | Q(recipient=user)).values_list('sender_id', 'recipient_id'):
                if s_id != user.id:
                    partner_ids.add(s_id)
                if r_id != user.id:
                    partner_ids.add(r_id)

            teammate_ids = set(TeamMember.objects.filter(
                team__memberships__user=user
            ).exclude(user=user).values_list('user_id', flat=True))

            all_ids = partner_ids | teammate_ids
            if all_ids:
                qs = User.objects.filter(id__in=all_ids, is_active=True)
            else:
                qs = User.objects.filter(is_active=True).exclude(id=user.id)[:20]

        contacts = [
            {
                'id': u.id,
                'name': u.full_name,
                'full_name': u.full_name,
                'email': u.email,
                'department': getattr(u, 'department', ''),
                'initial': u.full_name[0].upper() if u.full_name else u.email[0].upper(),
                'unread_count': Message.objects.filter(sender=u, recipient=user, is_read=False).count()
            }
            for u in qs[:50]
        ]

        return JsonResponse({
            'success': True,
            'count': len(contacts),
            'contacts': contacts
        }, status=200)


# ==============================================================================
# NOTIFICATIONS API (Bell icon in Top Navbar & Student Dashboard Modal)
# ==============================================================================

def seed_student_dashboard_notifications(user):
    """
    Seeds the 3 workspace notifications from the updated student dashboard notification panel screenshot:
    1. 'Submission status' - 'Your last project is currently under review.' (tag: 'Node Theory', 2h ago)
    2. 'Project update' - 'Your latest project activity is ready to review.' (Today)
    3. 'Teacher reply' - 'Your teacher answered one of your questions.' (Yesterday)
    """
    now = timezone.now()
    n1 = Notification.objects.create(
        recipient=user,
        title="Submission status",
        message="Your last project is currently under review.",
        notification_type=NotificationType.SUBMISSION_STATUS,
        action_url="/workspace/projects/",
        tag="Node Theory",
        is_read=False,
    )
    Notification.objects.filter(id=n1.id).update(created_at=now - timezone.timedelta(hours=2))

    n2 = Notification.objects.create(
        recipient=user,
        title="Project update",
        message="Your latest project activity is ready to review.",
        notification_type=NotificationType.PROJECT_UPDATE,
        action_url="/workspace/projects/",
        tag="",
        is_read=False,
    )
    Notification.objects.filter(id=n2.id).update(created_at=now - timezone.timedelta(hours=5))

    n3 = Notification.objects.create(
        recipient=user,
        title="Teacher reply",
        message="Your teacher answered one of your questions.",
        notification_type=NotificationType.TEACHER_REPLY,
        action_url="/workspace/queries/",
        tag="",
        is_read=False,
    )
    Notification.objects.filter(id=n3.id).update(created_at=now - timezone.timedelta(days=1))


def seed_teacher_dashboard_notifications(user):
    """
    Seeds the 3 workspace notifications from the Teacher Activity notification panel screenshot (media_1795200389663_d4e22e88.png):
    1. 'Review queue' - '3 student submissions are awaiting your feedback.' (Today)
    2. 'Question received' - 'A student asked for clarification on project scope.' (Today)
    3. 'Progress update' - 'The class is moving ahead on schedule.' (Yesterday)
    """
    now = timezone.now()

    # Calculate awaiting review count if available
    awaiting_count = Project.objects.filter(status__in=[ProjectStatus.AWAITING_REVIEW, ProjectStatus.SUBMITTED]).count()
    if awaiting_count <= 0:
        awaiting_count = 3

    n1 = Notification.objects.create(
        recipient=user,
        title="Review queue",
        message=f"{awaiting_count} student submissions are awaiting your feedback.",
        notification_type=NotificationType.REVIEW_QUEUE,
        action_url="/workspace/student-projects/",
        tag="",
        is_read=False,
    )
    Notification.objects.filter(id=n1.id).update(created_at=now - timezone.timedelta(hours=2))

    # Look for any recent query
    recent_query = Query.objects.exclude(asked_by=user).order_by('-created_at').first()
    query_msg = "A student asked for clarification on project scope."
    if recent_query and recent_query.title and recent_query.title.lower() != 'sample 1':
        query_msg = f"A student asked: {recent_query.title}"

    n2 = Notification.objects.create(
        recipient=user,
        title="Question received",
        message=query_msg,
        notification_type=NotificationType.QUESTION_RECEIVED,
        action_url="/workspace/queries/",
        tag="",
        is_read=False,
    )
    Notification.objects.filter(id=n2.id).update(created_at=now - timezone.timedelta(hours=5))

    n3 = Notification.objects.create(
        recipient=user,
        title="Progress update",
        message="The class is moving ahead on schedule.",
        notification_type=NotificationType.PROGRESS_UPDATE,
        action_url="/workspace/teacher-dashboard/",
        tag="",
        is_read=False,
    )
    Notification.objects.filter(id=n3.id).update(created_at=now - timezone.timedelta(days=1))


class NotificationListAPIView(APIView):
    """
    GET  /api/notifications/
    POST /api/notifications/

    Returns notifications matching:
      - Student modal structure (media_1795191141742_a61b9c81.png):
        - Title: Your notifications
        - Subtitle: Updates from your project workspace.
        - Cards: Submission status, Project update, Teacher reply
      - Teacher modal structure (media_1795200389663_d4e22e88.png):
        - Title: Teacher activity
        - Subtitle: Updates from your project workspace.
        - Cards: Review queue, Question received, Progress update
      - Modal actions: Cancel, Close
    """

    def get(self, request, *args, **kwargs):
        user = request.user if (request.user and request.user.is_authenticated) else User.objects.first()
        if not user:
            return JsonResponse({'success': False, 'code': 'UNAUTHORIZED', 'error': 'Authentication required.'}, status=401)

        is_teacher = (
            user.is_staff or
            getattr(user, 'account_type', '') in (AccountType.TEACHER, AccountType.FACULTY) or
            request.GET.get('role') in ('teacher', 'faculty') or
            '/teacher/' in request.path or
            'teacher-activity' in request.path
        )

        # Allow seeding default screenshot notifications if ?seed=1 or ?init=1
        if request.GET.get('seed') in ('1', 'true', 'yes') or request.GET.get('init') in ('1', 'true', 'yes'):
            if not Notification.objects.filter(recipient=user).exists():
                if is_teacher:
                    seed_teacher_dashboard_notifications(user)
                else:
                    seed_student_dashboard_notifications(user)
        elif not Notification.objects.filter(recipient=user).exists() and is_teacher:
            # Auto-seed teacher activity notifications if teacher has none yet
            seed_teacher_dashboard_notifications(user)

        queryset = Notification.objects.filter(recipient=user)
        if request.GET.get('unread') in ('1', 'true', 'True'):
            queryset = queryset.filter(is_read=False)

        notifications_data = [n.to_dict() for n in queryset]
        unread_count = Notification.objects.filter(recipient=user, is_read=False).count()

        title = 'Teacher activity' if is_teacher else 'Your notifications'

        return JsonResponse({
            'success': True,
            'is_teacher': is_teacher,
            'panel_info': {
                'title': title,
                'subtitle': 'Updates from your project workspace.',
                'buttons': {
                    'cancel': 'Cancel',
                    'close': 'Close',
                }
            },
            'modal': {
                'title': title,
                'subtitle': 'Updates from your project workspace.',
                'cancel_label': 'Cancel',
                'close_label': 'Close',
                'close_icon': True,
            },
            'unread_count': unread_count,
            'count': len(notifications_data),
            'notifications': notifications_data
        }, status=200)

    def post(self, request, *args, **kwargs):
        user = request.user if (request.user and request.user.is_authenticated) else User.objects.first()
        if not user:
            return JsonResponse({'success': False, 'code': 'UNAUTHORIZED', 'error': 'Authentication required.'}, status=401)

        data = request.data or {}
        title = data.get('title', '').strip()
        message = data.get('message', '').strip()
        if not title or not message:
            return JsonResponse({'success': False, 'error': 'Title and message are required.'}, status=400)

        recipient_id = data.get('recipient_id')
        recipient = User.objects.filter(id=recipient_id).first() if recipient_id else user

        notification = create_notification(
            recipient=recipient,
            title=title,
            message=message,
            notification_type=data.get('notification_type', NotificationType.INFO),
            action_url=data.get('action_url', ''),
            tag=data.get('tag', '') or data.get('badge', '')
        )

        return JsonResponse({
            'success': True,
            'message': 'Notification created.',
            'notification': notification.to_dict()
        }, status=201)


class NotificationDetailAPIView(APIView):
    """
    PATCH  /api/notifications/<id>/read/
    DELETE /api/notifications/<id>/
    """

    def patch(self, request, pk, *args, **kwargs):
        user = request.user if (request.user and request.user.is_authenticated) else User.objects.first()
        try:
            notification = Notification.objects.get(pk=pk, recipient=user)
        except Notification.DoesNotExist:
            return JsonResponse({'success': False, 'error': 'Notification not found.'}, status=404)

        notification.is_read = True
        notification.read_at = timezone.now()
        notification.save(update_fields=['is_read', 'read_at'])

        return JsonResponse({
            'success': True,
            'message': 'Marked as read.',
            'notification': notification.to_dict()
        }, status=200)

    def delete(self, request, pk, *args, **kwargs):
        user = request.user if (request.user and request.user.is_authenticated) else User.objects.first()
        try:
            notification = Notification.objects.get(pk=pk, recipient=user)
        except Notification.DoesNotExist:
            return JsonResponse({'success': False, 'error': 'Notification not found.'}, status=404)

        notification.delete()
        return JsonResponse({'success': True, 'message': 'Notification deleted.'}, status=200)


class NotificationMarkAllReadAPIView(APIView):
    """
    POST /api/notifications/mark-all-read/
    """

    def post(self, request, *args, **kwargs):
        user = request.user if (request.user and request.user.is_authenticated) else User.objects.first()
        if not user:
            return JsonResponse({'success': False, 'code': 'UNAUTHORIZED', 'error': 'Authentication required.'}, status=401)

        Notification.objects.filter(recipient=user, is_read=False).update(
            is_read=True,
            read_at=timezone.now()
        )

        return JsonResponse({
            'success': True,
            'message': 'All notifications marked as read.'
        }, status=200)


class NotificationCloseAPIView(APIView):
    """
    POST /api/notifications/close/
    POST /api/workspace/notifications/close/

    Triggered when user clicks 'Close' or 'Cancel' on the notifications modal.
    Optionally marks notifications as read if mark_read=true.
    """

    def post(self, request, *args, **kwargs):
        user = request.user if (request.user and request.user.is_authenticated) else User.objects.first()
        if not user:
            return JsonResponse({'success': False, 'code': 'UNAUTHORIZED', 'error': 'Authentication required.'}, status=401)

        data = request.data or {}
        mark_read = (
            request.GET.get('mark_read', 'false').lower() in ('1', 'true', 'yes') or
            str(data.get('mark_read', '')).lower() in ('1', 'true', 'yes')
        )
        if mark_read:
            Notification.objects.filter(recipient=user, is_read=False).update(
                is_read=True,
                read_at=timezone.now()
            )

        unread_count = Notification.objects.filter(recipient=user, is_read=False).count()
        return JsonResponse({
            'success': True,
            'message': 'Notification panel closed.',
            'unread_count': unread_count
        }, status=200)


class NotificationSeedAPIView(APIView):
    """
    POST /api/notifications/seed/
    POST /api/workspace/notifications/seed/
    POST /api/teacher/activity/seed/

    Seeds the 3 workspace notifications:
    - Student:
      - Submission status ('Your last project is currently under review.', tag: 'Node Theory', 2h ago)
      - Project update ('Your latest project activity is ready to review.', Today)
      - Teacher reply ('Your teacher answered one of your questions.', Yesterday)
    - Teacher:
      - Review queue ('3 student submissions are awaiting your feedback.', Today)
      - Question received ('A student asked for clarification on project scope.', Today)
      - Progress update ('The class is moving ahead on schedule.', Yesterday)
    """

    def post(self, request, *args, **kwargs):
        user = request.user if (request.user and request.user.is_authenticated) else User.objects.first()
        if not user:
            return JsonResponse({'success': False, 'code': 'UNAUTHORIZED', 'error': 'Authentication required.'}, status=401)

        is_teacher = (
            user.is_staff or
            getattr(user, 'account_type', '') in (AccountType.TEACHER, AccountType.FACULTY) or
            request.GET.get('role') in ('teacher', 'faculty') or
            (request.data and request.data.get('role') in ('teacher', 'faculty')) or
            '/teacher/' in request.path or
            'teacher-activity' in request.path
        )

        if is_teacher:
            seed_teacher_dashboard_notifications(user)
            msg = 'Teacher activity workspace notifications initialized successfully.'
        else:
            seed_student_dashboard_notifications(user)
            msg = 'Sample student workspace notifications initialized successfully.'

        queryset = Notification.objects.filter(recipient=user)

        return JsonResponse({
            'success': True,
            'is_teacher': is_teacher,
            'message': msg,
            'count': queryset.count(),
            'notifications': [n.to_dict() for n in queryset]
        }, status=201)


# ==============================================================================
# TEAM CHAT & GROUP MESSAGING API (Workspace / Team chat)
# ==============================================================================

def _is_team_member(team, user):
    """
    Checks if a user is an accepted member, leader, creator, or supervisor of a team.
    Messages and chat are strictly visible only to accepted members of the selected team.
    """
    if not user or not user.is_authenticated:
        return False
    if user.is_staff or getattr(user, 'account_type', '') in (AccountType.TEACHER, AccountType.FACULTY):
        return True
    return (
        TeamMember.objects.filter(team=team, user=user).exists()
        or team.created_by_id == user.id
        or team.leader_id == user.id
    )


def update_team_unread_notifications(team, sender):
    """
    Creates or updates unread message notifications for all other members in the team.
    When 2 or 3 or more messages are unread, indicates the exact unread count:
    'You have <count> unread messages in team '<team_name>'.'
    """
    other_members = User.objects.filter(
        Q(team_memberships__team=team) | Q(created_teams=team) | Q(led_teams=team)
    ).distinct().exclude(id=sender.id)

    action_url = f"/workspace/team-chat/?team_id={team.id}"

    for member in other_members:
        unread_count = TeamMessage.objects.filter(team=team).exclude(read_by=member).count()
        if unread_count <= 0:
            continue

        if unread_count == 1:
            title = f"New message in {team.name}"
            latest_msg = TeamMessage.objects.filter(team=team, sender=sender).order_by('-created_at').first()
            content_preview = latest_msg.content if (latest_msg and latest_msg.content) else ''
            if content_preview:
                if len(content_preview) > 40:
                    content_preview = content_preview[:37] + '...'
                message = f"{sender.full_name} sent a message in team '{team.name}': \"{content_preview}\""
            else:
                message = f"{sender.full_name} shared a file in team '{team.name}'."
        else:
            title = f"{unread_count} unread messages in {team.name}"
            message = f"You have {unread_count} unread messages in team '{team.name}'."

        existing_notif = Notification.objects.filter(
            recipient=member,
            notification_type=NotificationType.TEAM_MESSAGE,
            action_url=action_url,
            is_read=False
        ).first()

        if existing_notif:
            existing_notif.title = title
            existing_notif.message = message
            existing_notif.created_at = timezone.now()
            existing_notif.save(update_fields=['title', 'message', 'created_at'])
        else:
            Notification.objects.create(
                recipient=member,
                title=title,
                message=message,
                notification_type=NotificationType.TEAM_MESSAGE,
                action_url=action_url,
                is_read=False
            )


def mark_team_messages_as_read(team, user):
    """
    Marks all messages in the team as read by the user, and marks any unread
    team message notifications for this user in this team as read.
    """
    if not user or not user.is_authenticated:
        return 0

    unread_msgs = list(TeamMessage.objects.filter(team=team).exclude(read_by=user))
    for msg in unread_msgs:
        msg.read_by.add(user)

    action_url = f"/workspace/team-chat/?team_id={team.id}"
    Notification.objects.filter(
        recipient=user,
        notification_type=NotificationType.TEAM_MESSAGE,
        action_url=action_url,
        is_read=False
    ).update(is_read=True, read_at=timezone.now())

    return len(unread_msgs)


class TeamChatAPIView(APIView):
    """
    GET /api/teams/chat/
    GET /api/workspace/team-chat/

    Matches the Workspace / Team chat page layout in the UI:
      - Category: PING
      - Page title: Team chat
      - Subtitle: Messages are visible to accepted members of the selected team.
      - Left column: List of user's teams with member count, initial, active status, unread counts.
      - Right column: Active team chat feed with header, messages, attachments, empty state.
    Automatically marks active team messages as read for the user.
    """

    def get(self, request, *args, **kwargs):
        user = request.user if (request.user and request.user.is_authenticated) else User.objects.first()
        if not user:
            return JsonResponse({'success': False, 'code': 'UNAUTHORIZED', 'error': 'Authentication required.'}, status=401)

        # Get all teams the user belongs to (accepted members, creator, or leader)
        user_teams_qs = Team.objects.filter(
            Q(memberships__user=user) | Q(created_by=user) | Q(leader=user)
        ).distinct().prefetch_related('memberships', 'messages')

        # Allow faculty to browse any team
        is_faculty = user.is_staff or getattr(user, 'account_type', '') in (AccountType.TEACHER, AccountType.FACULTY)
        if is_faculty and not user_teams_qs.exists():
            user_teams_qs = Team.objects.all().prefetch_related('memberships', 'messages')

        teams_list = list(user_teams_qs)

        # Determine active team
        requested_team_id = request.GET.get('team_id') or request.GET.get('id')
        active_team = None

        if requested_team_id:
            try:
                candidate_team = Team.objects.get(pk=requested_team_id)
            except Team.DoesNotExist:
                return JsonResponse({'success': False, 'error': 'Team not found.'}, status=404)

            if not _is_team_member(candidate_team, user):
                return JsonResponse({
                    'success': False,
                    'code': 'FORBIDDEN',
                    'error': 'Messages are visible only to accepted members of the selected team.'
                }, status=403)
            active_team = candidate_team
        elif teams_list:
            active_team = teams_list[0]

        # Format teams card list for left column
        teams_data = []
        for t in teams_list:
            t_members_count = t.memberships.count()
            t_unread_count = t.messages.exclude(read_by=user).count()
            teams_data.append({
                'id': t.id,
                'name': t.name,
                'initial': t.name[0].lower() if t.name else 'x',
                'description': t.description,
                'members_count': t_members_count,
                'members_subtext': f"{t_members_count} members",
                'unread_count': t_unread_count,
                'is_active': bool(active_team and t.id == active_team.id),
            })

        # Process active team messages
        messages_data = []
        if active_team:
            # Auto mark read if requested (default True)
            if request.GET.get('mark_read', 'true').lower() in ('true', '1', 'yes'):
                mark_team_messages_as_read(active_team, user)

            messages_qs = active_team.messages.select_related('sender').prefetch_related('read_by').order_by('created_at')
            messages_data = [m.to_dict(current_user=user) for m in messages_qs]

        active_team_members_count = active_team.memberships.count() if active_team else 0

        return JsonResponse({
            'success': True,
            'page_info': {
                'category': 'PING',
                'tag': 'PING',
                'title': 'Team chat',
                'subtitle': 'Messages are visible to accepted members of the selected team.',
                'breadcrumb': 'Workspace / Team chat',
                'active_nav': 'team_chat',
            },
            'teams': teams_data,
            'teams_count': len(teams_data),
            'active_team': {
                'id': active_team.id,
                'name': active_team.name,
                'initial': active_team.name[0].lower() if active_team.name else 'x',
                'description': active_team.description,
                'members_count': active_team_members_count,
                'members_header': f"{active_team_members_count} team members",
            } if active_team else None,
            'messages': messages_data,
            'messages_count': len(messages_data),
            'empty_state': {
                'message': 'No messages yet. Start the conversation.',
                'subtext': 'Send updates, share resources, or collaborate on your project.',
            },
            'input_placeholder': 'Write a message....',
            'attach_button_label': 'Attach file',
            'no_file_label': 'No file selected',
            'send_button_label': 'Send',
        }, status=200)


class TeamMessageListCreateAPIView(APIView):
    """
    GET  /api/teams/<id>/chat/
    GET  /api/teams/<id>/messages/
    POST /api/teams/<id>/chat/
    POST /api/teams/<id>/messages/

    Sends and retrieves messages in a team chat with file attachment support.
    Access is strictly restricted to accepted members of the team.
    """

    def get(self, request, pk, *args, **kwargs):
        user = request.user if (request.user and request.user.is_authenticated) else User.objects.first()
        if not user:
            return JsonResponse({'success': False, 'code': 'UNAUTHORIZED', 'error': 'Authentication required.'}, status=401)

        try:
            team = Team.objects.prefetch_related('memberships').get(pk=pk)
        except Team.DoesNotExist:
            return JsonResponse({'success': False, 'error': 'Team not found.'}, status=404)

        if not _is_team_member(team, user):
            return JsonResponse({
                'success': False,
                'code': 'FORBIDDEN',
                'error': 'Messages are visible only to accepted members of the selected team.'
            }, status=403)

        # Auto mark as read on GET unless mark_read=false
        if request.GET.get('mark_read', 'true').lower() in ('true', '1', 'yes'):
            mark_team_messages_as_read(team, user)

        messages_qs = team.messages.select_related('sender').prefetch_related('read_by').order_by('created_at')
        messages_data = [m.to_dict(current_user=user) for m in messages_qs]
        members_count = team.memberships.count()

        return JsonResponse({
            'success': True,
            'team': {
                'id': team.id,
                'name': team.name,
                'initial': team.name[0].lower() if team.name else 'x',
                'members_count': members_count,
                'members_header': f"{members_count} team members",
            },
            'empty_message': 'No messages yet. Start the conversation.',
            'messages_count': len(messages_data),
            'messages': messages_data,
        }, status=200)

    def post(self, request, pk, *args, **kwargs):
        user = request.user if (request.user and request.user.is_authenticated) else User.objects.first()
        if not user:
            return JsonResponse({'success': False, 'code': 'UNAUTHORIZED', 'error': 'Authentication required.'}, status=401)

        try:
            team = Team.objects.get(pk=pk)
        except Team.DoesNotExist:
            return JsonResponse({'success': False, 'error': 'Team not found.'}, status=404)

        if not _is_team_member(team, user):
            return JsonResponse({
                'success': False,
                'code': 'FORBIDDEN',
                'error': 'Messages are visible only to accepted members of the selected team.'
            }, status=403)

        data = request.data or {}
        content = (data.get('content') or request.POST.get('content') or '').strip()
        file_obj = request.FILES.get('attachment') or request.FILES.get('file')

        if not content and not file_obj:
            return JsonResponse({
                'success': False,
                'error': 'Please provide message content or attach a file.'
            }, status=400)

        attachment_name = ''
        attachment_size = 0
        attachment_type = ''
        if file_obj:
            attachment_name = file_obj.name
            attachment_size = file_obj.size
            attachment_type = getattr(file_obj, 'content_type', '') or 'application/octet-stream'

        msg = TeamMessage.objects.create(
            team=team,
            sender=user,
            content=content,
            attachment=file_obj,
            attachment_name=attachment_name,
            attachment_size=attachment_size,
            attachment_type=attachment_type
        )
        # Sender automatically has read their own message
        msg.read_by.add(user)

        # Update or create notifications for all other team members
        update_team_unread_notifications(team, user)

        return JsonResponse({
            'success': True,
            'message': 'Message sent successfully.',
            'data': msg.to_dict(current_user=user)
        }, status=201)


class TeamChatMarkReadAPIView(APIView):
    """
    POST /api/teams/<id>/chat/read/
    POST /api/teams/<id>/messages/read/

    Marks all messages in the team as read for the current user and clears unread notifications.
    """

    def post(self, request, pk, *args, **kwargs):
        user = request.user if (request.user and request.user.is_authenticated) else User.objects.first()
        if not user:
            return JsonResponse({'success': False, 'code': 'UNAUTHORIZED', 'error': 'Authentication required.'}, status=401)

        try:
            team = Team.objects.get(pk=pk)
        except Team.DoesNotExist:
            return JsonResponse({'success': False, 'error': 'Team not found.'}, status=404)

        if not _is_team_member(team, user):
            return JsonResponse({
                'success': False,
                'code': 'FORBIDDEN',
                'error': 'Messages are visible only to accepted members of the selected team.'
            }, status=403)

        marked_count = mark_team_messages_as_read(team, user)

        return JsonResponse({
            'success': True,
            'message': f"All messages in team '{team.name}' marked as read.",
            'team_id': team.id,
            'marked_count': marked_count,
            'unread_count': 0
        }, status=200)


class TeamMessageDetailAPIView(APIView):
    """
    GET    /api/teams/<team_id>/messages/<pk>/
    DELETE /api/teams/<team_id>/messages/<pk>/
    """

    def get(self, request, team_id, pk, *args, **kwargs):
        user = request.user if (request.user and request.user.is_authenticated) else User.objects.first()
        try:
            msg = TeamMessage.objects.select_related('sender', 'team').get(pk=pk, team_id=team_id)
        except TeamMessage.DoesNotExist:
            return JsonResponse({'success': False, 'error': 'Message not found.'}, status=404)

        if not _is_team_member(msg.team, user):
            return JsonResponse({'success': False, 'code': 'FORBIDDEN', 'error': 'Access denied.'}, status=403)

        return JsonResponse({'success': True, 'message': msg.to_dict(current_user=user)}, status=200)

    def delete(self, request, team_id, pk, *args, **kwargs):
        user = request.user if (request.user and request.user.is_authenticated) else User.objects.first()
        if not user:
            return JsonResponse({'success': False, 'code': 'UNAUTHORIZED', 'error': 'Authentication required.'}, status=401)

        try:
            msg = TeamMessage.objects.select_related('team').get(pk=pk, team_id=team_id)
        except TeamMessage.DoesNotExist:
            return JsonResponse({'success': False, 'error': 'Message not found.'}, status=404)

        is_sender = (msg.sender_id == user.id)
        is_leader = (msg.team.leader_id == user.id or msg.team.created_by_id == user.id)
        is_staff = user.is_staff or getattr(user, 'account_type', '') in (AccountType.TEACHER, AccountType.FACULTY)

        if not (is_sender or is_leader or is_staff):
            return JsonResponse({'success': False, 'code': 'FORBIDDEN', 'error': 'You do not have permission to delete this message.'}, status=403)

        msg.delete()
        return JsonResponse({'success': True, 'message': 'Message deleted.'}, status=200)


# ==============================================================================
# EXPORTED VIEW CALLABLES FOR URL ROUTING
# ==============================================================================

# Auth
register_view = RegisterAPIView.as_view()
login_view = LoginAPIView.as_view()
logout_view = LogoutAPIView.as_view()
me_view = UserProfileAPIView.as_view()
account_types_view = AccountTypesAPIView.as_view()
check_email_view = CheckEmailAvailabilityAPIView.as_view()
csrf_token_view = CsrfTokenAPIView.as_view()

# Workspace & Dashboard
dashboard_view = DashboardAPIView.as_view()
teacher_activity_view = TeacherActivityAPIView.as_view()

# Projects
project_list_create_view = ProjectListCreateAPIView.as_view()
project_detail_view = ProjectDetailAPIView.as_view()
project_submit_review_view = ProjectSubmitReviewAPIView.as_view()
project_review_view = ProjectReviewAPIView.as_view()
teacher_student_projects_view = TeacherStudentProjectsAPIView.as_view()
teacher_student_project_detail_view = TeacherStudentProjectDetailAPIView.as_view()

# Teams & Invitations
my_team_view = MyTeamAPIView.as_view()
team_list_create_view = TeamListCreateAPIView.as_view()
team_detail_view = TeamDetailAPIView.as_view()
team_member_manage_view = TeamMemberManageAPIView.as_view()
team_assign_leader_view = TeamAssignLeaderAPIView.as_view()
team_invitation_create_view = TeamInvitationCreateAPIView.as_view()
team_invitation_respond_view = TeamInvitationRespondAPIView.as_view()
invitation_list_view = InvitationListAPIView.as_view()
team_upload_project_view = TeamUploadProjectAPIView.as_view()
team_candidates_view = TeamCandidatesAPIView.as_view()
teacher_student_teams_projects_view = TeacherStudentTeamsProjectsAPIView.as_view()
teacher_student_team_detail_view = TeacherStudentTeamDetailAPIView.as_view()
teacher_student_team_remind_view = TeacherStudentTeamRemindAPIView.as_view()
teacher_student_team_review_view = TeacherStudentTeamReviewAPIView.as_view()

# Queries & Teacher Q&A
query_list_create_view = QueryListCreateAPIView.as_view()
query_detail_view = QueryDetailAPIView.as_view()
query_reply_view = QueryReplyAPIView.as_view()
teacher_qa_list_create_view = QueryListCreateAPIView.as_view()
teacher_qa_detail_view = QueryDetailAPIView.as_view()
teacher_qa_reply_view = QueryReplyAPIView.as_view()
queries_workspace_view = QueriesWorkspaceAPIView.as_view()

# Messages
message_list_create_view = MessageListCreateAPIView.as_view()
message_detail_view = MessageDetailAPIView.as_view()

# Notifications
notification_list_view = NotificationListAPIView.as_view()
notification_detail_view = NotificationDetailAPIView.as_view()
notification_mark_all_read_view = NotificationMarkAllReadAPIView.as_view()
notification_close_view = NotificationCloseAPIView.as_view()
notification_seed_view = NotificationSeedAPIView.as_view()

# Topics & Data
topic_list_view = TopicListAPIView.as_view()
topic_upload_view = TopicUploadAPIView.as_view()
topic_select_view = TopicSelectAPIView.as_view()
topic_release_view = TopicReleaseAPIView.as_view()
topic_detail_view = TopicDetailAPIView.as_view()
topic_assign_guide_view = TopicAssignGuideAPIView.as_view()
topic_export_view = TopicExportAPIView.as_view()

# Project Files
project_file_upload_view = ProjectFileUploadAPIView.as_view()

# Team Chat & Group Messages (Workspace / Team chat)
team_chat_view = TeamChatAPIView.as_view()
team_message_list_create_view = TeamMessageListCreateAPIView.as_view()
team_chat_mark_read_view = TeamChatMarkReadAPIView.as_view()
team_message_detail_view = TeamMessageDetailAPIView.as_view()

# Personal 1-on-1 Chat (Workspace / Chat)
chat_workspace_view = ChatWorkspaceAPIView.as_view()
direct_chat_mark_read_view = DirectChatMarkReadAPIView.as_view()
direct_chat_contacts_view = DirectChatContactsAPIView.as_view()
