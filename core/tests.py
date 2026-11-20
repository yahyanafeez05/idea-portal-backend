import json
from django.test import TestCase, Client
from django.urls import reverse
from django.contrib.auth import get_user_model
from django.core.files.uploadedfile import SimpleUploadedFile
from core.models import (
    AccountType, AuthToken, Project, ProjectStatus,
    Team, TeamMember, Notification, Topic, TopicStatus, ProjectFile,
    TeamInvitation, InvitationStatus, TeamMessage, NotificationType, Message,
    Query, QueryStatus
)

User = get_user_model()


class AuthBackendTests(TestCase):
    def setUp(self):
        self.client = Client()
        self.register_url = '/api/auth/register/'
        self.login_url = '/api/auth/login/'
        self.logout_url = '/api/auth/logout/'
        self.me_url = '/api/auth/me/'
        self.account_types_url = '/api/auth/account-types/'

    def test_successful_registration(self):
        """Test account creation with all required fields from updated Register Page."""
        payload = {
            'full_name': 'Sarah Connor',
            'account_type': 'Student',
            'department': 'Computer Science',
            'section': 'Section A',
            'email': 'sarah.connor@example.com',
            'password': 'StrongPassword2026!'
        }
        response = self.client.post(
            self.register_url,
            data=json.dumps(payload),
            content_type='application/json'
        )
        self.assertEqual(response.status_code, 201)
        data = response.json()
        self.assertTrue(data['success'])
        self.assertIn('token', data)
        self.assertEqual(data['user']['email'], 'sarah.connor@example.com')
        self.assertEqual(data['user']['full_name'], 'Sarah Connor')
        self.assertEqual(data['user']['account_type'], 'student')
        self.assertEqual(data['user']['account_type_display'], 'Student')
        self.assertEqual(data['user']['department'], 'Computer Science')
        self.assertEqual(data['user']['section'], 'Section A')

        # Check database
        user = User.objects.get(email='sarah.connor@example.com')
        self.assertTrue(user.check_password('StrongPassword2026!'))
        self.assertEqual(user.section, 'Section A')

    def test_restrict_duplicate_account_creation(self):
        """
        CRITICAL TEST: Ensure an account cannot be created again if email already exists.
        Must restrict creation and return 409 Conflict.
        """
        # Create initial account
        User.objects.create_user(
            email='existing.user@example.com',
            password='ExistingPassword123!',
            full_name='Existing User',
            department='Mathematics',
            account_type=AccountType.STUDENT
        )

        # Attempt to create account again with identical email
        payload = {
            'full_name': 'Another Person',
            'account_type': 'Faculty',
            'department': 'Physics',
            'email': 'existing.user@example.com',
            'password': 'NewPassword123!'
        }
        response = self.client.post(
            self.register_url,
            data=json.dumps(payload),
            content_type='application/json'
        )
        self.assertEqual(response.status_code, 409)
        data = response.json()
        self.assertFalse(data['success'])
        self.assertEqual(data['code'], 'ACCOUNT_ALREADY_EXISTS')
        self.assertIn('An account with this email address already exists', data['message'])

    def test_restrict_duplicate_account_case_insensitive(self):
        """Ensure duplicate account restriction works case-insensitively."""
        User.objects.create_user(
            email='john.doe@example.com',
            password='Password123!',
            full_name='John Doe',
            department='Chemistry'
        )

        # Attempt to register with uppercase variant
        payload = {
            'full_name': 'John Duplicate',
            'account_type': 'Student',
            'department': 'Chemistry',
            'email': 'JOHN.DOE@EXAMPLE.COM',
            'password': 'Password123!'
        }
        response = self.client.post(
            self.register_url,
            data=json.dumps(payload),
            content_type='application/json'
        )
        self.assertEqual(response.status_code, 409)
        data = response.json()
        self.assertEqual(data['code'], 'ACCOUNT_ALREADY_EXISTS')

    def test_registration_validation_errors(self):
        """Test validation for missing, invalid, or weak input fields."""
        # 1. Missing full name and department
        payload = {
            'full_name': '   ',
            'account_type': 'Student',
            'department': '',
            'email': 'bad_email_format',
            'password': 'short'
        }
        response = self.client.post(
            self.register_url,
            data=json.dumps(payload),
            content_type='application/json'
        )
        self.assertEqual(response.status_code, 400)
        data = response.json()
        self.assertFalse(data['success'])
        self.assertIn('full_name', data['errors'])
        self.assertIn('department', data['errors'])
        self.assertIn('email', data['errors'])
        self.assertIn('password', data['errors'])

    def test_successful_login(self):
        """Test login for Screen 2: 'Welcome back'."""
        user = User.objects.create_user(
            email='student@nodetheory.com',
            password='SecretPassword123!',
            full_name='Alice Smith',
            department='Mechanical Engineering',
            account_type=AccountType.STUDENT
        )

        payload = {
            'email': 'student@nodetheory.com',
            'password': 'SecretPassword123!'
        }
        response = self.client.post(
            self.login_url,
            data=json.dumps(payload),
            content_type='application/json'
        )
        self.assertEqual(response.status_code, 200)
        data = response.json()
        self.assertTrue(data['success'])
        self.assertIn('token', data)
        self.assertEqual(data['user']['email'], 'student@nodetheory.com')
        self.assertEqual(data['user']['full_name'], 'Alice Smith')

    def test_login_case_insensitive_email(self):
        """Test login with uppercase email matches lowercase in database."""
        User.objects.create_user(
            email='case.test@nodetheory.com',
            password='SecretPassword123!',
            full_name='Case Tester',
            department='Biology'
        )

        payload = {
            'email': 'CASE.TEST@NODETHEORY.COM',
            'password': 'SecretPassword123!'
        }
        response = self.client.post(
            self.login_url,
            data=json.dumps(payload),
            content_type='application/json'
        )
        self.assertEqual(response.status_code, 200)
        data = response.json()
        self.assertTrue(data['success'])

    def test_login_invalid_password(self):
        """Test login with incorrect password returns 401."""
        User.objects.create_user(
            email='user@nodetheory.com',
            password='CorrectPassword123!',
            full_name='User One',
            department='Arts'
        )

        payload = {
            'email': 'user@nodetheory.com',
            'password': 'WrongPassword999!'
        }
        response = self.client.post(
            self.login_url,
            data=json.dumps(payload),
            content_type='application/json'
        )
        self.assertEqual(response.status_code, 401)
        data = response.json()
        self.assertFalse(data['success'])
        self.assertEqual(data['code'], 'INVALID_CREDENTIALS')

    def test_login_nonexistent_account(self):
        """Test login with non-existent email returns 401."""
        payload = {
            'email': 'doesnotexist@nodetheory.com',
            'password': 'SomePassword123!'
        }
        response = self.client.post(
            self.login_url,
            data=json.dumps(payload),
            content_type='application/json'
        )
        self.assertEqual(response.status_code, 401)
        data = response.json()
        self.assertFalse(data['success'])
        self.assertEqual(data['code'], 'INVALID_CREDENTIALS')

    def test_login_deactivated_account(self):
        """Test login with disabled/inactive account returns 403."""
        user = User.objects.create_user(
            email='disabled@nodetheory.com',
            password='ValidPassword123!',
            full_name='Disabled User',
            department='Finance'
        )
        user.is_active = False
        user.save()

        payload = {
            'email': 'disabled@nodetheory.com',
            'password': 'ValidPassword123!'
        }
        response = self.client.post(
            self.login_url,
            data=json.dumps(payload),
            content_type='application/json'
        )
        self.assertEqual(response.status_code, 403)
        data = response.json()
        self.assertFalse(data['success'])
        self.assertEqual(data['code'], 'ACCOUNT_DISABLED')

    def test_me_endpoint_with_bearer_token(self):
        """Test protected /me/ endpoint using Bearer token authentication."""
        user = User.objects.create_user(
            email='tokenuser@nodetheory.com',
            password='TokenPassword123!',
            full_name='Token Tester',
            department='Electronics'
        )
        token = AuthToken.create_for_user(user)

        # Call /me without auth
        response = self.client.get(self.me_url)
        self.assertEqual(response.status_code, 401)

        # Call /me with Bearer token
        response = self.client.get(
            self.me_url,
            HTTP_AUTHORIZATION=f'Bearer {token.key}'
        )
        self.assertEqual(response.status_code, 200)
        data = response.json()
        self.assertTrue(data['success'])
        self.assertEqual(data['user']['email'], 'tokenuser@nodetheory.com')

    def test_logout(self):
        """Test logout invalidates token."""
        user = User.objects.create_user(
            email='logoutuser@nodetheory.com',
            password='LogoutPassword123!',
            full_name='Logout Tester',
            department='Literature'
        )
        token = AuthToken.create_for_user(user)

        response = self.client.post(
            self.logout_url,
            HTTP_AUTHORIZATION=f'Bearer {token.key}'
        )
        self.assertEqual(response.status_code, 200)

        # Token should now be inactive
        token.refresh_from_db()
        self.assertFalse(token.is_active)

    def test_account_types_list(self):
        """Test account types dropdown options endpoint."""
        response = self.client.get(self.account_types_url)
        self.assertEqual(response.status_code, 200)
        data = response.json()
        self.assertTrue(data['success'])
        types = [t['value'] for t in data['account_types']]
        self.assertIn('student', types)
        self.assertIn('faculty', types)
        self.assertIn('staff', types)

    def test_form_data_submission(self):
        """Test that form-encoded requests (x-www-form-urlencoded) are supported as well."""
        form_payload = {
            'full_name': 'Form User',
            'account_type': 'Student',
            'department': 'History',
            'email': 'form.user@nodetheory.com',
            'password': 'FormPassword2026!'
        }
        response = self.client.post(self.register_url, data=form_payload)
        self.assertEqual(response.status_code, 201)
        self.assertTrue(User.objects.filter(email='form.user@nodetheory.com').exists())

        login_payload = {
            'email': 'form.user@nodetheory.com',
            'password': 'FormPassword2026!'
        }
        login_response = self.client.post(self.login_url, data=login_payload)
        self.assertEqual(login_response.status_code, 200)
        self.assertTrue(login_response.json()['success'])

    def test_register_get_request_method(self):
        """Test GET request method on register endpoint returns endpoint documentation."""
        response = self.client.get(self.register_url)
        self.assertEqual(response.status_code, 200)
        data = response.json()
        self.assertTrue(data['success'])
        self.assertIn('POST', data['supported_methods'])

    def test_login_get_request_method(self):
        """Test GET request method on login endpoint returns endpoint documentation."""
        response = self.client.get(self.login_url)
        self.assertEqual(response.status_code, 200)
        data = response.json()
        self.assertTrue(data['success'])
        self.assertIn('POST', data['supported_methods'])

    def test_method_not_allowed_json_response(self):
        """Test that unsupported HTTP methods return 405 with clean JSON error."""
        response = self.client.delete(self.register_url)
        self.assertEqual(response.status_code, 405)
        data = response.json()
        self.assertFalse(data['success'])
        self.assertEqual(data['code'], 'METHOD_NOT_ALLOWED')

    def test_check_email_availability_endpoint(self):
        """Test real-time check-email endpoint for duplicate restriction pre-check."""
        check_url = '/api/auth/check-email/'

        # Initially available
        res1 = self.client.get(check_url, {'email': 'available@example.com'})
        self.assertEqual(res1.status_code, 200)
        self.assertTrue(res1.json()['available'])
        self.assertFalse(res1.json()['exists'])

        # Register the user
        User.objects.create_user(
            email='available@example.com',
            password='TestPassword123!',
            full_name='Test User',
            department='Design'
        )

        # Now should report as already existing / restricted
        res2 = self.client.get(check_url, {'email': 'available@example.com'})
        self.assertEqual(res2.status_code, 200)
        self.assertFalse(res2.json()['available'])
        self.assertTrue(res2.json()['exists'])
        self.assertIn('already exists', res2.json()['message'])

    def test_workspace_dashboard_empty_state(self):
        """
        Tests the exact UI state shown in the user's screenshot:
        - Greeting: 'Good morning, sid' (or time-appropriate)
        - Workspace: 'STUDENT WORKSPACE'
        - Metric cards: Projects: 0, Approved: 0, Awaiting review: 0
        - Recent projects: empty list [] -> triggers 'No projects yet.'
        """
        user = User.objects.create_user(
            email='sid@nodetheory.com',
            password='SidPassword123!',
            full_name='sid',
            department='Computer Science',
            account_type=AccountType.STUDENT
        )
        token = AuthToken.create_for_user(user)

        response = self.client.get(
            '/api/dashboard/',
            HTTP_AUTHORIZATION=f'Bearer {token.key}'
        )
        self.assertEqual(response.status_code, 200)
        data = response.json()
        self.assertTrue(data['success'])

        # Verify UI specific elements
        self.assertEqual(data['workspace']['label'], 'STUDENT WORKSPACE')
        self.assertEqual(data['workspace']['name'], 'sid')
        self.assertIn('sid', data['workspace']['full_greeting'])
        self.assertEqual(data['workspace']['hero']['tag'], 'YOUR PROJECT WORKSPACE')
        self.assertEqual(data['workspace']['hero']['title'], 'Make your next idea happen.')

        # Verify initial stats match the screenshot (0, 0, 0)
        self.assertEqual(data['stats']['projects'], 0)
        self.assertEqual(data['stats']['approved'], 0)
        self.assertEqual(data['stats']['awaiting_review'], 0)
        self.assertEqual(data['recent_projects'], [])

    def test_workspace_dashboard_populated_stats(self):
        """
        Verify that creating projects updates the Dashboard stats:
        - Total Projects
        - Approved Projects
        - Awaiting Review Projects
        - Recent Projects list
        """
        from core.models import Project, ProjectStatus
        user = User.objects.create_user(
            email='builder@nodetheory.com',
            password='BuilderPass123!',
            full_name='Alex Builder',
            department='Engineering',
            account_type=AccountType.STUDENT
        )
        token = AuthToken.create_for_user(user)

        # Create 1 awaiting_review project and 1 approved project
        Project.objects.create(
            title='AI Research Assistant',
            description='A deep learning model for research paper summarization.',
            owner=user,
            status=ProjectStatus.AWAITING_REVIEW
        )
        Project.objects.create(
            title='Node Theory Mobile App',
            description='Mobile client for Node Theory workspace.',
            owner=user,
            status=ProjectStatus.APPROVED
        )

        response = self.client.get(
            '/api/dashboard/',
            HTTP_AUTHORIZATION=f'Bearer {token.key}'
        )
        self.assertEqual(response.status_code, 200)
        data = response.json()

        self.assertEqual(data['stats']['projects'], 2)
        self.assertEqual(data['stats']['approved'], 1)
        self.assertEqual(data['stats']['awaiting_review'], 1)
        self.assertEqual(len(data['recent_projects']), 2)
        self.assertEqual(data['recent_projects'][0]['title'], 'Node Theory Mobile App')

    def test_project_crud_and_review_workflow(self):
        """Test creating, submitting, and approving a project via REST API."""
        user = User.objects.create_user(
            email='projectuser@nodetheory.com',
            password='ProjectUser123!',
            full_name='Dev User',
            department='Information Technology',
            account_type=AccountType.STUDENT
        )
        token = AuthToken.create_for_user(user)

        # 1. Create project via POST /api/projects/
        create_payload = {
            'title': 'Autonomous Rover',
            'description': 'Hardware + Software autonomous robot',
            'github_url': 'https://github.com/nodetheory/rover'
        }
        res_create = self.client.post(
            '/api/projects/',
            data=json.dumps(create_payload),
            content_type='application/json',
            HTTP_AUTHORIZATION=f'Bearer {token.key}'
        )
        self.assertEqual(res_create.status_code, 201)
        project_id = res_create.json()['project']['id']

        # 2. Get project detail
        res_detail = self.client.get(
            f'/api/projects/{project_id}/',
            HTTP_AUTHORIZATION=f'Bearer {token.key}'
        )
        self.assertEqual(res_detail.status_code, 200)
        self.assertEqual(res_detail.json()['project']['title'], 'Autonomous Rover')

        # 3. Faculty approves the project
        faculty = User.objects.create_user(
            email='prof@nodetheory.com',
            password='ProfPassword123!',
            full_name='Professor Smith',
            department='Robotics',
            account_type=AccountType.FACULTY
        )
        faculty_token = AuthToken.create_for_user(faculty)

        review_payload = {
            'status': 'approved',
            'feedback': 'Excellent prototype proposal! Approved.'
        }
        res_review = self.client.post(
            f'/api/projects/{project_id}/review/',
            data=json.dumps(review_payload),
            content_type='application/json',
            HTTP_AUTHORIZATION=f'Bearer {faculty_token.key}'
        )
        self.assertEqual(res_review.status_code, 200)
        self.assertEqual(res_review.json()['project']['status'], 'approved')

    def test_teams_queries_and_messages_endpoints(self):
        """Test Team creation, Query submission, and Messaging APIs."""
        user1 = User.objects.create_user(
            email='u1@nodetheory.com',
            password='Pass123!456',
            full_name='User One',
            department='CS'
        )
        user2 = User.objects.create_user(
            email='u2@nodetheory.com',
            password='Pass123!456',
            full_name='User Two',
            department='CS'
        )
        token = AuthToken.create_for_user(user1)

        # 1. Team Create
        team_res = self.client.post(
            '/api/teams/',
            data=json.dumps({'name': 'Alpha Team', 'description': 'Hackathon Squad'}),
            content_type='application/json',
            HTTP_AUTHORIZATION=f'Bearer {token.key}'
        )
        self.assertEqual(team_res.status_code, 201)

        # 2. Query Create
        query_res = self.client.post(
            '/api/queries/',
            data=json.dumps({'title': 'How to setup Docker?', 'description': 'Need help with compose file'}),
            content_type='application/json',
            HTTP_AUTHORIZATION=f'Bearer {token.key}'
        )
        self.assertEqual(query_res.status_code, 201)

        # 3. Message Send
        msg_res = self.client.post(
            '/api/messages/',
            data=json.dumps({
                'recipient_id': user2.id,
                'subject': 'Welcome to Alpha Team',
                'content': 'Hey, glad to have you on board!'
            }),
            content_type='application/json',
            HTTP_AUTHORIZATION=f'Bearer {token.key}'
        )
        self.assertEqual(msg_res.status_code, 201)

    def test_registration_with_teacher_account_type(self):
        """Test registration with 'Teacher' account type using teacher sign-in code."""
        payload = {
            'full_name': 'Prof. Charles Xavier',
            'account_type': 'Teacher',
            'teacher_sign_in_code': 'TEACH2026',
            'email': 'professor.x@nodetheory.com',
            'password': 'StrongPassword2026!'
        }
        response = self.client.post(
            self.register_url,
            data=json.dumps(payload),
            content_type='application/json'
        )
        self.assertEqual(response.status_code, 201)
        data = response.json()
        self.assertEqual(data['user']['account_type'], 'teacher')
        self.assertEqual(data['user']['role'], 'teacher')
        self.assertTrue(data['user']['is_teacher'])
        self.assertFalse(data['user']['is_student'])
        self.assertEqual(data['user']['workspace_label'], 'TEACHER WORKSPACE')
        self.assertEqual(data['user']['redirect_url'], '/teacher/dashboard')

    def test_registration_rejects_unselected_dropdown_placeholders(self):
        """
        Verify that submitting default unselected dropdown options
        ('Choose your department') triggers a clear validation error.
        """
        payload = {
            'full_name': 'John Doe',
            'account_type': 'Student',
            'department': 'Choose your department',
            'section': 'Choose your section',
            'email': 'john.placeholder@example.com',
            'password': 'StrongPassword2026!'
        }
        response = self.client.post(
            self.register_url,
            data=json.dumps(payload),
            content_type='application/json'
        )
        self.assertEqual(response.status_code, 400)
        data = response.json()
        self.assertFalse(data['success'])
        self.assertIn('department', data['errors'])
        self.assertIn('Please choose your department.', data['errors']['department'])

    def test_registration_get_returns_departments_and_sections(self):
        """Verify GET /api/auth/register/ returns departments and sections choices for the frontend dropdowns."""
        response = self.client.get(self.register_url)
        self.assertEqual(response.status_code, 200)
        data = response.json()
        self.assertTrue(data['success'])
        self.assertIn('departments', data)
        self.assertIn('sections', data)
        self.assertIn('Section A', data['sections'])
        self.assertIn('Computer Science and Engineering', data['departments'])

    def test_student_dashboard_faris_ui_components(self):
        """
        Verify exact UI components from the Student Dashboard screenshot:
        - Greeting: 'Good morning, faris ✦'
        - Tag: 'STUDENT WORKSPACE'
        - Subtitle: 'Your workspace is ready. Add your project details to get started.'
        - Hero: 'Make your next idea happen.' (Mode: 'BUILD MODE')
        - Active projects (00, 'Across this semester')
        - Approved (00, 'You\\'re doing great!')
        - Awaiting feedback (00, 'Your teacher will be in touch')
        - Recent projects ('Your latest submissions and updates')
        - Teacher Q&A ('Your latest questions')
        - Notification bell count
        """
        faris = User.objects.create_user(
            email='faris@nodetheory.com',
            password='FarisPassword2026!',
            full_name='faris',
            department='Computer Science',
            account_type=AccountType.STUDENT
        )
        token = AuthToken.create_for_user(faris)

        response = self.client.get(
            '/api/dashboard/',
            HTTP_AUTHORIZATION=f'Bearer {token.key}'
        )
        self.assertEqual(response.status_code, 200)
        data = response.json()
        self.assertTrue(data['success'])

        # Header & Greeting
        self.assertEqual(data['workspace']['label'], 'STUDENT WORKSPACE')
        self.assertEqual(data['workspace']['name'], 'faris')
        self.assertIn('faris ✦', data['workspace']['full_greeting'])
        self.assertEqual(data['workspace']['subtitle'], 'Your workspace is ready. Add your project details to get started.')
        self.assertEqual(data['workspace']['hero']['mode'], 'BUILD MODE')

        # 3 Metric Cards matching screenshot
        self.assertEqual(data['stats']['active_projects'], 0)
        self.assertEqual(data['stats']['active_projects_formatted'], '00')
        self.assertEqual(data['stats']['active_projects_subtext'], 'Across this semester')

        self.assertEqual(data['stats']['approved'], 0)
        self.assertEqual(data['stats']['approved_formatted'], '00')
        self.assertEqual(data['stats']['approved_subtext'], "You're doing great!")

        self.assertEqual(data['stats']['awaiting_feedback'], 0)
        self.assertEqual(data['stats']['awaiting_feedback_formatted'], '00')
        self.assertEqual(data['stats']['awaiting_feedback_subtext'], 'Your teacher will be in touch')

        # Recent projects
        self.assertEqual(data['recent_projects'], [])
        self.assertEqual(data['recent_projects_widget']['title'], 'Recent projects')
        self.assertEqual(data['recent_projects_widget']['subtext'], 'Your latest submissions and updates')
        self.assertEqual(data['recent_projects_widget']['link_text'], 'View all →')

        # Teacher Q&A
        self.assertEqual(data['teacher_qa'], [])
        self.assertEqual(data['teacher_qa_widget']['title'], 'Teacher Q&A')
        self.assertEqual(data['teacher_qa_widget']['subtext'], 'Your latest questions')
        self.assertEqual(data['teacher_qa_widget']['link_text'], 'See all')

        # Notification bell
        self.assertIn('notifications', data)
        self.assertEqual(data['notifications']['unread_count'], 0)

    def test_notification_flow_and_teacher_qa(self):
        """
        Test the complete notification flow:
        - When a teacher approves project -> student gets in-app notification
        - When teacher replies to Teacher Q&A -> student gets notification
        - Test listing notifications, unread filter, and mark all as read.
        """
        student = User.objects.create_user(
            email='student.notify@nodetheory.com',
            password='StudentPass123!',
            full_name='Student Notify',
            department='CSE'
        )
        teacher = User.objects.create_user(
            email='teacher.notify@nodetheory.com',
            password='TeacherPass123!',
            full_name='Teacher John',
            department='CSE',
            account_type=AccountType.TEACHER
        )
        student_token = AuthToken.create_for_user(student)
        teacher_token = AuthToken.create_for_user(teacher)

        # 1. Student creates project
        from core.models import Project, ProjectStatus
        project = Project.objects.create(
            title='Autonomous Drone',
            owner=student,
            status=ProjectStatus.AWAITING_REVIEW
        )

        # Teacher approves project
        self.client.post(
            f'/api/projects/{project.id}/review/',
            data=json.dumps({'status': 'approved', 'feedback': 'Great project plan!'}),
            content_type='application/json',
            HTTP_AUTHORIZATION=f'Bearer {teacher_token.key}'
        )

        # 2. Student asks a question in Teacher Q&A
        query_res = self.client.post(
            '/api/teacher-qa/',
            data=json.dumps({'title': 'Sensor calibration question', 'description': 'How to calibrate gyro?'}),
            content_type='application/json',
            HTTP_AUTHORIZATION=f'Bearer {student_token.key}'
        )
        query_id = query_res.json()['query']['id']

        # Teacher replies to Teacher Q&A
        self.client.post(
            f'/api/teacher-qa/{query_id}/reply/',
            data=json.dumps({'response': 'Use the offset calibration routine on startup.'}),
            content_type='application/json',
            HTTP_AUTHORIZATION=f'Bearer {teacher_token.key}'
        )

        # 3. Check student notifications
        notif_res = self.client.get(
            '/api/notifications/',
            HTTP_AUTHORIZATION=f'Bearer {student_token.key}'
        )
        self.assertEqual(notif_res.status_code, 200)
        notif_data = notif_res.json()
        self.assertEqual(notif_data['unread_count'], 2)
        self.assertEqual(len(notif_data['notifications']), 2)

        first_notif_id = notif_data['notifications'][0]['id']

        # 4. Mark one notification as read
        mark_res = self.client.patch(
            f'/api/notifications/{first_notif_id}/read/',
            HTTP_AUTHORIZATION=f'Bearer {student_token.key}'
        )
        self.assertEqual(mark_res.status_code, 200)

        # Verify unread count is now 1
        unread_res = self.client.get(
            '/api/notifications/?unread=1',
            HTTP_AUTHORIZATION=f'Bearer {student_token.key}'
        )
        self.assertEqual(unread_res.json()['count'], 1)

        # 5. Mark all as read
        all_read_res = self.client.post(
            '/api/notifications/mark-all-read/',
            HTTP_AUTHORIZATION=f'Bearer {student_token.key}'
        )
        self.assertEqual(all_read_res.status_code, 200)

        # Verify all are read
        final_res = self.client.get(
            '/api/notifications/',
            HTTP_AUTHORIZATION=f'Bearer {student_token.key}'
        )
        self.assertEqual(final_res.json()['unread_count'], 0)

    def test_teacher_registration_rejects_missing_or_invalid_code(self):
        """Teacher registration must reject if teacher_sign_in_code is omitted or invalid."""
        # 1. Missing code
        payload_missing = {
            'full_name': 'Prof. John',
            'account_type': 'Teacher',
            'email': 'prof.john@example.com',
            'password': 'SecurePassword123!'
        }
        res1 = self.client.post(
            self.register_url,
            data=json.dumps(payload_missing),
            content_type='application/json'
        )
        self.assertEqual(res1.status_code, 400)
        self.assertIn('teacher_sign_in_code', res1.json()['errors'])

        # 2. Invalid code
        payload_invalid = {
            'full_name': 'Prof. John',
            'account_type': 'Teacher',
            'teacher_sign_in_code': 'WRONG_CODE_999',
            'email': 'prof.john@example.com',
            'password': 'SecurePassword123!'
        }
        res2 = self.client.post(
            self.register_url,
            data=json.dumps(payload_invalid),
            content_type='application/json'
        )
        self.assertEqual(res2.status_code, 400)
        self.assertIn('teacher_sign_in_code', res2.json()['errors'])
        self.assertIn('Invalid teacher sign-in code', res2.json()['errors']['teacher_sign_in_code'][0])

    def test_teacher_login_role_differentiation(self):
        """
        Verify teacher login returns teacher role, redirect URL, and permissions,
        and enforces role restrictions when requested.
        """
        # Create student and teacher
        student = User.objects.create_user(
            email='student.login@nodetheory.com',
            password='StudentPass123!',
            full_name='Student User',
            department='CSE',
            account_type=AccountType.STUDENT
        )
        teacher = User.objects.create_user(
            email='teacher.login@nodetheory.com',
            password='TeacherPass123!',
            full_name='Prof. Teacher',
            account_type=AccountType.TEACHER
        )

        # 1. Teacher login returns role=teacher, is_teacher=True, redirect=/teacher/dashboard
        res_t = self.client.post(
            self.login_url,
            data=json.dumps({'email': 'teacher.login@nodetheory.com', 'password': 'TeacherPass123!'}),
            content_type='application/json'
        )
        self.assertEqual(res_t.status_code, 200)
        t_data = res_t.json()
        self.assertEqual(t_data['role'], 'teacher')
        self.assertTrue(t_data['is_teacher'])
        self.assertFalse(t_data['is_student'])
        self.assertEqual(t_data['workspace_label'], 'TEACHER WORKSPACE')
        self.assertEqual(t_data['redirect_url'], '/teacher/dashboard')

        # 2. Student login returns role=student, is_student=True, redirect=/dashboard
        res_s = self.client.post(
            self.login_url,
            data=json.dumps({'email': 'student.login@nodetheory.com', 'password': 'StudentPass123!'}),
            content_type='application/json'
        )
        self.assertEqual(res_s.status_code, 200)
        s_data = res_s.json()
        self.assertEqual(s_data['role'], 'student')
        self.assertTrue(s_data['is_student'])
        self.assertFalse(s_data['is_teacher'])
        self.assertEqual(s_data['workspace_label'], 'STUDENT WORKSPACE')
        self.assertEqual(s_data['redirect_url'], '/dashboard')

        # 3. Student attempting to log in via teacher portal with account_type='teacher' is rejected
        res_mismatch = self.client.post(
            self.login_url,
            data=json.dumps({
                'email': 'student.login@nodetheory.com',
                'password': 'StudentPass123!',
                'account_type': 'teacher'
            }),
            content_type='application/json'
        )
        self.assertEqual(res_mismatch.status_code, 403)
        self.assertEqual(res_mismatch.json()['code'], 'ROLE_MISMATCH')

    def test_teacher_workspace_dashboard(self):
        """Verify Teacher accessing dashboard receives Teacher Workspace data."""
        teacher = User.objects.create_user(
            email='mentor@nodetheory.com',
            password='MentorPass123!',
            full_name='Dr. Mentor',
            account_type=AccountType.TEACHER
        )
        token = AuthToken.create_for_user(teacher)

        res = self.client.get(
            '/api/dashboard/',
            HTTP_AUTHORIZATION=f'Bearer {token.key}'
        )
        self.assertEqual(res.status_code, 200)
        data = res.json()
        self.assertEqual(data['workspace']['label'], 'TEACHER WORKSPACE')
        self.assertEqual(data['workspace']['hero']['mode'], 'REVIEW MODE')
        self.assertEqual(data['user']['role'], 'teacher')
        self.assertTrue(data['user']['is_teacher'])

    def test_my_projects_workspace_sections_and_search(self):
        """
        Verify the 'My projects' workspace page matches the screenshot UI:
        - Page Info: 'YOUR WORK', 'Keep track of your submissions and teacher feedback.'
        - 'My projects' section: count, items, empty message when search matches or doesn't.
        - 'Team projects' section: count, items, subtext 'Projects shared with teams you belong to'.
        - Real-time search by keyword filtering across title, description, team name.
        """
        user = User.objects.create_user(
            email='faris.projects@nodetheory.com',
            password='Password123!',
            full_name='Faris',
            department='CSE',
            account_type=AccountType.STUDENT
        )
        token = AuthToken.create_for_user(user)
        auth_header = {'HTTP_AUTHORIZATION': f'Bearer {token.key}'}

        # 1. Initial Empty State
        empty_res = self.client.get('/api/projects/', **auth_header)
        self.assertEqual(empty_res.status_code, 200)
        empty_data = empty_res.json()
        self.assertTrue(empty_data['success'])
        self.assertEqual(empty_data['page_info']['title'], 'YOUR WORK')
        self.assertEqual(empty_data['page_info']['subtitle'], 'Keep track of your submissions and teacher feedback.')
        self.assertEqual(empty_data['summary']['my_projects_count'], 0)
        self.assertEqual(empty_data['summary']['team_projects_count'], 0)
        self.assertEqual(empty_data['my_projects']['count'], 0)
        self.assertEqual(empty_data['my_projects']['empty_message'], 'No projects created yet.')
        self.assertEqual(empty_data['team_projects']['empty_message'], 'No team projects yet.')

        # 2. Create Personal Project ("My projects")
        create_personal_res = self.client.post(
            '/api/projects/',
            data=json.dumps({
                'title': 'Solar Energy Monitor',
                'description': 'IoT telemetry tracking solar output',
                'department': 'Electrical Engineering'
            }),
            content_type='application/json',
            **auth_header
        )
        self.assertEqual(create_personal_res.status_code, 201)
        personal_proj = create_personal_res.json()['project']
        self.assertFalse(personal_proj['is_team_project'])
        self.assertIsNone(personal_proj['team_name'])

        # 3. Create Team and Team Project ("Team projects")
        team = Team.objects.create(name='Robotics Guild', created_by=user, department='Robotics')
        TeamMember.objects.create(team=team, user=user, role='Leader')

        create_team_proj_res = self.client.post(
            '/api/projects/',
            data=json.dumps({
                'title': 'Autonomous Rover Navigation',
                'description': 'SLAM algorithm for terrain mapping',
                'team_id': team.id
            }),
            content_type='application/json',
            **auth_header
        )
        self.assertEqual(create_team_proj_res.status_code, 201)
        team_proj = create_team_proj_res.json()['project']
        self.assertTrue(team_proj['is_team_project'])
        self.assertEqual(team_proj['team_name'], 'Robotics Guild')

        # 4. Fetch list endpoint - verify split between My projects and Team projects
        list_res = self.client.get('/api/projects/', **auth_header)
        self.assertEqual(list_res.status_code, 200)
        list_data = list_res.json()
        self.assertEqual(list_data['summary']['my_projects_count'], 1)
        self.assertEqual(list_data['summary']['team_projects_count'], 1)
        self.assertEqual(list_data['my_projects']['count'], 1)
        self.assertEqual(list_data['my_projects']['items'][0]['title'], 'Solar Energy Monitor')
        self.assertEqual(list_data['team_projects']['count'], 1)
        self.assertEqual(list_data['team_projects']['items'][0]['title'], 'Autonomous Rover Navigation')

        # 5. Search for 'Solar' -> matches personal project only
        search_solar = self.client.get('/api/projects/?search=Solar', **auth_header)
        self.assertEqual(search_solar.status_code, 200)
        solar_data = search_solar.json()
        self.assertEqual(solar_data['my_projects']['count'], 1)
        self.assertEqual(solar_data['team_projects']['count'], 0)
        self.assertEqual(solar_data['team_projects']['empty_message'], 'No team projects match your search.')

        # 6. Search for 'Rover' -> matches team project only
        search_rover = self.client.get('/api/projects/?search=Rover', **auth_header)
        self.assertEqual(search_rover.status_code, 200)
        rover_data = search_rover.json()
        self.assertEqual(rover_data['my_projects']['count'], 0)
        self.assertEqual(rover_data['my_projects']['empty_message'], 'No projects match your search yet.')
        self.assertEqual(rover_data['team_projects']['count'], 1)

        # 7. Search for unmatched string -> both show exact empty messages
        search_none = self.client.get('/api/projects/?search=QuantumSupercomputer', **auth_header)
        self.assertEqual(search_none.status_code, 200)
        none_data = search_none.json()
        self.assertEqual(none_data['my_projects']['empty_message'], 'No projects match your search yet.')
        self.assertEqual(none_data['team_projects']['empty_message'], 'No team projects match your search.')

        # 8. Filter by Workspace / Department
        dept_res = self.client.get('/api/projects/?workspace=Electrical', **auth_header)
        self.assertEqual(dept_res.status_code, 200)
        dept_data = dept_res.json()
        self.assertEqual(dept_data['my_projects']['count'], 1)
        self.assertEqual(dept_data['team_projects']['count'], 0)

        # 9. Verify alias routes
        alias_res = self.client.get('/api/my-projects/', **auth_header)
        self.assertEqual(alias_res.status_code, 200)
        self.assertEqual(alias_res.json()['summary']['total_projects'], 2)

    def test_team_project_creation_and_member_notification(self):
        """Verify creating a team project notifies all team members."""
        creator = User.objects.create_user(
            email='lead@nodetheory.com',
            password='Password123!',
            full_name='Team Lead'
        )
        member = User.objects.create_user(
            email='member@nodetheory.com',
            password='Password123!',
            full_name='Team Member'
        )
        team = Team.objects.create(name='AI Innovators', created_by=creator)
        TeamMember.objects.create(team=team, user=creator, role='Leader')
        TeamMember.objects.create(team=team, user=member, role='Member')

        token = AuthToken.create_for_user(creator)
        res = self.client.post(
            '/api/projects/',
            data=json.dumps({
                'title': 'Neural Synthesizer',
                'description': 'Audio synthesis using GANs',
                'team_id': team.id
            }),
            content_type='application/json',
            HTTP_AUTHORIZATION=f'Bearer {token.key}'
        )
        self.assertEqual(res.status_code, 201)

        # Check notification was created for member
        notif = Notification.objects.filter(recipient=member).first()
        self.assertIsNotNone(notif)
        self.assertIn('Neural Synthesizer', notif.message)
        self.assertIn('AI Innovators', notif.title)

    def test_patch_project_team_reassignment(self):
        """Verify converting personal project to team project and vice versa."""
        user = User.objects.create_user(
            email='tester@nodetheory.com',
            password='Password123!',
            full_name='Tester'
        )
        team = Team.objects.create(name='Dev Squad', created_by=user)
        project = Project.objects.create(
            title='Solo App',
            owner=user,
            department='CS'
        )
        self.assertFalse(project.to_dict()['is_team_project'])

        token = AuthToken.create_for_user(user)
        auth_header = {'HTTP_AUTHORIZATION': f'Bearer {token.key}'}

        # Convert to team project
        patch_res = self.client.patch(
            f'/api/projects/{project.id}/',
            data=json.dumps({'team_id': team.id}),
            content_type='application/json',
            **auth_header
        )
        self.assertEqual(patch_res.status_code, 200)
        self.assertTrue(patch_res.json()['project']['is_team_project'])
        self.assertEqual(patch_res.json()['project']['team_name'], 'Dev Squad')

        # Convert back to solo project
        patch_res2 = self.client.patch(
            f'/api/projects/{project.id}/',
            data=json.dumps({'team_id': None}),
            content_type='application/json',
            **auth_header
        )
        self.assertEqual(patch_res2.status_code, 200)
        self.assertFalse(patch_res2.json()['project']['is_team_project'])
        self.assertIsNone(patch_res2.json()['project']['team_name'])

    def test_topics_list_and_auto_seeding(self):
        """
        Verify Workspace / Data Topics table (Screenshot 1):
        - Auto-seeds the 11 healthcare topics (H1 through H11) if empty.
        - Returns Case, Title, Domain, Level, Team ID, Guide, Status ('Available').
        """
        res = self.client.get('/api/topics/')
        self.assertEqual(res.status_code, 200)
        data = res.json()
        self.assertTrue(data['success'])
        self.assertEqual(data['page_info']['tag'], 'DATA')
        self.assertEqual(data['page_info']['title'], 'Topics')
        self.assertEqual(data['page_info']['breadcrumb'], 'Workspace / Data')
        self.assertEqual(data['summary']['total_topics'], 11)
        self.assertEqual(data['summary']['available_topics'], 11)
        self.assertEqual(data['summary']['selected_topics'], 0)

        topics = data['topics']
        self.assertEqual(len(topics), 11)
        first = topics[0]
        self.assertEqual(first['case'], 'H1')
        self.assertEqual(first['title'], 'AI-Based Brain Aneurysm Triage on CT and MR Angiography')
        self.assertEqual(first['domain'], 'Healthcare')
        self.assertEqual(first['level'], 'High')
        self.assertEqual(first['status'], 'Available')
        self.assertTrue(first['is_available'])
        self.assertIsNone(first['team_id'])

        # Verify search filter on topics
        search_res = self.client.get('/api/topics/?search=Aneurysm')
        self.assertEqual(search_res.status_code, 200)
        self.assertEqual(len(search_res.json()['topics']), 1)
        self.assertEqual(search_res.json()['topics'][0]['case'], 'H1')

    def test_strict_rule_1_team_cannot_select_multiple_projects(self):
        """
        Rule 1 Enforcement:
        'in a team has select the only one project, the same team can't able to select the two project as the same time'
        """
        user1 = User.objects.create_user(email='lead.t1@nodetheory.com', password='Password123!', full_name='Team Lead 1')
        user2 = User.objects.create_user(email='member.t1@nodetheory.com', password='Password123!', full_name='Team Member 1')
        team = Team.objects.create(name='Team Alpha', created_by=user1)
        TeamMember.objects.create(team=team, user=user1, role='Leader')
        TeamMember.objects.create(team=team, user=user2, role='Member')

        token1 = AuthToken.create_for_user(user1)
        token2 = AuthToken.create_for_user(user2)

        # 1. Team Lead selects topic H1
        res1 = self.client.post(
            '/api/topics/H1/select/',
            data=json.dumps({'team_id': team.id}),
            content_type='application/json',
            HTTP_AUTHORIZATION=f'Bearer {token1.key}'
        )
        self.assertEqual(res1.status_code, 201)
        self.assertTrue(res1.json()['success'])
        self.assertEqual(res1.json()['project']['topic_code'], 'H1')

        # 2. Team Member (or Lead) in the SAME team attempts to select another topic (H2)
        res2 = self.client.post(
            '/api/topics/H2/select/',
            data=json.dumps({'team_id': team.id}),
            content_type='application/json',
            HTTP_AUTHORIZATION=f'Bearer {token2.key}'
        )
        self.assertEqual(res2.status_code, 409)
        data2 = res2.json()
        self.assertFalse(data2['success'])
        self.assertEqual(data2['code'], 'TEAM_PROJECT_LIMIT_EXCEEDED')
        self.assertIn('already selected project', data2['error'])
        self.assertIn('A team cannot select more than one project simultaneously', data2['error'])

    def test_strict_rule_2_exclusivity_other_team_cannot_select_same_topic(self):
        """
        Rule 2 Enforcement:
        'when team A select the a project , the team B can't able to select the same project so restrict it'
        """
        lead_a = User.objects.create_user(email='lead.a@nodetheory.com', password='Password123!', full_name='Alice Lead')
        team_a = Team.objects.create(name='Team A', created_by=lead_a)
        TeamMember.objects.create(team=team_a, user=lead_a, role='Leader')
        token_a = AuthToken.create_for_user(lead_a)

        lead_b = User.objects.create_user(email='lead.b@nodetheory.com', password='Password123!', full_name='Bob Lead')
        team_b = Team.objects.create(name='Team B', created_by=lead_b)
        TeamMember.objects.create(team=team_b, user=lead_b, role='Leader')
        token_b = AuthToken.create_for_user(lead_b)

        # 1. Team A selects Topic H3 ('Safe Drug-Decision Assistant with Retrieval and Refusal')
        res_a = self.client.post(
            '/api/topics/H3/select/',
            data=json.dumps({'team_id': team_a.id}),
            content_type='application/json',
            HTTP_AUTHORIZATION=f'Bearer {token_a.key}'
        )
        self.assertEqual(res_a.status_code, 201)
        self.assertEqual(res_a.json()['project']['topic_code'], 'H3')

        # 2. Team B attempts to select the SAME Topic H3
        res_b = self.client.post(
            '/api/topics/H3/select/',
            data=json.dumps({'team_id': team_b.id}),
            content_type='application/json',
            HTTP_AUTHORIZATION=f'Bearer {token_b.key}'
        )
        self.assertEqual(res_b.status_code, 409)
        data_b = res_b.json()
        self.assertFalse(data_b['success'])
        self.assertEqual(data_b['code'], 'TOPIC_ALREADY_SELECTED')
        self.assertIn('already been selected by Team A', data_b['error'])

        # 3. In the Topics table, Topic H3 reflects Team A selection
        topics_res = self.client.get('/api/topics/')
        h3_topic = next(t for t in topics_res.json()['topics'] if t['case'] == 'H3')
        self.assertEqual(h3_topic['status'], 'Selected')
        self.assertFalse(h3_topic['is_available'])
        self.assertEqual(h3_topic['team_id'], team_a.id)
        self.assertEqual(h3_topic['team_name'], 'Team A')

    def test_uploaded_project_card_after_selection_matches_screenshot_2(self):
        """
        Verify the Workspace / My projects page after topic selection matches Screenshot 2:
        - Project card showing:
          * Title: 'AI-Based Brain Aneurysm Triage on CT and MR Angiography'
          * Status: 'Not started' (red badge)
          * Topic H1 · Selected <Date>
          * Progress: 0%
          * Badge: 'Selected' (is_selected: True)
          * Edit project, Upload a file, Delete project available
        """
        student = User.objects.create_user(
            email='faris@nodetheory.com',
            password='Password123!',
            full_name='faris',
            department='Healthcare AI',
            account_type=AccountType.STUDENT
        )
        token = AuthToken.create_for_user(student)
        auth = {'HTTP_AUTHORIZATION': f'Bearer {token.key}'}

        # Select topic H1
        select_res = self.client.post(
            '/api/topics/H1/select/',
            content_type='application/json',
            **auth
        )
        self.assertEqual(select_res.status_code, 201)

        # Check 'My projects' list API
        list_res = self.client.get('/api/my-projects/', **auth)
        self.assertEqual(list_res.status_code, 200)
        data = list_res.json()
        self.assertEqual(data['summary']['my_projects_count'], 1)

        project = data['my_projects']['items'][0]
        self.assertEqual(project['title'], 'AI-Based Brain Aneurysm Triage on CT and MR Angiography')
        self.assertEqual(project['topic_code'], 'H1')
        self.assertEqual(project['status'], 'not_started')
        self.assertEqual(project['status_display'], 'Not started')
        self.assertEqual(project['progress'], 0)
        self.assertEqual(project['progress_display'], '0%')
        self.assertTrue(project['is_selected'])
        self.assertIn('Topic H1 · Selected', project['subtext'])

    def test_project_file_upload_and_progress_update(self):
        """
        Verify 'Upload a file' action on the project card:
        - Uploads document/code/data file
        - Advances status from 'not_started' to 'in_progress'
        """
        user = User.objects.create_user(email='uploader@nodetheory.com', password='Password123!', full_name='Uploader')
        token = AuthToken.create_for_user(user)
        auth = {'HTTP_AUTHORIZATION': f'Bearer {token.key}'}

        # Select topic H4
        sel_res = self.client.post('/api/topics/H4/select/', content_type='application/json', **auth)
        proj_id = sel_res.json()['project']['id']

        # Upload a file
        dummy_file = SimpleUploadedFile("dataset_v1.csv", b"sample,case\n1,H4\n2,H4", content_type="text/csv")
        upload_res = self.client.post(
            f'/api/projects/{proj_id}/files/',
            {'file': dummy_file},
            format='multipart',
            **auth
        )
        self.assertEqual(upload_res.status_code, 201)
        upload_data = upload_res.json()
        self.assertTrue(upload_data['success'])
        self.assertEqual(upload_data['file']['filename'], 'dataset_v1.csv')
        self.assertEqual(upload_data['project']['status'], 'in_progress')
        self.assertEqual(upload_data['project']['progress'], 25)

        # List project files
        files_res = self.client.get(f'/api/projects/{proj_id}/files/', **auth)
        self.assertEqual(files_res.status_code, 200)
        self.assertEqual(files_res.json()['files_count'], 1)

    def test_delete_project_frees_topic_for_other_teams(self):
        """
        Verify 'Delete project' action:
        - When a project is deleted, its linked topic becomes AVAILABLE again so other teams can select it.
        """
        lead_a = User.objects.create_user(email='lead.alpha@nodetheory.com', password='Password123!', full_name='Alice')
        team_a = Team.objects.create(name='Team Alpha', created_by=lead_a)
        TeamMember.objects.create(team=team_a, user=lead_a, role='Leader')
        token_a = AuthToken.create_for_user(lead_a)

        lead_b = User.objects.create_user(email='lead.beta@nodetheory.com', password='Password123!', full_name='Bob')
        team_b = Team.objects.create(name='Team Beta', created_by=lead_b)
        TeamMember.objects.create(team=team_b, user=lead_b, role='Leader')
        token_b = AuthToken.create_for_user(lead_b)

        # Team A selects H5
        sel_res = self.client.post(
            '/api/topics/H5/select/',
            data=json.dumps({'team_id': team_a.id}),
            content_type='application/json',
            HTTP_AUTHORIZATION=f'Bearer {token_a.key}'
        )
        proj_id = sel_res.json()['project']['id']

        # Team B cannot select H5 (409)
        conflict_res = self.client.post(
            '/api/topics/H5/select/',
            data=json.dumps({'team_id': team_b.id}),
            content_type='application/json',
            HTTP_AUTHORIZATION=f'Bearer {token_b.key}'
        )
        self.assertEqual(conflict_res.status_code, 409)

        # Team A deletes project
        del_res = self.client.delete(
            f'/api/projects/{proj_id}/',
            HTTP_AUTHORIZATION=f'Bearer {token_a.key}'
        )
        self.assertEqual(del_res.status_code, 200)

        # Team B can now select Topic H5 successfully!
        free_sel_res = self.client.post(
            '/api/topics/H5/select/',
            data=json.dumps({'team_id': team_b.id}),
            content_type='application/json',
            HTTP_AUTHORIZATION=f'Bearer {token_b.key}'
        )
        self.assertEqual(free_sel_res.status_code, 201)
        self.assertEqual(free_sel_res.json()['topic']['team_name'], 'Team Beta')

    def test_dataset_upload_csv_and_json(self):
        """
        Verify 'Upload file' on Workspace / Data screen:
        'Upload a file to replace or add your dataset'
        """
        csv_data = (
            "Case,Title,Domain,Level,Guide\n"
            "D1,Robotic Exoskeleton for Stroke Rehabilitation,Biomedical,High,Dr. Smith\n"
            "D2,Autonomous Greenhouse Climate Regulation,AgriTech,Moderate,Prof. Green\n"
        )
        csv_file = SimpleUploadedFile("custom_dataset.csv", csv_data.encode('utf-8'), content_type="text/csv")

        upload_res = self.client.post('/api/topics/upload/', {'file': csv_file}, format='multipart')
        self.assertEqual(upload_res.status_code, 201)
        data = upload_res.json()
        self.assertTrue(data['success'])
        self.assertEqual(data['created_count'], 2)

        # Verify added topics appear in list
        topics_res = self.client.get('/api/topics/?search=Robotic')
        self.assertEqual(topics_res.status_code, 200)
        self.assertEqual(len(topics_res.json()['topics']), 1)
        self.assertEqual(topics_res.json()['topics'][0]['case'], 'D1')
        self.assertEqual(topics_res.json()['topics'][0]['guide'], 'Dr. Smith')

    def test_my_team_page_empty_state_matches_screenshot_1(self):
        """
        Verify Workspace / My team screen (Screenshot 1):
        - Header: 'STUDENT WORKSPACE', 'My team', 'Create a team, invite student accounts, and submit shared projects.'
        - When user has not joined any team:
          * has_team: False
          * empty_message: "You haven't joined a team yet. Create one or accept an invitation."
        """
        student = User.objects.create_user(
            email='solo.student@nodetheory.com',
            password='Password123!',
            full_name='Faris Solo',
            account_type=AccountType.STUDENT
        )
        token = AuthToken.create_for_user(student)

        res = self.client.get('/api/teams/my-team/', HTTP_AUTHORIZATION=f'Bearer {token.key}')
        self.assertEqual(res.status_code, 200)
        data = res.json()
        self.assertTrue(data['success'])
        self.assertFalse(data['has_team'])
        self.assertIsNone(data['team'])
        self.assertEqual(data['page_info']['tag'], 'STUDENT WORKSPACE')
        self.assertEqual(data['page_info']['title'], 'My team')
        self.assertEqual(data['page_info']['subtitle'], 'Create a team, invite student accounts, and submit shared projects.')
        self.assertEqual(data['page_info']['breadcrumb'], 'Workspace / My team')
        self.assertEqual(data['empty_message'], "You haven't joined a team yet. Create one or accept an invitation.")

    def test_create_team_modal_with_photo_matches_screenshot_2(self):
        """
        Verify 'Create a team' modal (Screenshot 2):
        - Team name: 'Enter a team name'
        - Team description: 'Add a short team bio or project focus'
        - Team photo: 'Choose a team photo - PNG, JPG, GIF · Optional'
        - Creator is set as leader and added to team members as Leader.
        """
        student = User.objects.create_user(
            email='founder@nodetheory.com',
            password='Password123!',
            full_name='Founder Student',
            department='BioEngineering',
            account_type=AccountType.STUDENT
        )
        token = AuthToken.create_for_user(student)
        auth = {'HTTP_AUTHORIZATION': f'Bearer {token.key}'}

        dummy_photo = SimpleUploadedFile("team_avatar.png", b"fake_png_image_binary_data", content_type="image/png")

        create_res = self.client.post(
            '/api/teams/',
            {
                'team_name': 'BioTech Innovators',
                'team_description': 'Developing computational diagnostics for neurological conditions.',
                'team_photo': dummy_photo,
                'department': 'BioEngineering'
            },
            format='multipart',
            **auth
        )
        self.assertEqual(create_res.status_code, 201)
        data = create_res.json()
        self.assertTrue(data['success'])
        team = data['team']
        self.assertEqual(team['name'], 'BioTech Innovators')
        self.assertEqual(team['description'], 'Developing computational diagnostics for neurological conditions.')
        self.assertIn('team_avatar', team['photo_url'])
        self.assertEqual(team['leader']['id'], student.id)
        self.assertEqual(team['members_count'], 1)
        self.assertTrue(team['members'][0]['is_leader'])

        # Check /api/teams/my-team/ now returns has_team: True
        my_team_res = self.client.get('/api/teams/my-team/', **auth)
        self.assertEqual(my_team_res.status_code, 200)
        my_team_data = my_team_res.json()
        self.assertTrue(my_team_data['has_team'])
        self.assertTrue(my_team_data['is_leader'])
        self.assertEqual(my_team_data['team']['name'], 'BioTech Innovators')

    def test_team_leader_sends_invitation_to_user(self):
        """
        Verify:
        'the teamleader is send the request to the user'
        - Invitation is stored in DB with status 'pending'
        - In-app notification sent directly to invited user's notification box.
        """
        leader = User.objects.create_user(email='leader.dev@nodetheory.com', password='Password123!', full_name='Team Lead')
        candidate = User.objects.create_user(email='candidate.dev@nodetheory.com', password='Password123!', full_name='Alex Candidate')
        team = Team.objects.create(name='Quantum Developers', created_by=leader, leader=leader)
        TeamMember.objects.create(team=team, user=leader, role='Leader')

        token = AuthToken.create_for_user(leader)

        invite_res = self.client.post(
            f'/api/teams/{team.id}/invitations/',
            data=json.dumps({
                'email': 'candidate.dev@nodetheory.com',
                'message': 'We would love to have you on our capstone team!',
                'role': 'Full Stack Developer'
            }),
            content_type='application/json',
            HTTP_AUTHORIZATION=f'Bearer {token.key}'
        )
        self.assertEqual(invite_res.status_code, 201)
        inv_data = invite_res.json()
        self.assertTrue(inv_data['success'])
        self.assertEqual(inv_data['invitation']['status'], 'pending')
        self.assertEqual(inv_data['invitation']['role'], 'Full Stack Developer')

        # Check notification arrived in candidate's notification box
        notif = Notification.objects.filter(recipient=candidate).first()
        self.assertIsNotNone(notif)
        self.assertEqual(notif.notification_type, 'team_invite')
        self.assertIn('Team Invitation: Quantum Developers', notif.title)
        self.assertIn('Team Lead (Team Leader) invited you', notif.message)

    def test_user_accepts_invitation_joins_team_and_notifies_leader(self):
        """
        Verify:
        'when the user acept he request the use will joined in the team'
        - User status becomes member of team
        - Notification sent to team leader confirming acceptance.
        """
        leader = User.objects.create_user(email='boss@nodetheory.com', password='Password123!', full_name='Leader Bob')
        invitee = User.objects.create_user(email='recruit@nodetheory.com', password='Password123!', full_name='Recruit Rachel')
        team = Team.objects.create(name='Cyber Guardians', created_by=leader, leader=leader)
        TeamMember.objects.create(team=team, user=leader, role='Leader')

        invitation = TeamInvitation.objects.create(
            team=team,
            invited_by=leader,
            invited_user=invitee,
            role='Security Analyst',
            status=InvitationStatus.PENDING
        )

        invitee_token = AuthToken.create_for_user(invitee)

        # Invitee accepts invitation
        accept_res = self.client.post(
            f'/api/invitations/{invitation.id}/accept/',
            HTTP_AUTHORIZATION=f'Bearer {invitee_token.key}'
        )
        self.assertEqual(accept_res.status_code, 200)
        self.assertTrue(accept_res.json()['success'])
        self.assertEqual(accept_res.json()['invitation']['status'], 'accepted')

        # Check invitee is now a member in DB
        self.assertTrue(TeamMember.objects.filter(team=team, user=invitee).exists())
        self.assertEqual(team.memberships.count(), 2)

        # Check notification sent to Team Leader
        leader_notif = Notification.objects.filter(recipient=leader, notification_type='team_invite_accepted').first()
        self.assertIsNotNone(leader_notif)
        self.assertIn('Invitation Accepted', leader_notif.title)
        self.assertIn('Recruit Rachel accepted your invitation and joined', leader_notif.message)

    def test_user_rejects_invitation_sends_rejection_message_to_leader(self):
        """
        Verify:
        'the use is reject the reques the rejection message is send to the team leader'
        - Rejection reason saved
        - User is NOT joined into team
        - Rejection message sent directly into team leader's notification box.
        """
        leader = User.objects.create_user(email='capt@nodetheory.com', password='Password123!', full_name='Capt Marvel')
        invitee = User.objects.create_user(email='spidey@nodetheory.com', password='Password123!', full_name='Peter Parker')
        team = Team.objects.create(name='Avengers Lab', created_by=leader, leader=leader)
        TeamMember.objects.create(team=team, user=leader, role='Leader')

        invitation = TeamInvitation.objects.create(
            team=team,
            invited_by=leader,
            invited_user=invitee,
            role='Research Fellow',
            status=InvitationStatus.PENDING
        )

        invitee_token = AuthToken.create_for_user(invitee)

        # Invitee rejects invitation with a message
        rejection_payload = {
            'reason': 'I have already joined the Queens neighborhood robotics group.'
        }
        reject_res = self.client.post(
            f'/api/invitations/{invitation.id}/reject/',
            data=json.dumps(rejection_payload),
            content_type='application/json',
            HTTP_AUTHORIZATION=f'Bearer {invitee_token.key}'
        )
        self.assertEqual(reject_res.status_code, 200)
        self.assertTrue(reject_res.json()['success'])
        self.assertEqual(reject_res.json()['invitation']['status'], 'rejected')
        self.assertEqual(reject_res.json()['invitation']['rejection_reason'], 'I have already joined the Queens neighborhood robotics group.')

        # User is NOT added to team
        self.assertFalse(TeamMember.objects.filter(team=team, user=invitee).exists())

        # Notification with rejection message sent to Team Leader
        leader_notif = Notification.objects.filter(recipient=leader, notification_type='team_invite_rejected').first()
        self.assertIsNotNone(leader_notif)
        self.assertIn('Invitation Declined: Avengers Lab', leader_notif.title)
        self.assertIn('Peter Parker declined your invitation', leader_notif.message)
        self.assertIn('Queens neighborhood robotics group', leader_notif.message)

    def test_teacher_assigns_team_leader(self):
        """
        Verify:
        'the team leader is accined by the teacher'
        - Teacher assigns student as team leader
        - Updates team leader in DB and TeamMember role to 'Leader'
        - Student receives notification from teacher.
        """
        teacher = User.objects.create_user(
            email='prof.oak@nodetheory.com',
            password='TeacherPass123!',
            full_name='Prof. Oak',
            account_type=AccountType.TEACHER
        )
        student_a = User.objects.create_user(email='ash@nodetheory.com', password='Password123!', full_name='Ash Ketchum')
        student_b = User.objects.create_user(email='gary@nodetheory.com', password='Password123!', full_name='Gary Oak')

        team = Team.objects.create(name='Pallet Town Tech', created_by=student_a, leader=student_a)
        TeamMember.objects.create(team=team, user=student_a, role='Leader')
        TeamMember.objects.create(team=team, user=student_b, role='Member')

        teacher_token = AuthToken.create_for_user(teacher)

        # Teacher reassigns team leader to Gary Oak
        assign_res = self.client.post(
            f'/api/teams/{team.id}/assign-leader/',
            data=json.dumps({'student_id': student_b.id}),
            content_type='application/json',
            HTTP_AUTHORIZATION=f'Bearer {teacher_token.key}'
        )
        self.assertEqual(assign_res.status_code, 200)
        self.assertTrue(assign_res.json()['success'])
        self.assertEqual(assign_res.json()['leader']['id'], student_b.id)

        # Check DB state
        team.refresh_from_db()
        self.assertEqual(team.leader, student_b)
        self.assertEqual(team.assigned_by_teacher, teacher)

        # Check TeamMember roles
        gary_member = TeamMember.objects.get(team=team, user=student_b)
        ash_member = TeamMember.objects.get(team=team, user=student_a)
        self.assertEqual(gary_member.role, 'Leader')
        self.assertEqual(ash_member.role, 'Member')

        # Check notification sent to student Gary
        student_notif = Notification.objects.filter(recipient=student_b, notification_type='team_leader_assigned').first()
        self.assertIsNotNone(student_notif)
        self.assertIn('Assigned as Team Leader', student_notif.title)
        self.assertIn('Prof. Oak has assigned you as the Team Leader', student_notif.message)

    def test_team_card_shows_exact_options_matching_screenshot(self):
        """
        Verify Team Card after creation (Screenshot):
        - Team avatar initial: 'x'
        - Team name pill: 'xander'
        - Subtitle: '1 members'
        - 4 actions:
          1. Edit details
          2. Invite member
          3. Delete team
          4. Upload project
        """
        user = User.objects.create_user(email='xander@nodetheory.com', password='Password123!', full_name='Xander Cage')
        token = AuthToken.create_for_user(user)
        auth = {'HTTP_AUTHORIZATION': f'Bearer {token.key}'}

        # Create team named 'xander' matching the screenshot
        create_res = self.client.post(
            '/api/teams/',
            data={'name': 'xander', 'description': 'Autonomous drone telemetry research team.'},
            **auth
        )
        self.assertEqual(create_res.status_code, 201)

        # Get My team page
        my_team_res = self.client.get('/api/teams/my-team/', **auth)
        self.assertEqual(my_team_res.status_code, 200)
        data = my_team_res.json()
        self.assertTrue(data['success'])
        self.assertTrue(data['has_team'])
        self.assertTrue(data['is_leader'])

        team = data['team']
        self.assertEqual(team['name'], 'xander')
        self.assertEqual(team['initial'], 'x')
        self.assertEqual(team['members_count'], 1)
        self.assertEqual(team['members_subtext'], '1 members')

        # Check the 4 action buttons
        options = {opt['key']: opt for opt in data['options']}
        self.assertIn('edit_details', options)
        self.assertEqual(options['edit_details']['label'], 'Edit details')
        self.assertIn('invite_member', options)
        self.assertEqual(options['invite_member']['label'], 'Invite member')
        self.assertIn('delete_team', options)
        self.assertEqual(options['delete_team']['label'], 'Delete team')
        self.assertIn('upload_project', options)
        self.assertEqual(options['upload_project']['label'], 'Upload project')

    def test_team_card_action_edit_details(self):
        """Verify 'Edit details' action updates team name and description."""
        user = User.objects.create_user(email='editor@nodetheory.com', password='Password123!', full_name='Editor')
        token = AuthToken.create_for_user(user)
        team = Team.objects.create(name='Original Name', created_by=user, leader=user)
        TeamMember.objects.create(team=team, user=user, role='Leader')

        auth = {'HTTP_AUTHORIZATION': f'Bearer {token.key}'}
        patch_res = self.client.patch(
            f'/api/teams/{team.id}/',
            data=json.dumps({
                'name': 'Updated Team Name',
                'description': 'Updated bio focus for the team.'
            }),
            content_type='application/json',
            **auth
        )
        self.assertEqual(patch_res.status_code, 200)
        self.assertEqual(patch_res.json()['team']['name'], 'Updated Team Name')
        self.assertEqual(patch_res.json()['team']['description'], 'Updated bio focus for the team.')

        # Also verify via /api/teams/my-team/ direct alias
        alias_patch = self.client.patch(
            '/api/teams/my-team/',
            data=json.dumps({'description': 'Refined project focus via my-team alias.'}),
            content_type='application/json',
            **auth
        )
        self.assertEqual(alias_patch.status_code, 200)
        self.assertEqual(alias_patch.json()['team']['description'], 'Refined project focus via my-team alias.')

    def test_team_card_action_upload_project(self):
        """
        Verify 'Upload project' action button on team card:
        - Uploads project file for the team
        - Creates project in database linked to team
        - Automatically notifies all other team members
        """
        leader = User.objects.create_user(email='t.leader@nodetheory.com', password='Password123!', full_name='Team Lead')
        mate = User.objects.create_user(email='t.mate@nodetheory.com', password='Password123!', full_name='Teammate One')
        team = Team.objects.create(name='AeroDynamics', created_by=leader, leader=leader, department='Mechanical')
        TeamMember.objects.create(team=team, user=leader, role='Leader')
        TeamMember.objects.create(team=team, user=mate, role='Member')

        token = AuthToken.create_for_user(leader)
        auth = {'HTTP_AUTHORIZATION': f'Bearer {token.key}'}

        project_file = SimpleUploadedFile("wing_simulation.py", b"print('Simulation running')", content_type="text/x-python")

        upload_res = self.client.post(
            f'/api/teams/{team.id}/upload-project/',
            {
                'title': 'Hypersonic Wing Aerodynamics',
                'description': 'CFD simulation data and mesh models',
                'file': project_file
            },
            format='multipart',
            **auth
        )
        self.assertEqual(upload_res.status_code, 201)
        data = upload_res.json()
        self.assertTrue(data['success'])
        proj = data['project']
        self.assertEqual(proj['title'], 'Hypersonic Wing Aerodynamics')
        self.assertTrue(proj['is_team_project'])
        self.assertEqual(proj['team_name'], 'AeroDynamics')
        self.assertEqual(proj['status'], 'in_progress')
        self.assertEqual(proj['progress'], 25)

        # Verify notification delivered to teammate
        mate_notif = Notification.objects.filter(recipient=mate).first()
        self.assertIsNotNone(mate_notif)
        self.assertIn('Project Uploaded', mate_notif.title)
        self.assertIn('Team Lead uploaded project', mate_notif.message)

    def test_team_card_action_delete_team(self):
        """
        Verify 'Delete team' action button:
        - Deletes team
        - Automatically frees any topic selected by team
        - My team page returns to empty state.
        """
        leader = User.objects.create_user(email='del.leader@nodetheory.com', password='Password123!', full_name='Del Leader')
        team = Team.objects.create(name='Temporary Team', created_by=leader, leader=leader)
        TeamMember.objects.create(team=team, user=leader, role='Leader')
        token = AuthToken.create_for_user(leader)
        auth = {'HTTP_AUTHORIZATION': f'Bearer {token.key}'}

        # Select Topic H6
        sel_res = self.client.post('/api/topics/H6/select/', data=json.dumps({'team_id': team.id}), content_type='application/json', **auth)
        self.assertEqual(sel_res.status_code, 201)
        topic_h6 = Topic.objects.get(case_code='H6')
        self.assertEqual(topic_h6.status, TopicStatus.SELECTED)
        self.assertEqual(topic_h6.team, team)

        # Delete team via DELETE /api/teams/<id>/
        del_res = self.client.delete(f'/api/teams/{team.id}/', **auth)
        self.assertEqual(del_res.status_code, 200)

        # Verify topic H6 is freed and AVAILABLE again
        topic_h6.refresh_from_db()
        self.assertEqual(topic_h6.status, TopicStatus.AVAILABLE)
        self.assertIsNone(topic_h6.team)
        self.assertTrue(topic_h6.to_dict()['is_available'])

        # Verify /api/teams/my-team/ returns empty state
        my_team_res = self.client.get('/api/teams/my-team/', **auth)
        self.assertFalse(my_team_res.json()['has_team'])
        self.assertEqual(my_team_res.json()['empty_message'], "You haven't joined a team yet. Create one or accept an invitation.")

    def test_team_candidates_search_for_invite_modal(self):
        """
        Verify candidates endpoint for 'Invite member' modal:
        - Searches students by name or email
        - Excludes users already in the team
        """
        leader = User.objects.create_user(email='lead.search@nodetheory.com', password='Password123!', full_name='Lead Searcher')
        existing_member = User.objects.create_user(email='member.search@nodetheory.com', password='Password123!', full_name='Already Member')
        candidate1 = User.objects.create_user(email='alice.candidate@nodetheory.com', password='Password123!', full_name='Alice Wonderland')
        candidate2 = User.objects.create_user(email='bob.candidate@nodetheory.com', password='Password123!', full_name='Bob Builder')

        team = Team.objects.create(name='Search Squad', created_by=leader, leader=leader)
        TeamMember.objects.create(team=team, user=leader, role='Leader')
        TeamMember.objects.create(team=team, user=existing_member, role='Member')

        token = AuthToken.create_for_user(leader)
        auth = {'HTTP_AUTHORIZATION': f'Bearer {token.key}'}

        # Query all candidates
        cand_res = self.client.get(f'/api/teams/{team.id}/candidates/', **auth)
        self.assertEqual(cand_res.status_code, 200)
        cand_ids = [c['id'] for c in cand_res.json()['candidates']]
        self.assertIn(candidate1.id, cand_ids)
        self.assertIn(candidate2.id, cand_ids)
        self.assertNotIn(existing_member.id, cand_ids)
        self.assertNotIn(leader.id, cand_ids)

        # Filter by search='Alice'
        alice_res = self.client.get(f'/api/teams/{team.id}/candidates/?search=Alice', **auth)
        self.assertEqual(alice_res.status_code, 200)
        self.assertEqual(len(alice_res.json()['candidates']), 1)
        self.assertEqual(alice_res.json()['candidates'][0]['full_name'], 'Alice Wonderland')


class TeamChatBackendTests(TestCase):
    """
    Comprehensive test suite for Workspace / Team Chat:
    - Verifies exact visual structure matching screenshot media_1795186862393_ed57fcf1.png:
      - 'PING' category, 'Team chat' title
      - 'Messages are visible to accepted members of the selected team.' subtitle
      - Left column: team pill with initial 'x', team name 'xander', '1 members'
      - Right column: header 'xander', '1 team members'
      - Empty state: 'No messages yet. Start the conversation.'
      - Input controls: '[Attach file] No file selected', 'Write a message....', '[Send]'
    - Enforces group chat is strictly restricted to accepted members of the selected team.
    - File attachment uploads (documents, images, archives).
    - Unread message indication in notification box when 2, 3 or more messages are unread:
      'You have 3 unread messages in team 'xander'.'
    - Visiting team chat or marking as read clears notifications and unread badge.
    - Dashboard sidebar badge reflects unread team chat messages.
    """

    def setUp(self):
        self.client = Client()

        # Create members
        self.leader = User.objects.create_user(
            email='faris.lead@nodetheory.com',
            password='Password123!',
            full_name='Faris Student',
            account_type=AccountType.STUDENT,
            department='Computer Science'
        )
        self.teammate = User.objects.create_user(
            email='sarah.member@nodetheory.com',
            password='Password123!',
            full_name='Sarah Teammate',
            account_type=AccountType.STUDENT,
            department='Computer Science'
        )
        self.outsider = User.objects.create_user(
            email='outsider@nodetheory.com',
            password='Password123!',
            full_name='Outsider Student',
            account_type=AccountType.STUDENT,
            department='Electrical Engineering'
        )

        # Create team 'xander'
        self.team = Team.objects.create(
            name='xander',
            description='Project xander team workspace',
            created_by=self.leader,
            leader=self.leader
        )
        TeamMember.objects.create(team=self.team, user=self.leader, role='Leader')
        TeamMember.objects.create(team=self.team, user=self.teammate, role='Member')

        # Tokens
        self.leader_token = AuthToken.create_for_user(self.leader)
        self.leader_auth = {'HTTP_AUTHORIZATION': f'Bearer {self.leader_token.key}'}

        self.teammate_token = AuthToken.create_for_user(self.teammate)
        self.teammate_auth = {'HTTP_AUTHORIZATION': f'Bearer {self.teammate_token.key}'}

        self.outsider_token = AuthToken.create_for_user(self.outsider)
        self.outsider_auth = {'HTTP_AUTHORIZATION': f'Bearer {self.outsider_token.key}'}

    def test_team_chat_page_layout_and_empty_state_matching_screenshot(self):
        """
        Verify Workspace / Team chat layout matches screenshot media_1795186862393_ed57fcf1.png:
        - Category: PING
        - Page title: Team chat
        - Subtitle: Messages are visible to accepted members of the selected team.
        - Left column: Teams list with initial 'x', 'xander', '2 members'
        - Right column: Header 'xander', '2 team members'
        - Empty message: 'No messages yet. Start the conversation.'
        - Controls: Attach file, Write a message...., Send
        """
        response = self.client.get('/api/workspace/team-chat/', **self.leader_auth)
        self.assertEqual(response.status_code, 200)
        data = response.json()
        self.assertTrue(data['success'])

        # Page Info
        self.assertEqual(data['page_info']['category'], 'PING')
        self.assertEqual(data['page_info']['title'], 'Team chat')
        self.assertEqual(data['page_info']['subtitle'], 'Messages are visible to accepted members of the selected team.')
        self.assertEqual(data['page_info']['breadcrumb'], 'Workspace / Team chat')

        # Left Column: Teams
        self.assertEqual(len(data['teams']), 1)
        team_card = data['teams'][0]
        self.assertEqual(team_card['name'], 'xander')
        self.assertEqual(team_card['initial'], 'x')
        self.assertEqual(team_card['members_count'], 2)
        self.assertEqual(team_card['members_subtext'], '2 members')
        self.assertTrue(team_card['is_active'])

        # Right Column: Active Team Feed
        self.assertIsNotNone(data['active_team'])
        self.assertEqual(data['active_team']['name'], 'xander')
        self.assertEqual(data['active_team']['members_header'], '2 team members')
        self.assertEqual(data['empty_state']['message'], 'No messages yet. Start the conversation.')
        self.assertEqual(data['messages_count'], 0)
        self.assertEqual(data['messages'], [])

        # Input Controls labels
        self.assertEqual(data['input_placeholder'], 'Write a message....')
        self.assertEqual(data['attach_button_label'], 'Attach file')
        self.assertEqual(data['no_file_label'], 'No file selected')
        self.assertEqual(data['send_button_label'], 'Send')

    def test_team_chat_restricted_to_accepted_team_members(self):
        """
        Verify that team chat is strictly restricted to accepted members of the team.
        Non-members are denied access with 403 Forbidden.
        """
        # Outsider attempts to view messages
        get_res = self.client.get(f'/api/teams/{self.team.id}/chat/', **self.outsider_auth)
        self.assertEqual(get_res.status_code, 403)
        self.assertFalse(get_res.json()['success'])
        self.assertEqual(get_res.json()['error'], 'Messages are visible only to accepted members of the selected team.')

        # Outsider attempts to post a message
        post_res = self.client.post(
            f'/api/teams/{self.team.id}/chat/',
            data={'content': 'Unauthorized intrusion attempt'},
            **self.outsider_auth
        )
        self.assertEqual(post_res.status_code, 403)
        self.assertFalse(post_res.json()['success'])
        self.assertEqual(post_res.json()['error'], 'Messages are visible only to accepted members of the selected team.')

        # Outsider attempts to load workspace team chat with team_id
        ws_res = self.client.get(f'/api/workspace/team-chat/?team_id={self.team.id}', **self.outsider_auth)
        self.assertEqual(ws_res.status_code, 403)

    def test_send_team_message_with_attachment(self):
        """
        Verify sending a team message with a file attachment:
        - Uploads file and text
        - Stores attachment metadata: name, size, type, formatted_size, url
        - Message is saved and returned with has_attachment=True
        """
        fake_file = SimpleUploadedFile(
            'project_diagram.png',
            b'PNG_IMAGE_CONTENT_SAMPLE_1234567890',
            content_type='image/png'
        )

        response = self.client.post(
            f'/api/teams/{self.team.id}/messages/',
            data={
                'content': 'Here is the system architecture diagram for our submission.',
                'attachment': fake_file
            },
            **self.leader_auth
        )
        self.assertEqual(response.status_code, 201)
        data = response.json()
        self.assertTrue(data['success'])
        self.assertEqual(data['message'], 'Message sent successfully.')

        msg_data = data['data']
        self.assertEqual(msg_data['content'], 'Here is the system architecture diagram for our submission.')
        self.assertTrue(msg_data['has_attachment'])
        self.assertIsNotNone(msg_data['attachment'])
        self.assertEqual(msg_data['attachment']['name'], 'project_diagram.png')
        self.assertEqual(msg_data['attachment']['type'], 'image/png')
        self.assertTrue(msg_data['attachment']['formatted_size'].endswith('B'))
        self.assertTrue(msg_data['is_me'])

        # Verify in database
        db_msg = TeamMessage.objects.get(id=msg_data['id'])
        self.assertEqual(db_msg.attachment_name, 'project_diagram.png')
        self.assertIn(self.leader, db_msg.read_by.all())

    def test_send_file_only_and_text_only_and_empty_validation(self):
        """
        Verify:
        - Sending text only works.
        - Sending file only works without text.
        - Sending empty payload returns 400 Bad Request.
        """
        # Text only
        res_text = self.client.post(
            f'/api/teams/{self.team.id}/messages/',
            data={'content': 'Text only message.'},
            **self.leader_auth
        )
        self.assertEqual(res_text.status_code, 201)
        self.assertFalse(res_text.json()['data']['has_attachment'])

        # File only
        fake_doc = SimpleUploadedFile(
            'requirements.pdf',
            b'%PDF-1.4 SAMPLE DOCUMENT DATA',
            content_type='application/pdf'
        )
        res_file = self.client.post(
            f'/api/teams/{self.team.id}/messages/',
            data={'file': fake_doc},
            **self.leader_auth
        )
        self.assertEqual(res_file.status_code, 201)
        self.assertTrue(res_file.json()['data']['has_attachment'])
        self.assertEqual(res_file.json()['data']['attachment']['name'], 'requirements.pdf')

        # Empty payload
        res_empty = self.client.post(
            f'/api/teams/{self.team.id}/messages/',
            data={},
            **self.leader_auth
        )
        self.assertEqual(res_empty.status_code, 400)
        self.assertFalse(res_empty.json()['success'])
        self.assertEqual(res_empty.json()['error'], 'Please provide message content or attach a file.')

    def test_unread_messages_indication_in_notification_box(self):
        """
        CRITICAL REQUIREMENT TEST:
        When 2 or 3 messages are unread, an indication message is shown in the notification box:
        - 1 message: 'New message in xander'
        - 2 messages: '2 unread messages in xander' ('You have 2 unread messages in team 'xander'.')
        - 3 messages: '3 unread messages in xander' ('You have 3 unread messages in team 'xander'.')
        - Appears in recipient's notification box (/api/notifications/) with notification_type='team_message'.
        """
        # 1st message sent by Faris (leader)
        self.client.post(
            f'/api/teams/{self.team.id}/messages/',
            data={'content': 'Hey team, please review task 1.'},
            **self.leader_auth
        )

        # Check Sarah's notifications (1 message)
        notif_res1 = self.client.get('/api/notifications/', **self.teammate_auth)
        self.assertEqual(notif_res1.status_code, 200)
        self.assertEqual(notif_res1.json()['unread_count'], 1)
        notif1 = notif_res1.json()['notifications'][0]
        self.assertEqual(notif1['notification_type'], NotificationType.TEAM_MESSAGE)
        self.assertEqual(notif1['title'], 'New message in xander')
        self.assertIn('Hey team', notif1['message'])

        # 2nd message sent by Faris
        self.client.post(
            f'/api/teams/{self.team.id}/messages/',
            data={'content': 'Also uploaded the dataset file.'},
            **self.leader_auth
        )

        # Check Sarah's notifications (2 messages unread indication)
        notif_res2 = self.client.get('/api/notifications/', **self.teammate_auth)
        self.assertEqual(notif_res2.status_code, 200)
        self.assertEqual(notif_res2.json()['unread_count'], 1)  # Consolidated team notification
        notif2 = notif_res2.json()['notifications'][0]
        self.assertEqual(notif2['title'], '2 unread messages in xander')
        self.assertEqual(notif2['message'], "You have 2 unread messages in team 'xander'.")

        # 3rd message sent by Faris
        self.client.post(
            f'/api/teams/{self.team.id}/messages/',
            data={'content': 'Meeting tomorrow at 10 AM!'},
            **self.leader_auth
        )

        # Check Sarah's notifications (3 messages unread indication)
        notif_res3 = self.client.get('/api/notifications/', **self.teammate_auth)
        self.assertEqual(notif_res3.status_code, 200)
        notif3 = notif_res3.json()['notifications'][0]
        self.assertEqual(notif3['title'], '3 unread messages in xander')
        self.assertEqual(notif3['message'], "You have 3 unread messages in team 'xander'.")

        # Verify Dashboard unread counter shows the notification and team chat badge
        dash_res = self.client.get('/api/dashboard/', **self.teammate_auth)
        self.assertEqual(dash_res.status_code, 200)
        self.assertEqual(dash_res.json()['notifications']['unread_count'], 1)
        self.assertEqual(dash_res.json()['sidebar_badges']['unread_notifications'], 1)
        self.assertEqual(dash_res.json()['sidebar_badges']['team_chat'], 3)

    def test_opening_chat_or_marking_as_read_clears_notification_and_resets_unread(self):
        """
        Verify:
        - When teammate opens team chat (/api/workspace/team-chat/ or /api/teams/<id>/chat/),
          all unread messages are marked read and unread notification is cleared.
        - Notification is marked is_read=True.
        - Calling /api/teams/<id>/chat/read/ explicitly also marks read.
        """
        # Faris sends 3 messages
        for i in range(1, 4):
            self.client.post(
                f'/api/teams/{self.team.id}/messages/',
                data={'content': f'Message number {i}'},
                **self.leader_auth
            )

        # Verify unread count is 3 for teammate
        unread_msgs = TeamMessage.objects.filter(team=self.team).exclude(read_by=self.teammate).count()
        self.assertEqual(unread_msgs, 3)

        # Teammate opens workspace team chat
        chat_res = self.client.get(f'/api/workspace/team-chat/?team_id={self.team.id}', **self.teammate_auth)
        self.assertEqual(chat_res.status_code, 200)
        self.assertEqual(chat_res.json()['messages_count'], 3)

        # Verify messages are now read by teammate
        unread_after = TeamMessage.objects.filter(team=self.team).exclude(read_by=self.teammate).count()
        self.assertEqual(unread_after, 0)

        # Verify notification is marked read
        notif = Notification.objects.filter(recipient=self.teammate, notification_type=NotificationType.TEAM_MESSAGE).first()
        self.assertIsNotNone(notif)
        self.assertTrue(notif.is_read)

        # Dashboard sidebar badge is now 0
        dash_res = self.client.get('/api/dashboard/', **self.teammate_auth)
        self.assertEqual(dash_res.json()['sidebar_badges']['team_chat'], 0)
        self.assertEqual(dash_res.json()['notifications']['unread_count'], 0)

        # Explicit mark read endpoint works
        read_res = self.client.post(f'/api/teams/{self.team.id}/chat/read/', **self.teammate_auth)
        self.assertEqual(read_res.status_code, 200)
        self.assertTrue(read_res.json()['success'])
        self.assertEqual(read_res.json()['unread_count'], 0)

    def test_delete_team_message(self):
        """
        Verify message deletion:
        - Sender can delete their message.
        - Non-author regular member cannot delete another member's message.
        """
        # Leader sends message
        send_res = self.client.post(
            f'/api/teams/{self.team.id}/messages/',
            data={'content': 'Message to be deleted'},
            **self.leader_auth
        )
        msg_id = send_res.json()['data']['id']

        # Teammate (not author or leader) tries to delete -> forbidden
        del_attempt = self.client.delete(f'/api/teams/{self.team.id}/messages/{msg_id}/', **self.teammate_auth)
        # Leader is leader of the team, teammate is regular member
        # Teammate is not sender and not leader -> should be 403
        self.assertEqual(del_attempt.status_code, 403)

        # Sender (leader) deletes message -> 200 OK
        del_res = self.client.delete(f'/api/teams/{self.team.id}/messages/{msg_id}/', **self.leader_auth)
        self.assertEqual(del_res.status_code, 200)
        self.assertFalse(TeamMessage.objects.filter(id=msg_id).exists())


class PersonalChatBackendTests(TestCase):
    """
    Comprehensive test suite for Workspace / Chat (Personal 1-on-1 Direct Messaging):
    - Verifies exact visual structure matching screenshot media_1795188157069_2212b376.png:
      - 'PING' category, 'Chat' title
      - 'Private messages with other student accounts.' subtitle
      - Left column: contact card with initial 'F', name 'faris', email 'faris@gamil.com'
      - Right column: active contact header 'faris', 'faris@gamil.com'
      - Empty state: 'No messages yet. Start the conversation.'
      - Input controls: '[Attach file] No file selected', 'Write a message...', '[Send]'
    - Selecting contact by mail id / email to chat individually.
    - File attachment uploads (documents, images, code files).
    - Unread message indication in notification box when 2, 3 or more messages are unread:
      'You have 3 unread messages from Faris.'
    - Visiting chat or marking as read clears notifications and unread badge.
    - Dashboard sidebar badge reflects unread direct messages.
    """

    def setUp(self):
        self.client = Client()

        # Create Faris (as seen in screenshot: faris / faris@gamil.com)
        self.faris = User.objects.create_user(
            email='faris@gamil.com',
            password='Password123!',
            full_name='faris',
            account_type=AccountType.STUDENT,
            department='Computer Science'
        )

        # Create Sid (teammate/colleague chatting with Faris)
        self.sid = User.objects.create_user(
            email='sid@nodetheory.com',
            password='Password123!',
            full_name='sid',
            account_type=AccountType.STUDENT,
            department='Computer Science'
        )

        # Create third student
        self.alice = User.objects.create_user(
            email='alice@nodetheory.com',
            password='Password123!',
            full_name='Alice Wonder',
            account_type=AccountType.STUDENT,
            department='Design'
        )

        # Faris and Sid are teammates in a shared team
        self.team = Team.objects.create(name='xander', created_by=self.faris, leader=self.faris)
        TeamMember.objects.create(team=self.team, user=self.faris, role='Leader')
        TeamMember.objects.create(team=self.team, user=self.sid, role='Member')

        # Tokens
        self.faris_token = AuthToken.create_for_user(self.faris)
        self.faris_auth = {'HTTP_AUTHORIZATION': f'Bearer {self.faris_token.key}'}

        self.sid_token = AuthToken.create_for_user(self.sid)
        self.sid_auth = {'HTTP_AUTHORIZATION': f'Bearer {self.sid_token.key}'}

    def test_personal_chat_layout_matching_screenshot(self):
        """
        Verify Workspace / Chat layout matches screenshot media_1795188157069_2212b376.png:
        - Category: PING
        - Page title: Chat
        - Subtitle: Private messages with other student accounts.
        - Left column: contact card with initial 'F', name 'faris', email 'faris@gamil.com'
        - Right column: active contact header 'faris', 'faris@gamil.com'
        - Empty message: 'No messages yet. Start the conversation.'
        - Controls: Attach file, Write a message..., Send
        """
        response = self.client.get('/api/workspace/chat/?email=faris@gamil.com', **self.sid_auth)
        self.assertEqual(response.status_code, 200)
        data = response.json()
        self.assertTrue(data['success'])

        # Page Info
        self.assertEqual(data['page_info']['category'], 'PING')
        self.assertEqual(data['page_info']['title'], 'Chat')
        self.assertEqual(data['page_info']['subtitle'], 'Private messages with other student accounts.')
        self.assertEqual(data['page_info']['breadcrumb'], 'Workspace / Chat')

        # Left Column Contacts
        self.assertGreaterEqual(len(data['contacts']), 1)
        contact_card = data['contacts'][0]
        self.assertEqual(contact_card['email'], 'faris@gamil.com')
        self.assertEqual(contact_card['name'], 'faris')
        self.assertEqual(contact_card['initial'], 'F')
        self.assertTrue(contact_card['is_active'])

        # Right Column Active Contact Thread Header
        self.assertIsNotNone(data['active_contact'])
        self.assertEqual(data['active_contact']['email'], 'faris@gamil.com')
        self.assertEqual(data['active_contact']['name'], 'faris')
        self.assertEqual(data['active_contact']['initial'], 'F')

        # Empty State
        self.assertEqual(data['empty_state']['message'], 'No messages yet. Start the conversation.')
        self.assertEqual(data['messages_count'], 0)
        self.assertEqual(data['messages'], [])

        # Input Controls labels
        self.assertEqual(data['input_placeholder'], 'Write a message...')
        self.assertEqual(data['attach_button_label'], 'Attach file')
        self.assertEqual(data['no_file_label'], 'No file selected')
        self.assertEqual(data['send_button_label'], 'Send')

    def test_send_personal_message_by_selecting_mail_id(self):
        """
        Verify sending direct message to individual person by selecting their mail id:
        - Send message to faris@gamil.com
        - Stored with sender=sid, recipient=faris
        """
        payload = {
            'email': 'faris@gamil.com',
            'content': 'Hey Faris, let us discuss our project milestones.'
        }
        response = self.client.post('/api/messages/', data=payload, **self.sid_auth)
        self.assertEqual(response.status_code, 201)
        data = response.json()
        self.assertTrue(data['success'])
        self.assertIn('Message sent to faris (faris@gamil.com)', data['message'])

        msg_data = data['data']
        self.assertEqual(msg_data['content'], 'Hey Faris, let us discuss our project milestones.')
        self.assertEqual(msg_data['recipient']['email'], 'faris@gamil.com')
        self.assertEqual(msg_data['sender']['email'], 'sid@nodetheory.com')
        self.assertTrue(msg_data['is_me'])
        self.assertFalse(msg_data['is_read'])

    def test_send_personal_message_with_attachment(self):
        """
        Verify attaching file in personal 1-on-1 chat:
        - Uploads document with attachment file
        - Stores attachment_name, attachment_size, attachment_type, formatted_size, url
        """
        fake_pdf = SimpleUploadedFile(
            'research_notes.pdf',
            b'%PDF-1.4 TEST RESEARCH NOTES CONTENT',
            content_type='application/pdf'
        )

        response = self.client.post(
            '/api/messages/',
            data={
                'email': 'faris@gamil.com',
                'content': 'Sharing my latest research notes.',
                'attachment': fake_pdf
            },
            **self.sid_auth
        )
        self.assertEqual(response.status_code, 201)
        data = response.json()
        self.assertTrue(data['success'])

        msg_data = data['data']
        self.assertTrue(msg_data['has_attachment'])
        self.assertIsNotNone(msg_data['attachment'])
        self.assertEqual(msg_data['attachment']['name'], 'research_notes.pdf')
        self.assertEqual(msg_data['attachment']['type'], 'application/pdf')
        self.assertTrue(msg_data['attachment']['formatted_size'].endswith('B'))
        self.assertTrue(msg_data['attachment']['url'].startswith('/media/'))

    def test_personal_chat_unread_indication_in_notification_box(self):
        """
        CRITICAL REQUIREMENT TEST:
        When message arrives in inbox, an indication notification is sent to the notification button:
        - 1 message: 'New message from sid'
        - 2 messages: '2 unread messages from sid' ('You have 2 unread messages from sid.')
        - 3 messages: '3 unread messages from sid' ('You have 3 unread messages from sid.')
        - Appears in Faris's notification box (/api/notifications/) with notification_type='message'.
        """
        # 1st message sent by Sid to Faris
        self.client.post(
            '/api/messages/',
            data={'email': 'faris@gamil.com', 'content': 'Hello Faris, do you have a minute?'},
            **self.sid_auth
        )

        # Check Faris's notifications (1 message)
        notif_res1 = self.client.get('/api/notifications/', **self.faris_auth)
        self.assertEqual(notif_res1.status_code, 200)
        self.assertEqual(notif_res1.json()['unread_count'], 1)
        notif1 = notif_res1.json()['notifications'][0]
        self.assertEqual(notif1['notification_type'], NotificationType.MESSAGE)
        self.assertEqual(notif1['title'], 'New message from sid')
        self.assertIn('Hello Faris', notif1['message'])

        # 2nd message sent by Sid
        self.client.post(
            '/api/messages/',
            data={'email': 'faris@gamil.com', 'content': 'Checking on the dataset selection.'},
            **self.sid_auth
        )

        # Check Faris's notifications (2 messages unread indication)
        notif_res2 = self.client.get('/api/notifications/', **self.faris_auth)
        self.assertEqual(notif_res2.status_code, 200)
        self.assertEqual(notif_res2.json()['unread_count'], 1)
        notif2 = notif_res2.json()['notifications'][0]
        self.assertEqual(notif2['title'], '2 unread messages from sid')
        self.assertEqual(notif2['message'], 'You have 2 unread messages from sid.')

        # 3rd message sent by Sid
        self.client.post(
            '/api/messages/',
            data={'email': 'faris@gamil.com', 'content': 'Let us finalize topic H1!'},
            **self.sid_auth
        )

        # Check Faris's notifications (3 messages unread indication)
        notif_res3 = self.client.get('/api/notifications/', **self.faris_auth)
        self.assertEqual(notif_res3.status_code, 200)
        notif3 = notif_res3.json()['notifications'][0]
        self.assertEqual(notif3['title'], '3 unread messages from sid')
        self.assertEqual(notif3['message'], 'You have 3 unread messages from sid.')

        # Verify Dashboard unread counter and sidebar badge
        dash_res = self.client.get('/api/dashboard/', **self.faris_auth)
        self.assertEqual(dash_res.status_code, 200)
        self.assertEqual(dash_res.json()['notifications']['unread_count'], 1)
        self.assertEqual(dash_res.json()['sidebar_badges']['unread_notifications'], 1)
        self.assertEqual(dash_res.json()['sidebar_badges']['unread_messages'], 3)
        self.assertEqual(dash_res.json()['sidebar_badges']['chat'], 3)

    def test_opening_chat_or_marking_as_read_clears_notification_and_resets_unread(self):
        """
        Verify:
        - When Faris opens personal chat with Sid (/api/workspace/chat/?email=sid@nodetheory.com),
          all unread messages from Sid are marked read and unread notification is cleared.
        - Direct call to /api/chat/read/ also marks read.
        """
        # Sid sends 3 messages to Faris
        for i in range(1, 4):
            self.client.post(
                '/api/messages/',
                data={'email': 'faris@gamil.com', 'content': f'Direct message {i}'},
                **self.sid_auth
            )

        # Verify 3 unread messages for Faris
        self.assertEqual(Message.objects.filter(sender=self.sid, recipient=self.faris, is_read=False).count(), 3)

        # Faris opens chat with Sid
        chat_res = self.client.get('/api/workspace/chat/?email=sid@nodetheory.com', **self.faris_auth)
        self.assertEqual(chat_res.status_code, 200)
        self.assertEqual(chat_res.json()['messages_count'], 3)

        # Verify unread messages now 0
        self.assertEqual(Message.objects.filter(sender=self.sid, recipient=self.faris, is_read=False).count(), 0)

        # Verify notification is marked read
        notif = Notification.objects.filter(recipient=self.faris, notification_type=NotificationType.MESSAGE).first()
        self.assertIsNotNone(notif)
        self.assertTrue(notif.is_read)

        # Dashboard badges reset to 0
        dash_res = self.client.get('/api/dashboard/', **self.faris_auth)
        self.assertEqual(dash_res.json()['sidebar_badges']['unread_messages'], 0)
        self.assertEqual(dash_res.json()['sidebar_badges']['chat'], 0)
        self.assertEqual(dash_res.json()['notifications']['unread_count'], 0)

        # Explicit mark read endpoint works
        read_res = self.client.post('/api/chat/read/', data={'email': 'sid@nodetheory.com'}, **self.faris_auth)
        self.assertEqual(read_res.status_code, 200)
        self.assertTrue(read_res.json()['success'])
        self.assertEqual(read_res.json()['unread_count'], 0)

    def test_chat_contacts_list_and_search(self):
        """
        Verify listing contacts and searching by name/email:
        - Contacts include teammates and conversation partners
        - Query param ?search=Alice finds Alice
        """
        # Query contacts for Faris
        contacts_res = self.client.get('/api/chat/contacts/', **self.faris_auth)
        self.assertEqual(contacts_res.status_code, 200)
        emails = [c['email'] for c in contacts_res.json()['contacts']]
        self.assertIn('sid@nodetheory.com', emails)

        # Search for Alice
        search_res = self.client.get('/api/chat/contacts/?search=Alice', **self.faris_auth)
        self.assertEqual(search_res.status_code, 200)
        self.assertEqual(len(search_res.json()['contacts']), 1)
        self.assertEqual(search_res.json()['contacts'][0]['email'], 'alice@nodetheory.com')

    def test_validation_cannot_message_self_or_nonexistent_user(self):
        """
        Verify validation:
        - Cannot message oneself (returns 400).
        - Cannot message non-existent email (returns 404).
        """
        self_res = self.client.post(
            '/api/messages/',
            data={'email': 'faris@gamil.com', 'content': 'Talking to myself'},
            **self.faris_auth
        )
        self.assertEqual(self_res.status_code, 400)
        self.assertEqual(self_res.json()['error'], 'You cannot send a message to yourself.')

        none_res = self.client.post(
            '/api/messages/',
            data={'email': 'ghost@nowhere.com', 'content': 'Hello ghost'},
            **self.faris_auth
        )
        self.assertEqual(none_res.status_code, 404)


class QueriesWorkspaceBackendTests(TestCase):
    """
    Comprehensive test suite for Workspace / Queries (Questions & Answers):
    - Verifies exact visual structure matching screenshot media_1795189079667_69fd5640.png:
      - 'PING' category, 'Queries' active sidebar item with badge 0
      - 'ASK YOUR TEACHER' tag
      - 'Questions & answers' title
      - 'Get guidance from your teacher as you work through your project.' subtitle
      - Top action button '+ Ask a question'
      - Main card: 'Your questions' / 'Questions are shared with your teacher.'
      - Empty state: 'No questions yet. Ask your teacher for guidance.'
      - Bottom link: '+ Ask your teacher a question'
    - Student asks a question -> Notification is sent to Teacher's notification box.
    - Teacher replies -> Notification is sent into Student's notification box.
    - Reply appears in the exact place on the query object.
    - Status transitions from OPEN to ANSWERED.
    """

    def setUp(self):
        self.client = Client()

        # Create Teacher
        self.teacher = User.objects.create_user(
            email='prof.smith@nodetheory.com',
            password='Password123!',
            full_name='Dr. Smith',
            account_type=AccountType.TEACHER,
            department='Computer Science'
        )

        # Create Student Faris
        self.student = User.objects.create_user(
            email='faris@gamil.com',
            password='Password123!',
            full_name='faris',
            account_type=AccountType.STUDENT,
            department='Computer Science'
        )

        # Tokens
        self.teacher_token = AuthToken.create_for_user(self.teacher)
        self.teacher_auth = {'HTTP_AUTHORIZATION': f'Bearer {self.teacher_token.key}'}

        self.student_token = AuthToken.create_for_user(self.student)
        self.student_auth = {'HTTP_AUTHORIZATION': f'Bearer {self.student_token.key}'}

    def test_workspace_queries_layout_matching_screenshot(self):
        """
        Verify Workspace / Queries layout matches screenshot media_1795189079667_69fd5640.png:
        - Category: PING
        - Tag: ASK YOUR TEACHER
        - Title: Questions & answers
        - Subtitle: Get guidance from your teacher as you work through your project.
        - Button: + Ask a question
        - Card: Your questions / Questions are shared with your teacher.
        - Empty message: No questions yet. Ask your teacher for guidance.
        - Bottom link: + Ask your teacher a question
        - Sidebar badge queries: 0
        """
        response = self.client.get('/api/workspace/queries/', **self.student_auth)
        self.assertEqual(response.status_code, 200)
        data = response.json()
        self.assertTrue(data['success'])

        # Page Info
        self.assertEqual(data['page_info']['category'], 'PING')
        self.assertEqual(data['page_info']['tag'], 'ASK YOUR TEACHER')
        self.assertEqual(data['page_info']['title'], 'Questions & answers')
        self.assertEqual(data['page_info']['subtitle'], 'Get guidance from your teacher as you work through your project.')
        self.assertEqual(data['page_info']['breadcrumb'], 'Workspace / Queries')
        self.assertEqual(data['page_info']['active_nav'], 'queries')

        # Action Button
        self.assertEqual(data['action_button']['text'], '+ Ask a question')

        # Card Info
        self.assertEqual(data['card_info']['title'], 'Your questions')
        self.assertEqual(data['card_info']['subtitle'], 'Questions are shared with your teacher.')
        self.assertEqual(data['card_info']['empty_message'], 'No questions yet. Ask your teacher for guidance.')
        self.assertEqual(data['card_info']['bottom_link_text'], '+ Ask your teacher a question')

        # Empty state counts
        self.assertEqual(data['count'], 0)
        self.assertEqual(data['open_count'], 0)
        self.assertEqual(data['answered_count'], 0)
        self.assertEqual(data['queries'], [])
        self.assertEqual(data['sidebar_badges']['queries'], 0)

    def test_student_ask_question_sends_notification_to_teacher_box(self):
        """
        CRITICAL REQUIREMENT TEST:
        When a student asks a question:
        - The question is saved with status='open'.
        - A notification is automatically sent into the teacher's notification box.
        - Teacher notification box (/api/notifications/) displays the alert.
        - Teacher's unread notification counter increments.
        """
        payload = {
            'title': 'Clarification on CNN Architecture for H1 Case',
            'description': 'Should we use ResNet-50 or EfficientNet-B4 for the brain aneurysm classification?'
        }
        res = self.client.post('/api/workspace/queries/', data=payload, **self.student_auth)
        self.assertEqual(res.status_code, 201)
        data = res.json()
        self.assertTrue(data['success'])
        self.assertIn('Your question has been submitted and shared with your teacher.', data['message'])

        query_data = data['query']
        self.assertEqual(query_data['title'], 'Clarification on CNN Architecture for H1 Case')
        self.assertEqual(query_data['status'], 'open')
        self.assertEqual(query_data['asked_by']['email'], 'faris@gamil.com')
        self.assertFalse(query_data['has_reply'])

        # Check Teacher's notification box:
        teacher_notifs = self.client.get('/api/notifications/', **self.teacher_auth)
        self.assertEqual(teacher_notifs.status_code, 200)
        self.assertEqual(teacher_notifs.json()['unread_count'], 1)

        notif = teacher_notifs.json()['notifications'][0]
        self.assertEqual(notif['notification_type'], NotificationType.QUERY_ASKED)
        self.assertEqual(notif['title'], 'New Student Question: Clarification on CNN Architecture for H1 Case')
        self.assertIn('faris asked', notif['message'])
        self.assertIn('ResNet-50', notif['message'])
        self.assertIn('/workspace/queries/', notif['action_url'])

    def test_teacher_reply_sends_notification_to_student_and_displays_reply_in_place(self):
        """
        CRITICAL REQUIREMENT TEST:
        When teacher replies to student question:
        - The reply is saved and comes into the perfect place on the query.
        - Status updates to 'answered'.
        - Indication notification is sent into student's notification box.
        - Student's notification box (/api/notifications/) displays the alert.
        """
        # Student creates question
        query = Query.objects.create(
            title='How to format team project submission?',
            description='Should we submit ZIP file or Git repository link?',
            asked_by=self.student,
            status=QueryStatus.OPEN
        )

        # Teacher replies
        reply_payload = {
            'response': 'Please submit both a GitHub repository link and a release ZIP file with README.'
        }
        reply_res = self.client.post(f'/api/queries/{query.id}/reply/', data=reply_payload, **self.teacher_auth)
        self.assertEqual(reply_res.status_code, 200)
        data = reply_res.json()
        self.assertTrue(data['success'])

        # Verify reply is in the exact place on the query
        query_data = data['query']
        self.assertEqual(query_data['status'], 'answered')
        self.assertTrue(query_data['has_reply'])
        self.assertEqual(query_data['response'], 'Please submit both a GitHub repository link and a release ZIP file with README.')
        self.assertEqual(query_data['responded_by']['full_name'], 'Dr. Smith')

        # Check Student's notification box:
        student_notifs = self.client.get('/api/notifications/', **self.student_auth)
        self.assertEqual(student_notifs.status_code, 200)
        self.assertEqual(student_notifs.json()['unread_count'], 1)

        notif = student_notifs.json()['notifications'][0]
        self.assertEqual(notif['notification_type'], NotificationType.QUERY_ANSWERED)
        self.assertEqual(notif['title'], 'Teacher Answered Your Question: How to format team project submission?')
        self.assertIn('Prof. Dr. Smith replied', notif['message'])
        self.assertIn('GitHub repository', notif['message'])
        self.assertIn('/workspace/queries/', notif['action_url'])

        # Verify query displays the reply on Workspace Queries endpoint
        ws_res = self.client.get('/api/workspace/queries/', **self.student_auth)
        self.assertEqual(ws_res.status_code, 200)
        self.assertEqual(ws_res.json()['count'], 1)
        self.assertEqual(ws_res.json()['answered_count'], 1)
        self.assertEqual(ws_res.json()['open_count'], 0)
        self.assertEqual(ws_res.json()['queries'][0]['response'], 'Please submit both a GitHub repository link and a release ZIP file with README.')

    def test_queries_validation_and_deletion(self):
        """
        Verify validation and deletion:
        - Title and description required (400 Bad Request).
        - Author can delete question (200 OK).
        """
        # Empty submission returns 400
        empty_res = self.client.post('/api/workspace/queries/', data={'title': ''}, **self.student_auth)
        self.assertEqual(empty_res.status_code, 400)
        self.assertEqual(empty_res.json()['error'], 'Question title is required.')

        # Create and delete
        q = Query.objects.create(title='Temporary Question', description='To delete', asked_by=self.student)
        del_res = self.client.delete(f'/api/queries/{q.id}/', **self.student_auth)
        self.assertEqual(del_res.status_code, 200)
        self.assertFalse(Query.objects.filter(id=q.id).exists())


class NotificationPanelBackendTests(TestCase):
    """
    Comprehensive test suite for the updated Student Dashboard Notification Panel
    matching screenshot media_1795191141742_a61b9c81.png:
    - Modal Header:
      - Title: 'Your notifications'
      - Subtitle: 'Updates from your project workspace.'
      - Close icon '✕'
    - Notification Cards:
      1. 'Submission status' - 'Your last project is currently under review.' [Node Theory] - '2h ago'
      2. 'Project update' - 'Your latest project activity is ready to review.' - 'Today'
      3. 'Teacher reply' - 'Your teacher answered one of your questions.' - 'Yesterday'
    - Modal Footer buttons: 'Cancel' and 'Close'
    """

    def setUp(self):
        self.client = Client()
        self.student = User.objects.create_user(
            email='student.notif@nodetheory.com',
            password='Password123!',
            full_name='Student Notif',
            account_type=AccountType.STUDENT
        )
        self.token = AuthToken.create_for_user(self.student)
        self.auth = {'HTTP_AUTHORIZATION': f'Bearer {self.token.key}'}

    def test_notification_panel_modal_structure_matching_screenshot(self):
        """
        Verify the notification panel response structure matches the new UI modal:
        - panel_info and modal with title 'Your notifications', subtitle 'Updates from your project workspace.'
        - Buttons: Cancel and Close
        """
        res = self.client.get('/api/notifications/', **self.auth)
        self.assertEqual(res.status_code, 200)
        data = res.json()
        self.assertTrue(data['success'])

        # Modal info
        self.assertEqual(data['modal']['title'], 'Your notifications')
        self.assertEqual(data['modal']['subtitle'], 'Updates from your project workspace.')
        self.assertEqual(data['modal']['cancel_label'], 'Cancel')
        self.assertEqual(data['modal']['close_label'], 'Close')
        self.assertTrue(data['modal']['close_icon'])

        # Panel info
        self.assertEqual(data['panel_info']['title'], 'Your notifications')
        self.assertEqual(data['panel_info']['subtitle'], 'Updates from your project workspace.')
        self.assertEqual(data['panel_info']['buttons']['cancel'], 'Cancel')
        self.assertEqual(data['panel_info']['buttons']['close'], 'Close')

    def test_seed_student_dashboard_notifications_matching_screenshot(self):
        """
        Verify seeding and displaying the 3 workspace notifications from screenshot media_1795191141742_a61b9c81.png:
        1. 'Submission status' - 'Your last project is currently under review.' [Node Theory] (2h ago)
        2. 'Project update' - 'Your latest project activity is ready to review.' (Today)
        3. 'Teacher reply' - 'Your teacher answered one of your questions.' (Yesterday)
        """
        seed_res = self.client.post('/api/notifications/seed/', **self.auth)
        self.assertEqual(seed_res.status_code, 201)
        data = seed_res.json()
        self.assertTrue(data['success'])
        self.assertEqual(data['count'], 3)

        notifs = data['notifications']

        # Card 1: Submission status
        n1 = notifs[0]
        self.assertEqual(n1['title'], 'Submission status')
        self.assertEqual(n1['message'], 'Your last project is currently under review.')
        self.assertEqual(n1['tag'], 'Node Theory')
        self.assertEqual(n1['badge'], 'Node Theory')
        self.assertEqual(n1['time_ago'], '2h ago')

        # Card 2: Project update
        n2 = notifs[1]
        self.assertEqual(n2['title'], 'Project update')
        self.assertEqual(n2['message'], 'Your latest project activity is ready to review.')
        self.assertEqual(n2['time_ago'], 'Today')

        # Card 3: Teacher reply
        n3 = notifs[2]
        self.assertEqual(n3['title'], 'Teacher reply')
        self.assertEqual(n3['message'], 'Your teacher answered one of your questions.')
        self.assertEqual(n3['time_ago'], 'Yesterday')

        # Verify GET /api/notifications/panel/ returns all three cards
        panel_res = self.client.get('/api/notifications/panel/', **self.auth)
        self.assertEqual(panel_res.status_code, 200)
        self.assertEqual(panel_res.json()['count'], 3)
        self.assertEqual(panel_res.json()['unread_count'], 3)

    def test_notification_panel_close_and_mark_all_read(self):
        """
        Verify modal close and mark all as read:
        - Closing with mark_read=true updates all unread notifications to read.
        - Unread counter drops to 0.
        """
        # Seed 3 notifications
        self.client.post('/api/notifications/seed/', **self.auth)
        self.assertEqual(Notification.objects.filter(recipient=self.student, is_read=False).count(), 3)

        # Student clicks Close on notification modal
        close_res = self.client.post('/api/notifications/close/?mark_read=true', **self.auth)
        self.assertEqual(close_res.status_code, 200)
        data = close_res.json()
        self.assertTrue(data['success'])
        self.assertEqual(data['unread_count'], 0)

        # Database is updated
        self.assertEqual(Notification.objects.filter(recipient=self.student, is_read=False).count(), 0)

    def test_create_custom_notification_with_tag(self):
        """
        Verify creating notifications with custom tags/badges:
        - Post notification with tag='Node Theory'
        - Returns tag and badge in to_dict
        """
        payload = {
            'title': 'Submission status',
            'message': 'Your project proposal has been received.',
            'tag': 'Node Theory'
        }
        res = self.client.post('/api/notifications/', data=payload, **self.auth)
        self.assertEqual(res.status_code, 201)
        data = res.json()
        self.assertTrue(data['success'])
        self.assertEqual(data['notification']['tag'], 'Node Theory')
        self.assertEqual(data['notification']['badge'], 'Node Theory')









