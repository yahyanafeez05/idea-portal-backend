import json
from django.test import TestCase, Client
from django.urls import reverse
from django.contrib.auth import get_user_model
from core.models import AccountType, AuthToken

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
        """Test account creation with all required fields from Screen 1."""
        payload = {
            'full_name': 'Sarah Connor',
            'account_type': 'Student',
            'department': 'Computer Science',
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

        # Check database
        user = User.objects.get(email='sarah.connor@example.com')
        self.assertTrue(user.check_password('StrongPassword2026!'))

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
            'account_type': 'Faculty',
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

