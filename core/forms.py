import json
from django import forms
from django.core.exceptions import ValidationError
from django.core.validators import validate_email
from django.contrib.auth import password_validation
from django.contrib.auth import get_user_model
from core.models import AccountType, TeacherAccessCode

User = get_user_model()


class AccountRegistrationForm(forms.Form):
    """
    Form & Validator for the 'Start with a fresh account' page.
    Supports dynamic fields based on Account Type:
    - Student: Full name, Account type (Student), Department, Section, Email, Password.
    - Teacher: Full name, Account type (Teacher), Email, Password, Teacher sign-in code.
    """
    full_name = forms.CharField(
        max_length=150,
        required=True,
        error_messages={
            'required': 'Please enter your full name.',
            'max_length': 'Full name cannot exceed 150 characters.'
        }
    )
    account_type = forms.CharField(
        max_length=50,
        required=False,
        initial=AccountType.STUDENT
    )
    department = forms.CharField(
        max_length=120,
        required=False,
        error_messages={
            'max_length': 'Department name cannot exceed 120 characters.'
        }
    )
    section = forms.CharField(
        max_length=50,
        required=False,
        error_messages={
            'max_length': 'Section cannot exceed 50 characters.'
        }
    )
    teacher_sign_in_code = forms.CharField(
        max_length=100,
        required=False,
        error_messages={
            'max_length': 'Teacher sign-in code cannot exceed 100 characters.'
        }
    )
    email = forms.CharField(
        required=True,
        error_messages={
            'required': 'Please enter your email address.'
        }
    )
    password = forms.CharField(
        widget=forms.PasswordInput,
        required=True,
        min_length=8,
        error_messages={
            'required': 'Please enter a password.',
            'min_length': 'Password must be at least 8 characters long.'
        }
    )

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        # Support aliases for teacher_sign_in_code (teacher_code, sign_in_code, teacher_signin_code)
        if hasattr(self, 'data') and self.data:
            if not self.data.get('teacher_sign_in_code'):
                code_alias = (
                    self.data.get('teacher_code') or
                    self.data.get('sign_in_code') or
                    self.data.get('teacher_signin_code')
                )
                if code_alias:
                    # In querydict or dict
                    if hasattr(self.data, '_mutable') and not self.data._mutable:
                        self.data = self.data.copy()
                    self.data['teacher_sign_in_code'] = code_alias

    def clean_full_name(self):
        full_name = self.cleaned_data.get('full_name', '').strip()
        if not full_name:
            raise ValidationError('Full name cannot be empty or only spaces.')
        return full_name

    def clean_account_type(self):
        raw_type = self.cleaned_data.get('account_type')
        return AccountType.normalize(raw_type)

    def clean_email(self):
        raw_email = self.cleaned_data.get('email', '').strip().lower()
        if not raw_email:
            raise ValidationError('Email address is required.')

        try:
            validate_email(raw_email)
        except ValidationError:
            raise ValidationError('Please enter a valid email address.')

        # Restrict duplicate account creation
        if User.objects.filter(email__iexact=raw_email).exists():
            raise ValidationError(
                'An account with this email address already exists. Please log in instead.',
                code='account_already_exists'
            )

        return raw_email

    def clean_password(self):
        password = self.cleaned_data.get('password')
        if not password:
            raise ValidationError('Password is required.')

        temp_user = User(
            email=self.cleaned_data.get('email', ''),
            full_name=self.cleaned_data.get('full_name', ''),
            department=self.cleaned_data.get('department', ''),
            section=self.cleaned_data.get('section', '')
        )
        try:
            password_validation.validate_password(password, user=temp_user)
        except ValidationError as error:
            raise ValidationError(list(error.messages))

        return password

    def clean(self):
        cleaned_data = super().clean()
        account_type = cleaned_data.get('account_type', AccountType.STUDENT)
        department = cleaned_data.get('department', '').strip()
        section = cleaned_data.get('section', '').strip()
        teacher_code = cleaned_data.get('teacher_sign_in_code', '').strip()

        # Handle dropdown placeholder strings
        if department.lower() in ('choose your department', 'choose department', 'select department'):
            department = ''
        if section.lower() in ('choose your section', 'choose section', 'select section'):
            section = ''

        if account_type in (AccountType.TEACHER, AccountType.FACULTY):
            # -------------------------------------------------------------
            # TEACHER REGISTRATION RULES
            # -------------------------------------------------------------
            # 1. Teacher sign-in code is required and must be valid
            if not teacher_code:
                self.add_error('teacher_sign_in_code', 'Teacher sign-in code is required.')
            elif not TeacherAccessCode.is_valid_code(teacher_code):
                self.add_error(
                    'teacher_sign_in_code',
                    'Invalid teacher sign-in code. Please check with your administrator.'
                )

            # 2. Department & section are optional for teachers
            if not department:
                department = 'Faculty'
            cleaned_data['department'] = department
            cleaned_data['section'] = section
        else:
            # -------------------------------------------------------------
            # STUDENT REGISTRATION RULES
            # -------------------------------------------------------------
            # 1. Department is required for students
            if not department:
                self.add_error('department', 'Please choose your department.')
            cleaned_data['department'] = department
            cleaned_data['section'] = section

        return cleaned_data


class LoginForm(forms.Form):
    """
    Form & Validator for the 'Welcome back' login page.
    Supports email, password, and optional account_type ('student' or 'teacher').
    """
    email = forms.CharField(
        required=True,
        error_messages={
            'required': 'Please enter your email address.'
        }
    )
    password = forms.CharField(
        widget=forms.PasswordInput,
        required=True,
        error_messages={
            'required': 'Please enter your password.'
        }
    )
    account_type = forms.CharField(
        max_length=50,
        required=False
    )
    teacher_sign_in_code = forms.CharField(
        max_length=100,
        required=False
    )

    def clean_email(self):
        email = self.cleaned_data.get('email', '').strip().lower()
        if not email:
            raise ValidationError('Email address is required.')
        try:
            validate_email(email)
        except ValidationError:
            raise ValidationError('Please enter a valid email address.')
        return email

    def clean_account_type(self):
        raw = self.cleaned_data.get('account_type')
        if not raw:
            return None
        return AccountType.normalize(raw)
