import json
from django import forms
from django.core.exceptions import ValidationError
from django.core.validators import validate_email
from django.contrib.auth import password_validation
from django.contrib.auth import get_user_model
from core.models import AccountType

User = get_user_model()


class AccountRegistrationForm(forms.Form):
    """
    Form & Validator for the 'Start with a fresh account' page:
    - Full name
    - Account type (Dropdown: Student, Faculty, Staff, Other)
    - Department
    - Email
    - Password
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
        required=True,
        error_messages={
            'required': 'Please enter your department.',
            'max_length': 'Department name cannot exceed 120 characters.'
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

    def clean_full_name(self):
        full_name = self.cleaned_data.get('full_name', '').strip()
        if not full_name:
            raise ValidationError('Full name cannot be empty or only spaces.')
        return full_name

    def clean_department(self):
        department = self.cleaned_data.get('department', '').strip()
        if not department:
            raise ValidationError('Department cannot be empty or only spaces.')
        return department

    def clean_account_type(self):
        raw_type = self.cleaned_data.get('account_type')
        return AccountType.normalize(raw_type)

    def clean_email(self):
        raw_email = self.cleaned_data.get('email', '').strip().lower()
        if not raw_email:
            raise ValidationError('Email address is required.')

        # Validate email syntax
        try:
            validate_email(raw_email)
        except ValidationError:
            raise ValidationError('Please enter a valid email address.')

        # CRITICAL REQUIREMENT: Restrict duplicate account creation
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

        # Validate with Django's password validators
        # We construct a temporary user instance for attribute similarity checks
        temp_user = User(
            email=self.cleaned_data.get('email', ''),
            full_name=self.cleaned_data.get('full_name', ''),
            department=self.cleaned_data.get('department', '')
        )
        try:
            password_validation.validate_password(password, user=temp_user)
        except ValidationError as error:
            raise ValidationError(list(error.messages))

        return password


class LoginForm(forms.Form):
    """
    Form & Validator for the 'Welcome back' login page:
    - Email
    - Password
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

    def clean_email(self):
        email = self.cleaned_data.get('email', '').strip().lower()
        if not email:
            raise ValidationError('Email address is required.')
        try:
            validate_email(email)
        except ValidationError:
            raise ValidationError('Please enter a valid email address.')
        return email
