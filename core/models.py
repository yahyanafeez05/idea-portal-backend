from django.db import models
from django.contrib.auth.models import AbstractBaseUser, PermissionsMixin, BaseUserManager
from django.utils import timezone
from django.utils.translation import gettext_lazy as _
import secrets


class AccountType(models.TextChoices):
    STUDENT = 'student', _('Student')
    FACULTY = 'faculty', _('Faculty')
    STAFF = 'staff', _('Staff')
    OTHER = 'other', _('Other')

    @classmethod
    def normalize(cls, value):
        """
        Helper to normalize user-submitted account types like 'Student', 'STUDENT', 'student'
        to valid choices. Defaults to STUDENT if unrecognized or empty.
        """
        if not value:
            return cls.STUDENT
        val_str = str(value).strip().lower()
        for choice in cls.values:
            if choice == val_str:
                return choice
        # Also check display labels
        for choice_val, choice_label in cls.choices:
            if str(choice_label).lower() == val_str:
                return choice_val
        return cls.STUDENT


class UserManager(BaseUserManager):
    """
    Custom user manager where email is the unique identifier
    for authentication instead of usernames.
    """

    def create_user(self, email, password=None, full_name='', department='', account_type=AccountType.STUDENT, **extra_fields):
        if not email:
            raise ValueError(_('The Email address must be provided.'))
        if not password:
            raise ValueError(_('A password must be provided.'))

        email = self.normalize_email(email).strip().lower()

        extra_fields.setdefault('is_active', True)
        extra_fields.setdefault('is_staff', False)
        extra_fields.setdefault('is_superuser', False)

        normalized_type = AccountType.normalize(account_type)

        user = self.model(
            email=email,
            full_name=full_name.strip(),
            department=department.strip(),
            account_type=normalized_type,
            **extra_fields
        )
        user.set_password(password)
        user.save(using=self._db)
        return user

    def create_superuser(self, email, password=None, full_name='Administrator', department='Administration', **extra_fields):
        extra_fields.setdefault('is_staff', True)
        extra_fields.setdefault('is_superuser', True)
        extra_fields.setdefault('is_active', True)

        if extra_fields.get('is_staff') is not True:
            raise ValueError(_('Superuser must have is_staff=True.'))
        if extra_fields.get('is_superuser') is not True:
            raise ValueError(_('Superuser must have is_superuser=True.'))

        return self.create_user(
            email=email,
            password=password,
            full_name=full_name,
            department=department,
            account_type=AccountType.STAFF,
            **extra_fields
        )


class User(AbstractBaseUser, PermissionsMixin):
    """
    Custom User Model matching the Node Theory Account UI:
    - Full name
    - Account type (Dropdown: Student, Faculty, Staff, Other)
    - Department
    - Email (Unique identifier)
    - Password (Hashed via PBKDF2)
    """

    email = models.EmailField(
        _('Email Address'),
        unique=True,
        db_index=True,
        error_messages={
            'unique': _('An account with this email address already exists.'),
        }
    )
    full_name = models.CharField(
        _('Full Name'),
        max_length=150
    )
    account_type = models.CharField(
        _('Account Type'),
        max_length=20,
        choices=AccountType.choices,
        default=AccountType.STUDENT
    )
    department = models.CharField(
        _('Department'),
        max_length=120
    )

    is_active = models.BooleanField(
        _('Active'),
        default=True,
        help_text=_('Designates whether this user account is active. Deselect instead of deleting accounts.')
    )
    is_staff = models.BooleanField(
        _('Staff Status'),
        default=False,
        help_text=_('Designates whether the user can log into the Django admin site.')
    )
    date_joined = models.DateTimeField(
        _('Date Joined'),
        default=timezone.now
    )

    objects = UserManager()

    USERNAME_FIELD = 'email'
    REQUIRED_FIELDS = ['full_name', 'department']

    class Meta:
        verbose_name = _('User')
        verbose_name_plural = _('Users')
        ordering = ['-date_joined']

    def __str__(self):
        return f"{self.full_name} <{self.email}>"

    def clean(self):
        super().clean()
        if self.email:
            self.email = self.email.strip().lower()

    def save(self, *args, **kwargs):
        if self.email:
            self.email = self.email.strip().lower()
        super().save(*args, **kwargs)

    def to_dict(self):
        """Returns public user data dictionary for API responses."""
        return {
            'id': self.id,
            'full_name': self.full_name,
            'email': self.email,
            'account_type': self.account_type,
            'account_type_display': self.get_account_type_display(),
            'department': self.department,
            'is_active': self.is_active,
            'date_joined': self.date_joined.isoformat() if self.date_joined else None,
            'last_login': self.last_login.isoformat() if self.last_login else None,
        }


class AuthToken(models.Model):
    """
    Cryptographically secure API token for client apps (React/Vue/mobile/external clients).
    Passed in headers as:
        Authorization: Bearer <key>
        or
        Authorization: Token <key>
    """
    key = models.CharField(max_length=64, primary_key=True)
    user = models.ForeignKey(
        User,
        related_name='auth_tokens',
        on_delete=models.CASCADE,
        verbose_name=_('User')
    )
    created_at = models.DateTimeField(auto_now_add=True)
    last_used_at = models.DateTimeField(auto_now=True)
    is_active = models.BooleanField(default=True)

    class Meta:
        verbose_name = _('Auth Token')
        verbose_name_plural = _('Auth Tokens')
        ordering = ['-created_at']

    def __str__(self):
        return f"Token({self.user.email} - {self.key[:8]}...)"

    @classmethod
    def create_for_user(cls, user):
        """Generates a secure random 64-hex-char token."""
        token_key = secrets.token_hex(32)
        return cls.objects.create(key=token_key, user=user)
