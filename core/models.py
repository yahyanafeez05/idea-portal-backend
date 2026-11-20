from django.db import models
from django.contrib.auth.models import AbstractBaseUser, PermissionsMixin, BaseUserManager
from django.utils import timezone
from django.utils.translation import gettext_lazy as _
import secrets


class AccountType(models.TextChoices):
    STUDENT = 'student', _('Student')
    TEACHER = 'teacher', _('Teacher')
    FACULTY = 'faculty', _('Faculty')
    STAFF = 'staff', _('Staff')
    OTHER = 'other', _('Other')

    @classmethod
    def normalize(cls, value):
        """
        Helper to normalize user-submitted account types like 'Student', 'Teacher', 'Faculty', etc.
        Defaults to STUDENT if unrecognized or empty.
        """
        if not value:
            return cls.STUDENT
        val_str = str(value).strip().lower()
        if val_str in ('teacher', 'faculty', 'professor', 'instructor'):
            return cls.TEACHER
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

    def create_user(self, email, password=None, full_name='', department='', account_type=AccountType.STUDENT, section='', **extra_fields):
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
            section=str(section or '').strip(),
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
    section = models.CharField(
        _('Section'),
        max_length=50,
        blank=True,
        default=''
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
        is_teacher = self.account_type in (AccountType.TEACHER, AccountType.FACULTY)
        is_student = self.account_type == AccountType.STUDENT
        role = 'teacher' if is_teacher else ('student' if is_student else self.account_type)

        return {
            'id': self.id,
            'full_name': self.full_name,
            'email': self.email,
            'account_type': self.account_type,
            'account_type_display': self.get_account_type_display(),
            'role': role,
            'is_teacher': is_teacher,
            'is_student': is_student,
            'department': self.department,
            'section': self.section,
            'workspace_label': f"{self.get_account_type_display().upper()} WORKSPACE",
            'redirect_url': '/teacher/dashboard' if is_teacher else '/dashboard',
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


# ==============================================================================
# WORKSPACE MODELS: Projects, Teams, Queries, Messages
# ==============================================================================

class ProjectStatus(models.TextChoices):
    DRAFT = 'draft', _('Draft')
    NOT_STARTED = 'not_started', _('Not started')
    IN_PROGRESS = 'in_progress', _('In progress')
    AWAITING_REVIEW = 'awaiting_review', _('Awaiting review')
    APPROVED = 'approved', _('Approved')
    REJECTED = 'rejected', _('Rejected')
    COMPLETED = 'completed', _('Completed')

    @classmethod
    def normalize(cls, value):
        if not value:
            return cls.AWAITING_REVIEW
        val_str = str(value).strip().lower().replace(' ', '_').replace('-', '_')
        for choice in cls.values:
            if choice == val_str:
                return choice
        return cls.AWAITING_REVIEW


class TeacherAccessCode(models.Model):
    """
    Authorized sign-in codes for teacher / faculty account creation.
    Protects teacher registration so only authorized educators can register.
    """
    code = models.CharField(_('Access Code'), max_length=64, unique=True)
    description = models.CharField(_('Description / Assigned To'), max_length=150, blank=True)
    is_active = models.BooleanField(_('Is Active'), default=True)
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        verbose_name = _('Teacher Sign-In Code')
        verbose_name_plural = _('Teacher Sign-In Codes')
        ordering = ['-created_at']

    def __str__(self):
        return f"{self.code} ({'Active' if self.is_active else 'Inactive'})"

    @classmethod
    def is_valid_code(cls, raw_code):
        if not raw_code:
            return False
        clean_code = str(raw_code).strip()
        # Standard built-in authorized teacher codes
        default_codes = {'TEACH2026', 'NODE-TEACHER', 'NT-TEACHER-2026', 'TEACHER', 'TEACHER123', 'FACULTY2026'}
        if clean_code.upper() in default_codes:
            return True
        # Check database for custom administrator-created teacher codes
        return cls.objects.filter(code__iexact=clean_code, is_active=True).exists()


class Team(models.Model):
    """
    Workspace Teams for collaborating on projects.
    """
    name = models.CharField(_('Team Name'), max_length=150)
    description = models.TextField(_('Description'), blank=True)
    created_by = models.ForeignKey(
        User,
        related_name='created_teams',
        on_delete=models.CASCADE,
        verbose_name=_('Created By')
    )
    leader = models.ForeignKey(
        User,
        related_name='led_teams',
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        verbose_name=_('Team Leader')
    )
    assigned_by_teacher = models.ForeignKey(
        User,
        related_name='teacher_assigned_teams',
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        verbose_name=_('Assigned By Teacher')
    )
    photo = models.FileField(_('Team Photo'), upload_to='team_photos/%Y/%m/', null=True, blank=True)
    department = models.CharField(_('Department'), max_length=120, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        verbose_name = _('Team')
        verbose_name_plural = _('Teams')
        ordering = ['-created_at']

    def __str__(self):
        return self.name

    def save(self, *args, **kwargs):
        if not self.leader and self.created_by:
            self.leader = self.created_by
        if not self.department and self.created_by:
            self.department = self.created_by.department
        super().save(*args, **kwargs)

    def get_photo_url(self):
        try:
            return self.photo.url if self.photo else ''
        except Exception:
            return ''

    def delete(self, *args, **kwargs):
        # Free any assigned topic so other teams can select it
        if hasattr(self, 'assigned_topics'):
            for topic in self.assigned_topics.all():
                topic.team = None
                topic.selected_by = None
                topic.selected_at = None
                topic.status = TopicStatus.AVAILABLE
                topic.save()
        super().delete(*args, **kwargs)

    def to_dict(self):
        members = [
            {
                'id': m.user.id,
                'full_name': m.user.full_name,
                'email': m.user.email,
                'department': m.user.department,
                'role': m.role,
                'is_leader': (self.leader_id == m.user.id) or (m.role.lower() == 'leader'),
                'joined_at': m.joined_at.isoformat() if m.joined_at else None
            }
            for m in self.memberships.select_related('user').all()
        ]
        active_proj = self.projects.first()
        active_project_data = {
            'id': active_proj.id,
            'title': active_proj.title,
            'status': active_proj.status,
            'status_display': active_proj.get_status_display(),
            'progress': active_proj.progress,
            'topic_code': active_proj.topic.case_code if active_proj.topic else None,
        } if active_proj else None

        pending_invites = [
            inv.to_dict() for inv in self.invitations.filter(status='pending').select_related('invited_user', 'invited_by')
        ] if hasattr(self, 'invitations') else []

        leader_user = self.leader or self.created_by
        return {
            'id': self.id,
            'name': self.name,
            'description': self.description,
            'initial': self.name[0].lower() if self.name else 'x',
            'photo': self.get_photo_url(),
            'photo_url': self.get_photo_url(),
            'department': self.department,
            'leader': {
                'id': leader_user.id,
                'full_name': leader_user.full_name,
                'email': leader_user.email,
                'department': leader_user.department
            } if leader_user else None,
            'created_by': {
                'id': self.created_by.id,
                'full_name': self.created_by.full_name,
                'email': self.created_by.email
            } if self.created_by else None,
            'assigned_by_teacher': {
                'id': self.assigned_by_teacher.id,
                'full_name': self.assigned_by_teacher.full_name,
                'email': self.assigned_by_teacher.email
            } if self.assigned_by_teacher else None,
            'is_teacher_assigned': bool(self.assigned_by_teacher),
            'members_count': len(members),
            'members_subtext': f"{len(members)} members",
            'members': members,
            'actions': {
                'edit_details': f"/api/teams/{self.id}/",
                'invite_member': f"/api/teams/{self.id}/invitations/",
                'delete_team': f"/api/teams/{self.id}/",
                'upload_project': f"/api/teams/{self.id}/upload-project/",
            },
            'active_project': active_project_data,
            'pending_invitations_count': len(pending_invites),
            'pending_invitations': pending_invites,
            'created_at': self.created_at.isoformat() if self.created_at else None,
            'updated_at': self.updated_at.isoformat() if self.updated_at else None,
        }


class TeamMember(models.Model):
    """
    Membership linking Users to Teams.
    """
    team = models.ForeignKey(Team, related_name='memberships', on_delete=models.CASCADE)
    user = models.ForeignKey(User, related_name='team_memberships', on_delete=models.CASCADE)
    role = models.CharField(max_length=50, default='member')
    joined_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        verbose_name = _('Team Member')
        verbose_name_plural = _('Team Members')
        unique_together = ('team', 'user')

    def __str__(self):
        return f"{self.user.full_name} in {self.team.name} ({self.role})"


class InvitationStatus(models.TextChoices):
    PENDING = 'pending', _('Pending')
    ACCEPTED = 'accepted', _('Accepted')
    REJECTED = 'rejected', _('Rejected')
    CANCELLED = 'cancelled', _('Cancelled')


class TeamInvitation(models.Model):
    """
    Invitations sent by Team Leader to Users/Students to join the team.
    Tracks acceptance and rejection messages back to the leader.
    """
    team = models.ForeignKey(Team, related_name='invitations', on_delete=models.CASCADE)
    invited_by = models.ForeignKey(User, related_name='sent_invitations', on_delete=models.CASCADE)
    invited_user = models.ForeignKey(User, related_name='received_invitations', on_delete=models.CASCADE)
    role = models.CharField(max_length=50, default='Member')
    status = models.CharField(
        max_length=30,
        choices=InvitationStatus.choices,
        default=InvitationStatus.PENDING,
        db_index=True
    )
    message = models.TextField(_('Message'), blank=True)
    rejection_reason = models.TextField(_('Rejection Reason'), blank=True)
    responded_at = models.DateTimeField(null=True, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        verbose_name = _('Team Invitation')
        verbose_name_plural = _('Team Invitations')
        ordering = ['-created_at']

    def __str__(self):
        return f"Invite for {self.invited_user.full_name} to {self.team.name} ({self.status})"

    def to_dict(self):
        return {
            'id': self.id,
            'team_id': self.team.id,
            'team_name': self.team.name,
            'team_description': self.team.description,
            'team_photo': self.team.get_photo_url(),
            'invited_by': {
                'id': self.invited_by.id,
                'full_name': self.invited_by.full_name,
                'email': self.invited_by.email
            },
            'invited_user': {
                'id': self.invited_user.id,
                'full_name': self.invited_user.full_name,
                'email': self.invited_user.email,
                'department': self.invited_user.department
            },
            'status': self.status,
            'status_display': self.get_status_display(),
            'role': self.role,
            'message': self.message,
            'rejection_reason': self.rejection_reason,
            'responded_at': self.responded_at.isoformat() if self.responded_at else None,
            'created_at': self.created_at.isoformat() if self.created_at else None,
            'formatted_created_at': self.created_at.strftime('%b %d, %Y') if self.created_at else '',
        }


class TopicStatus(models.TextChoices):
    AVAILABLE = 'available', _('Available')
    SELECTED = 'selected', _('Selected')
    ASSIGNED = 'assigned', _('Assigned')
    IN_PROGRESS = 'in_progress', _('In progress')
    COMPLETED = 'completed', _('Completed')


class Topic(models.Model):
    """
    Project Topics / Case Datasets matching 'Workspace / Data' Topics table:
    - Case (e.g. H1, H2, H3...)
    - Title
    - Domain (e.g. Healthcare, AI, etc.)
    - Level (e.g. High, Moderate)
    - Team (ForeignKey to Team, null=True, blank=True)
    - Guide (Guide / mentor name or note)
    - Status (Available, Selected, Assigned...)
    - Selected By (ForeignKey to User, null=True, blank=True)
    - Selected At (DateTimeField, null=True, blank=True)
    """
    case_code = models.CharField(_('Case'), max_length=50, unique=True, db_index=True)
    title = models.CharField(_('Title'), max_length=255)
    domain = models.CharField(_('Domain'), max_length=120, default='Healthcare')
    level = models.CharField(_('Level'), max_length=50, default='Moderate')
    team = models.ForeignKey(
        'Team',
        related_name='assigned_topics',
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        verbose_name=_('Team ID')
    )
    guide = models.CharField(_('Guide'), max_length=150, blank=True, default='')
    status = models.CharField(
        _('Status'),
        max_length=30,
        choices=TopicStatus.choices,
        default=TopicStatus.AVAILABLE,
        db_index=True
    )
    selected_by = models.ForeignKey(
        User,
        related_name='selected_topics',
        on_delete=models.SET_NULL,
        null=True,
        blank=True
    )
    selected_at = models.DateTimeField(null=True, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        verbose_name = _('Topic')
        verbose_name_plural = _('Topics')
        ordering = ['id']

    def __str__(self):
        return f"{self.case_code}: {self.title} ({self.status})"

    def to_dict(self):
        return {
            'id': self.id,
            'case': self.case_code,
            'case_code': self.case_code,
            'title': self.title,
            'domain': self.domain,
            'level': self.level,
            'team_id': self.team.id if self.team else None,
            'team_name': self.team.name if self.team else '',
            'team_display': self.team.name if self.team else '',
            'guide': self.guide,
            'status': self.get_status_display(),
            'status_raw': self.status,
            'is_available': self.status == TopicStatus.AVAILABLE and self.team is None,
            'selected_by': self.selected_by.full_name if self.selected_by else None,
            'selected_at': self.selected_at.isoformat() if self.selected_at else None,
            'formatted_selected_date': self.selected_at.strftime('%B %d, %Y') if self.selected_at else '',
        }

    @classmethod
    def seed_defaults(cls):
        """Seed the 11 healthcare topics from the Node Theory Data Topics screen."""
        default_data = [
            ('H1', 'AI-Based Brain Aneurysm Triage on CT and MR Angiography', 'Healthcare', 'High'),
            ('H2', 'Digitisation of Paper and Photographed ECGs with Arrhythmia Flagging', 'Healthcare', 'Moderate'),
            ('H3', 'Safe Drug-Decision Assistant with Retrieval and Refusal', 'Healthcare', 'Moderate'),
            ('H4', 'Hospital Antibiogram and Empiric-Antibiotic Guide', 'Healthcare', 'Moderate'),
            ('H5', 'Seizure and Abnormal-EEG Detection across Patients', 'Healthcare', 'High'),
            ('H6', 'Oral Cancer Screening from Pathology Slides and Mouth Photos', 'Healthcare', 'Moderate'),
            ('H7', 'Voice Copilot for Frontline Health Workers', 'Healthcare', 'Moderate'),
            ('H8', 'Early Disease-Trend Warning from AYUSH and OPD Records', 'Healthcare', 'Moderate'),
            ('H9', 'Safe Health-Information Chatbot in Local Languages', 'Healthcare', 'Moderate'),
            ('H10', 'PressureGuard: Smart Bedsore Prevention Mat', 'Healthcare', 'High'),
            ('H11', 'Pasu: AI Speech-Therapy Coach in Tamil', 'Healthcare', 'High'),
        ]
        created_count = 0
        for code, title, domain, level in default_data:
            obj, created = cls.objects.get_or_create(
                case_code=code,
                defaults={
                    'title': title,
                    'domain': domain,
                    'level': level,
                    'status': TopicStatus.AVAILABLE
                }
            )
            if created:
                created_count += 1
        return created_count


class Project(models.Model):
    """
    Workspace Projects matching the Node Theory Dashboard:
    - Counts for 'Projects', 'Approved', 'Awaiting review'
    - 'Recent projects' list
    """
    title = models.CharField(_('Project Title'), max_length=200)
    description = models.TextField(_('Description'), blank=True)
    topic = models.ForeignKey(
        Topic,
        related_name='projects',
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        verbose_name=_('Selected Topic')
    )
    owner = models.ForeignKey(
        User,
        related_name='owned_projects',
        on_delete=models.CASCADE,
        verbose_name=_('Owner / Author')
    )
    team = models.ForeignKey(
        Team,
        related_name='projects',
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        verbose_name=_('Team')
    )
    department = models.CharField(_('Department'), max_length=120, blank=True)
    status = models.CharField(
        _('Status'),
        max_length=30,
        choices=ProjectStatus.choices,
        default=ProjectStatus.NOT_STARTED,
        db_index=True
    )
    progress = models.IntegerField(_('Progress (%)'), default=0)
    is_selected = models.BooleanField(_('Is Selected'), default=False)
    selected_at = models.DateTimeField(_('Selected Date'), null=True, blank=True)
    github_url = models.URLField(_('Repository URL'), blank=True, null=True)
    live_url = models.URLField(_('Live URL'), blank=True, null=True)
    feedback = models.TextField(_('Feedback / Review Notes'), blank=True)
    reviewed_by = models.ForeignKey(
        User,
        related_name='reviewed_projects',
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        verbose_name=_('Reviewed By')
    )
    reviewed_at = models.DateTimeField(_('Reviewed At'), null=True, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        verbose_name = _('Project')
        verbose_name_plural = _('Projects')
        ordering = ['-created_at']

    def __str__(self):
        return f"{self.title} ({self.get_status_display()})"

    def save(self, *args, **kwargs):
        if not self.department and self.owner:
            self.department = self.owner.department
        super().save(*args, **kwargs)

    def delete(self, *args, **kwargs):
        # When a project linked to a topic is deleted, free the topic for other teams
        if self.topic:
            topic = self.topic
            topic.team = None
            topic.selected_by = None
            topic.selected_at = None
            topic.status = TopicStatus.AVAILABLE
            topic.save()
        super().delete(*args, **kwargs)

    def to_dict(self):
        return {
            'id': self.id,
            'title': self.title,
            'description': self.description,
            'owner': {
                'id': self.owner.id,
                'full_name': self.owner.full_name,
                'email': self.owner.email,
                'department': self.owner.department,
            },
            'team': {'id': self.team.id, 'name': self.team.name} if self.team else None,
            'team_name': self.team.name if self.team else None,
            'is_team_project': bool(self.team_id),
            'department': self.department,
            'status': self.status,
            'status_display': self.get_status_display(),
            'progress': self.progress,
            'progress_display': f"{self.progress}%",
            'is_selected': self.is_selected or bool(self.topic),
            'topic_code': self.topic.case_code if self.topic else None,
            'topic_title': self.topic.title if self.topic else None,
            'topic': self.topic.to_dict() if self.topic else None,
            'selected_at': self.selected_at.isoformat() if self.selected_at else None,
            'formatted_selected_date': self.selected_at.strftime('%B %d, %Y') if self.selected_at else (self.created_at.strftime('%B %d, %Y') if self.created_at else ''),
            'subtext': f"Topic {self.topic.case_code} · Selected {self.selected_at.strftime('%B %d, %Y') if self.selected_at else self.created_at.strftime('%B %d, %Y')}" if self.topic else f"Created {self.created_at.strftime('%b %d, %Y')}",
            'github_url': self.github_url,
            'live_url': self.live_url,
            'feedback': self.feedback,
            'reviewed_by': self.reviewed_by.full_name if self.reviewed_by else None,
            'reviewed_at': self.reviewed_at.isoformat() if self.reviewed_at else None,
            'created_at': self.created_at.isoformat() if self.created_at else None,
            'formatted_created_at': self.created_at.strftime('%b %d, %Y') if self.created_at else '',
            'updated_at': self.updated_at.isoformat() if self.updated_at else None,
            'files_count': self.files.count() if hasattr(self, 'files') else 0,
            'files': [f.to_dict() for f in self.files.all()[:10]] if hasattr(self, 'files') else [],
        }


class ProjectFile(models.Model):
    """
    Files uploaded for a project (Matching 'Upload a file' action in Screenshot 2).
    """
    project = models.ForeignKey(
        Project,
        related_name='files',
        on_delete=models.CASCADE
    )
    file = models.FileField(upload_to='project_files/%Y/%m/%d/')
    filename = models.CharField(_('File Name'), max_length=255)
    file_size = models.BigIntegerField(_('File Size (Bytes)'), default=0)
    file_type = models.CharField(_('MIME / Extension'), max_length=100, blank=True)
    uploaded_by = models.ForeignKey(
        User,
        related_name='uploaded_project_files',
        on_delete=models.SET_NULL,
        null=True,
        blank=True
    )
    uploaded_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        verbose_name = _('Project File')
        verbose_name_plural = _('Project Files')
        ordering = ['-uploaded_at']

    def __str__(self):
        return f"{self.filename} ({self.project.title})"

    def to_dict(self):
        file_url = ''
        try:
            file_url = self.file.url if self.file else ''
        except Exception:
            file_url = f"/media/{self.filename}"
        return {
            'id': self.id,
            'filename': self.filename,
            'file_size': self.file_size,
            'formatted_file_size': self._format_size(self.file_size),
            'file_type': self.file_type,
            'file_url': file_url,
            'uploaded_by': self.uploaded_by.full_name if self.uploaded_by else None,
            'uploaded_at': self.uploaded_at.isoformat() if self.uploaded_at else None,
        }

    @staticmethod
    def _format_size(num_bytes):
        if not num_bytes:
            return '0 B'
        for unit in ['B', 'KB', 'MB', 'GB']:
            if abs(num_bytes) < 1024.0:
                return f"{num_bytes:3.1f} {unit}".strip()
            num_bytes /= 1024.0
        return f"{num_bytes:.1f} TB"


class QueryStatus(models.TextChoices):
    OPEN = 'open', _('Open')
    IN_REVIEW = 'in_review', _('In review')
    ANSWERED = 'answered', _('Answered')
    CLOSED = 'closed', _('Closed')


class Query(models.Model):
    """
    Questions / Queries submitted by students to mentors, faculty, or project leads.
    """
    title = models.CharField(_('Title'), max_length=200)
    description = models.TextField(_('Description'))
    project = models.ForeignKey(
        Project,
        related_name='queries',
        on_delete=models.SET_NULL,
        null=True,
        blank=True
    )
    asked_by = models.ForeignKey(
        User,
        related_name='queries_asked',
        on_delete=models.CASCADE,
        verbose_name=_('Asked By')
    )
    status = models.CharField(
        max_length=30,
        choices=QueryStatus.choices,
        default=QueryStatus.OPEN,
        db_index=True
    )
    response = models.TextField(_('Response / Answer'), blank=True)
    responded_by = models.ForeignKey(
        User,
        related_name='query_responses',
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        verbose_name=_('Responded By')
    )
    responded_at = models.DateTimeField(null=True, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        verbose_name = _('Query')
        verbose_name_plural = _('Queries')
        ordering = ['-created_at']

    def __str__(self):
        return f"Query: {self.title} ({self.get_status_display()})"

    def to_dict(self, current_user=None):
        asked_by_initial = self.asked_by.full_name[0].upper() if self.asked_by.full_name else self.asked_by.email[0].upper()
        responded_by_data = None
        if self.responded_by:
            resp_initial = self.responded_by.full_name[0].upper() if self.responded_by.full_name else self.responded_by.email[0].upper()
            responded_by_data = {
                'id': self.responded_by.id,
                'full_name': self.responded_by.full_name,
                'email': self.responded_by.email,
                'department': getattr(self.responded_by, 'department', ''),
                'initial': resp_initial,
            }

        is_me = bool(current_user and current_user.id == self.asked_by_id)

        return {
            'id': self.id,
            'title': self.title,
            'description': self.description,
            'question': self.description,
            'project': {'id': self.project.id, 'title': self.project.title} if self.project else None,
            'asked_by': {
                'id': self.asked_by.id,
                'full_name': self.asked_by.full_name,
                'email': self.asked_by.email,
                'department': getattr(self.asked_by, 'department', ''),
                'initial': asked_by_initial,
            },
            'is_me': is_me,
            'status': self.status,
            'status_display': self.get_status_display(),
            'has_reply': bool(self.response),
            'has_answer': bool(self.response),
            'response': self.response,
            'answer': self.response,
            'responded_by': responded_by_data,
            'responded_by_name': self.responded_by.full_name if self.responded_by else None,
            'responded_at': self.responded_at.isoformat() if self.responded_at else None,
            'formatted_responded_at': self.responded_at.strftime('%b %d, %Y %I:%M %p') if self.responded_at else '',
            'created_at': self.created_at.isoformat() if self.created_at else None,
            'formatted_created_at': self.created_at.strftime('%b %d, %Y') if self.created_at else '',
            'formatted_time': self.created_at.strftime('%I:%M %p') if self.created_at else '',
            'updated_at': self.updated_at.isoformat() if self.updated_at else None,
        }


class Message(models.Model):
    """
    Direct / 1-on-1 Messages matching 'Workspace / Chat' (Private messages with other student accounts):
    - sender (User)
    - recipient (User)
    - subject (optional)
    - content (text message)
    - attachment (optional FileField for file uploads)
    - attachment_name, attachment_size, attachment_type
    - is_read (boolean)
    - read_at (datetime)
    - created_at
    """
    sender = models.ForeignKey(
        User,
        related_name='sent_messages',
        on_delete=models.CASCADE,
        verbose_name=_('Sender')
    )
    recipient = models.ForeignKey(
        User,
        related_name='received_messages',
        on_delete=models.CASCADE,
        verbose_name=_('Recipient')
    )
    subject = models.CharField(_('Subject'), max_length=200, blank=True)
    content = models.TextField(_('Content'), blank=True, default='')
    attachment = models.FileField(
        _('Attached File'),
        upload_to='direct_chat_files/%Y/%m/%d/',
        null=True,
        blank=True
    )
    attachment_name = models.CharField(_('Attachment Name'), max_length=255, blank=True, default='')
    attachment_size = models.BigIntegerField(_('Attachment Size (Bytes)'), default=0)
    attachment_type = models.CharField(_('Attachment MIME Type'), max_length=100, blank=True, default='')
    is_read = models.BooleanField(default=False, db_index=True)
    read_at = models.DateTimeField(null=True, blank=True)
    created_at = models.DateTimeField(auto_now_add=True, db_index=True)

    class Meta:
        verbose_name = _('Message')
        verbose_name_plural = _('Messages')
        ordering = ['created_at']

    def __str__(self):
        return f"Msg from {self.sender.full_name} to {self.recipient.full_name}: {self.subject or self.content[:30] or self.attachment_name}"

    def get_attachment_url(self):
        try:
            return self.attachment.url if self.attachment else ''
        except Exception:
            return f"/media/{self.attachment_name}" if self.attachment_name else ''

    def to_dict(self, current_user=None):
        sender_initial = self.sender.full_name[0].upper() if self.sender.full_name else self.sender.email[0].upper()
        recipient_initial = self.recipient.full_name[0].upper() if self.recipient.full_name else self.recipient.email[0].upper()
        is_me = bool(current_user and current_user.id == self.sender_id)
        has_file = bool(self.attachment or self.attachment_name)

        return {
            'id': self.id,
            'sender': {
                'id': self.sender.id,
                'full_name': self.sender.full_name,
                'email': self.sender.email,
                'department': getattr(self.sender, 'department', ''),
                'initial': sender_initial,
            },
            'recipient': {
                'id': self.recipient.id,
                'full_name': self.recipient.full_name,
                'email': self.recipient.email,
                'department': getattr(self.recipient, 'department', ''),
                'initial': recipient_initial,
            },
            'is_me': is_me,
            'subject': self.subject,
            'content': self.content,
            'has_attachment': has_file,
            'attachment': {
                'name': self.attachment_name,
                'url': self.get_attachment_url(),
                'size': self.attachment_size,
                'formatted_size': self._format_size(self.attachment_size) if self.attachment_size else '',
                'type': self.attachment_type,
            } if has_file else None,
            'is_read': self.is_read,
            'read_at': self.read_at.isoformat() if self.read_at else None,
            'created_at': self.created_at.isoformat() if self.created_at else None,
            'formatted_time': self.created_at.strftime('%I:%M %p') if self.created_at else '',
            'formatted_date': self.created_at.strftime('%b %d, %Y') if self.created_at else '',
        }

    @staticmethod
    def _format_size(num_bytes):
        if not num_bytes:
            return '0 B'
        for unit in ['B', 'KB', 'MB', 'GB']:
            if abs(num_bytes) < 1024.0:
                return f"{num_bytes:3.1f} {unit}".strip()
            num_bytes /= 1024.0
        return f"{num_bytes:.1f} TB"


class TeamMessage(models.Model):
    """
    Team / Group Chat Messages matching 'Workspace / Team chat' (Screenshot):
    - Team-scoped (visible only to accepted members of the selected team)
    - Content (text message)
    - Attachment (file upload: PDF, code, document, dataset, etc.)
    - Read tracking per member via read_by
    - Created at (timestamp)
    """
    team = models.ForeignKey(
        Team,
        related_name='messages',
        on_delete=models.CASCADE,
        verbose_name=_('Team')
    )
    sender = models.ForeignKey(
        User,
        related_name='team_messages_sent',
        on_delete=models.CASCADE,
        verbose_name=_('Sender')
    )
    content = models.TextField(_('Message Content'), blank=True)
    attachment = models.FileField(
        _('Attached File'),
        upload_to='team_chat_files/%Y/%m/%d/',
        null=True,
        blank=True
    )
    attachment_name = models.CharField(_('Attachment Name'), max_length=255, blank=True)
    attachment_size = models.BigIntegerField(_('Attachment Size (Bytes)'), default=0)
    attachment_type = models.CharField(_('Attachment MIME Type'), max_length=100, blank=True)
    read_by = models.ManyToManyField(
        User,
        related_name='read_team_messages',
        blank=True
    )
    created_at = models.DateTimeField(auto_now_add=True, db_index=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        verbose_name = _('Team Message')
        verbose_name_plural = _('Team Messages')
        ordering = ['created_at']

    def __str__(self):
        return f"[{self.team.name}] {self.sender.full_name}: {self.content[:30] if self.content else self.attachment_name}"

    def get_attachment_url(self):
        try:
            return self.attachment.url if self.attachment else ''
        except Exception:
            return f"/media/{self.attachment_name}" if self.attachment_name else ''

    def to_dict(self, current_user=None):
        sender_initial = self.sender.full_name[0].upper() if self.sender.full_name else self.sender.email[0].upper()
        is_me = bool(current_user and current_user.id == self.sender_id)
        is_read_by_me = (current_user in self.read_by.all()) if current_user else True
        has_file = bool(self.attachment or self.attachment_name)

        return {
            'id': self.id,
            'team_id': self.team_id,
            'team_name': self.team.name,
            'sender': {
                'id': self.sender.id,
                'full_name': self.sender.full_name,
                'email': self.sender.email,
                'department': self.sender.department,
                'initial': sender_initial,
            },
            'is_me': is_me,
            'content': self.content,
            'has_attachment': has_file,
            'attachment': {
                'name': self.attachment_name,
                'url': self.get_attachment_url(),
                'size': self.attachment_size,
                'formatted_size': self._format_size(self.attachment_size) if self.attachment_size else '',
                'type': self.attachment_type,
            } if has_file else None,
            'is_read': is_read_by_me,
            'created_at': self.created_at.isoformat() if self.created_at else None,
            'formatted_time': self.created_at.strftime('%I:%M %p') if self.created_at else '',
            'formatted_date': self.created_at.strftime('%b %d, %Y') if self.created_at else '',
        }

    @staticmethod
    def _format_size(num_bytes):
        if not num_bytes:
            return '0 B'
        for unit in ['B', 'KB', 'MB', 'GB']:
            if abs(num_bytes) < 1024.0:
                return f"{num_bytes:3.1f} {unit}".strip()
            num_bytes /= 1024.0
        return f"{num_bytes:.1f} TB"


class NotificationType(models.TextChoices):
    INFO = 'info', _('Information')
    SUBMISSION_STATUS = 'submission_status', _('Submission status')
    PROJECT_UPDATE = 'project_update', _('Project update')
    TEACHER_REPLY = 'teacher_reply', _('Teacher reply')
    PROJECT_APPROVED = 'project_approved', _('Project Approved')
    PROJECT_FEEDBACK = 'project_feedback', _('Project Feedback')
    PROJECT_REJECTED = 'project_rejected', _('Project Rejected')
    QUERY_ASKED = 'query_asked', _('Student Asked Question')
    QUERY_ANSWERED = 'query_answered', _('Teacher Q&A Answered')
    TEAM_INVITE = 'team_invite', _('Team Invite')
    TEAM_INVITE_ACCEPTED = 'team_invite_accepted', _('Team Invite Accepted')
    TEAM_INVITE_REJECTED = 'team_invite_rejected', _('Team Invite Declined')
    TEAM_LEADER_ASSIGNED = 'team_leader_assigned', _('Team Leader Assigned')
    TEAM_MESSAGE = 'team_message', _('Team Message')
    MESSAGE = 'message', _('New Message')


class Notification(models.Model):
    """
    In-app notifications for projects, teacher feedback, and Q&A responses.
    """
    recipient = models.ForeignKey(
        User,
        related_name='notifications',
        on_delete=models.CASCADE,
        verbose_name=_('Recipient')
    )
    title = models.CharField(_('Title'), max_length=200)
    message = models.TextField(_('Message'))
    notification_type = models.CharField(
        _('Type'),
        max_length=50,
        choices=NotificationType.choices,
        default=NotificationType.INFO,
        db_index=True
    )
    tag = models.CharField(_('Tag / Badge'), max_length=100, blank=True, default='')
    action_url = models.CharField(_('Action URL'), max_length=255, blank=True, default='')
    is_read = models.BooleanField(_('Is Read'), default=False, db_index=True)
    read_at = models.DateTimeField(_('Read At'), null=True, blank=True)
    created_at = models.DateTimeField(auto_now_add=True, db_index=True)

    class Meta:
        verbose_name = _('Notification')
        verbose_name_plural = _('Notifications')
        ordering = ['-created_at']

    def __str__(self):
        return f"Notification for {self.recipient.email}: {self.title}"

    def to_dict(self):
        now = timezone.now()
        relative_time = "Just now"
        if self.created_at:
            diff = now - self.created_at
            seconds = int(diff.total_seconds())
            if seconds < 0:
                relative_time = "Just now"
            elif seconds < 60:
                relative_time = "Just now"
            elif seconds < 3600:
                relative_time = f"{seconds // 60}m ago"
            elif seconds < 86400:
                if (now.date() - self.created_at.date()).days == 1:
                    relative_time = "Yesterday"
                elif seconds <= 4 * 3600:
                    relative_time = f"{max(1, seconds // 3600)}h ago"
                else:
                    relative_time = "Today"
            elif (now.date() - self.created_at.date()).days == 1:
                relative_time = "Yesterday"
            else:
                days = (now.date() - self.created_at.date()).days
                if days < 7:
                    relative_time = f"{days}d ago"
                else:
                    relative_time = self.created_at.strftime('%b %d')

        tag_val = self.tag or ("Node Theory" if (self.notification_type in (NotificationType.SUBMISSION_STATUS, 'submission_status') or 'review' in self.message.lower()) else "")

        return {
            'id': self.id,
            'title': self.title,
            'message': self.message,
            'description': self.message,
            'notification_type': self.notification_type,
            'notification_type_display': self.get_notification_type_display(),
            'tag': tag_val if tag_val else None,
            'badge': tag_val if tag_val else None,
            'time_ago': relative_time,
            'relative_time': relative_time,
            'formatted_time': self.created_at.strftime('%I:%M %p') if self.created_at else '',
            'formatted_date': self.created_at.strftime('%b %d, %Y') if self.created_at else '',
            'action_url': self.action_url,
            'is_read': self.is_read,
            'read_at': self.read_at.isoformat() if self.read_at else None,
            'created_at': self.created_at.isoformat() if self.created_at else None,
        }
