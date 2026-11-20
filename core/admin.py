from django.contrib import admin
from django.contrib.auth.admin import UserAdmin as BaseUserAdmin
from core.models import User, AuthToken, Project, Team, TeamMember, Query, Message, Notification, TeacherAccessCode


@admin.register(User)
class UserAdmin(BaseUserAdmin):
    ordering = ['email']
    list_display = ['email', 'full_name', 'account_type', 'department', 'section', 'is_active', 'is_staff', 'date_joined']
    list_filter = ['account_type', 'department', 'section', 'is_active', 'is_staff', 'date_joined']
    search_fields = ['email', 'full_name', 'department', 'section']

    fieldsets = (
        (None, {'fields': ('email', 'password')}),
        ('Personal Info', {'fields': ('full_name', 'account_type', 'department', 'section')}),
        ('Permissions', {'fields': ('is_active', 'is_staff', 'is_superuser', 'groups', 'user_permissions')}),
        ('Important dates', {'fields': ('last_login', 'date_joined')}),
    )

    add_fieldsets = (
        (None, {
            'classes': ('wide',),
            'fields': ('email', 'full_name', 'account_type', 'department', 'section', 'password', 'is_active', 'is_staff'),
        }),
    )


@admin.register(AuthToken)
class AuthTokenAdmin(admin.ModelAdmin):
    list_display = ['key', 'user', 'is_active', 'created_at', 'last_used_at']
    list_filter = ['is_active', 'created_at']
    search_fields = ['key', 'user__email', 'user__full_name']
    readonly_fields = ['key', 'created_at', 'last_used_at']


class TeamMemberInline(admin.TabularInline):
    model = TeamMember
    extra = 1


@admin.register(Team)
class TeamAdmin(admin.ModelAdmin):
    list_display = ['name', 'created_by', 'department', 'created_at']
    list_filter = ['department', 'created_at']
    search_fields = ['name', 'description', 'created_by__email', 'created_by__full_name']
    inlines = [TeamMemberInline]


@admin.register(Project)
class ProjectAdmin(admin.ModelAdmin):
    list_display = ['title', 'owner', 'status', 'department', 'team', 'reviewed_by', 'created_at']
    list_filter = ['status', 'department', 'created_at']
    search_fields = ['title', 'description', 'owner__email', 'owner__full_name', 'department']
    readonly_fields = ['created_at', 'updated_at']


@admin.register(Query)
class QueryAdmin(admin.ModelAdmin):
    list_display = ['title', 'asked_by', 'status', 'project', 'responded_by', 'created_at']
    list_filter = ['status', 'created_at']
    search_fields = ['title', 'description', 'asked_by__email', 'asked_by__full_name']


@admin.register(Message)
class MessageAdmin(admin.ModelAdmin):
    list_display = ['sender', 'recipient', 'subject', 'is_read', 'created_at']
    list_filter = ['is_read', 'created_at']
    search_fields = ['subject', 'content', 'sender__email', 'recipient__email']


@admin.register(Notification)
class NotificationAdmin(admin.ModelAdmin):
    list_display = ['title', 'recipient', 'notification_type', 'is_read', 'created_at']
    list_filter = ['notification_type', 'is_read', 'created_at']
    search_fields = ['title', 'message', 'recipient__email', 'recipient__full_name']
    readonly_fields = ['created_at']


@admin.register(TeacherAccessCode)
class TeacherAccessCodeAdmin(admin.ModelAdmin):
    list_display = ['code', 'description', 'is_active', 'created_at']
    list_filter = ['is_active', 'created_at']
    search_fields = ['code', 'description']
