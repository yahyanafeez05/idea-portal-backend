from django.urls import path
from core import views

urlpatterns = [
    # -------------------------------------------------------------------------
    # Authentication & Accounts
    # -------------------------------------------------------------------------
    path('auth/register/', views.register_view, name='auth-register'),
    path('auth/login/', views.login_view, name='auth-login'),
    path('auth/logout/', views.logout_view, name='auth-logout'),
    path('auth/me/', views.me_view, name='auth-me'),
    path('auth/account-types/', views.account_types_view, name='auth-account-types'),
    path('auth/check-email/', views.check_email_view, name='auth-check-email'),
    path('auth/csrf/', views.csrf_token_view, name='auth-csrf'),

    # Direct short routes for convenience (e.g. /api/register/, /api/login/)
    path('register/', views.register_view, name='register'),
    path('login/', views.login_view, name='login'),
    path('logout/', views.logout_view, name='logout'),
    path('me/', views.me_view, name='me'),
    path('account-types/', views.account_types_view, name='account-types'),
    path('check-email/', views.check_email_view, name='check-email'),
    path('csrf/', views.csrf_token_view, name='csrf'),

    # -------------------------------------------------------------------------
    # Student Workspace Dashboard (Matches Student Dashboard Screenshot)
    # -------------------------------------------------------------------------
    path('dashboard/', views.dashboard_view, name='dashboard'),
    path('workspace/dashboard/', views.dashboard_view, name='workspace-dashboard'),
    path('workspace/', views.dashboard_view, name='workspace'),

    # -------------------------------------------------------------------------
    # Notifications API (Top Navbar Bell Icon)
    # -------------------------------------------------------------------------
    path('notifications/', views.notification_list_view, name='notification-list-create'),
    path('notifications/mark-all-read/', views.notification_mark_all_read_view, name='notification-mark-all-read'),
    path('notifications/<int:pk>/read/', views.notification_detail_view, name='notification-mark-read'),
    path('notifications/<int:pk>/', views.notification_detail_view, name='notification-detail'),

    # -------------------------------------------------------------------------
    # Projects API (Active projects, Approved, Awaiting feedback, Recent projects)
    # -------------------------------------------------------------------------
    path('projects/', views.project_list_create_view, name='project-list-create'),
    path('my-projects/', views.project_list_create_view, name='my-projects'),
    path('team-projects/', views.project_list_create_view, name='team-projects'),
    path('workspace/projects/', views.project_list_create_view, name='workspace-projects'),
    path('workspace/my-projects/', views.project_list_create_view, name='workspace-my-projects'),
    path('projects/<int:pk>/', views.project_detail_view, name='project-detail'),
    path('projects/<int:pk>/submit/', views.project_submit_review_view, name='project-submit-review'),
    path('projects/<int:pk>/review/', views.project_review_view, name='project-review'),
    path('projects/<int:pk>/files/', views.project_file_upload_view, name='project-files'),
    path('projects/<int:pk>/files/<int:file_id>/', views.project_file_upload_view, name='project-file-delete'),
    path('projects/<int:pk>/upload/', views.project_file_upload_view, name='project-upload-file'),

    # -------------------------------------------------------------------------
    # Topics & Dataset API (Workspace / Data Screen & Selection Rules)
    # -------------------------------------------------------------------------
    path('topics/', views.topic_list_view, name='topic-list'),
    path('topics/upload/', views.topic_upload_view, name='topic-upload'),
    path('topics/select/', views.topic_select_view, name='topic-select'),
    path('topics/<str:pk_or_case>/select/', views.topic_select_view, name='topic-select-case'),
    path('topics/release/', views.topic_release_view, name='topic-release'),
    path('topics/<str:pk_or_case>/release/', views.topic_release_view, name='topic-release-case'),
    path('topics/<str:pk_or_case>/unselect/', views.topic_release_view, name='topic-unselect-case'),

    # Workspace / Data Aliases
    path('data/', views.topic_list_view, name='data-topics'),
    path('data/topics/', views.topic_list_view, name='data-topics-alias'),
    path('data/upload/', views.topic_upload_view, name='data-upload'),
    path('workspace/data/', views.topic_list_view, name='workspace-data'),

    # -------------------------------------------------------------------------
    # Queries & Teacher Q&A API (Workspace / Queries - Questions & Answers)
    # -------------------------------------------------------------------------
    path('workspace/queries/', views.queries_workspace_view, name='workspace-queries'),
    path('workspace/queries/ask/', views.query_list_create_view, name='workspace-queries-ask'),
    path('workspace/teacher-qa/', views.queries_workspace_view, name='workspace-teacher-qa'),

    path('teacher-qa/', views.teacher_qa_list_create_view, name='teacher-qa-list-create'),
    path('teacher-qa/<int:pk>/', views.teacher_qa_detail_view, name='teacher-qa-detail'),
    path('teacher-qa/<int:pk>/reply/', views.teacher_qa_reply_view, name='teacher-qa-reply'),

    path('queries/', views.query_list_create_view, name='query-list-create'),
    path('queries/<int:pk>/', views.query_detail_view, name='query-detail'),
    path('queries/<int:pk>/reply/', views.query_reply_view, name='query-reply'),

    # -------------------------------------------------------------------------
    # Teams & Team Invitations API (Matches Workspace / My team & Create Team Modal)
    # -------------------------------------------------------------------------
    path('teams/my-team/', views.my_team_view, name='team-my-team'),
    path('workspace/my-team/', views.my_team_view, name='workspace-my-team'),
    path('teams/my-team/upload-project/', views.team_upload_project_view, name='team-my-team-upload-project'),
    path('teams/my-team/candidates/', views.team_candidates_view, name='team-my-team-candidates'),
    path('teams/', views.team_list_create_view, name='team-list-create'),
    path('teams/<int:pk>/', views.team_detail_view, name='team-detail'),
    path('teams/<int:pk>/upload-project/', views.team_upload_project_view, name='team-upload-project'),
    path('teams/<int:pk>/candidates/', views.team_candidates_view, name='team-candidates'),
    path('teams/<int:pk>/assign-leader/', views.team_assign_leader_view, name='team-assign-leader'),
    path('teams/<int:pk>/members/', views.team_member_manage_view, name='team-members'),
    path('teams/<int:pk>/members/<int:user_id>/', views.team_member_manage_view, name='team-member-remove'),
    path('teams/<int:pk>/invitations/', views.team_invitation_create_view, name='team-invitations'),
    path('teams/<int:pk>/invite/', views.team_invitation_create_view, name='team-invite'),
    path('teams/<int:team_id>/invitations/<int:pk>/accept/', views.team_invitation_respond_view, {'action': 'accept'}, name='team-invitation-accept'),
    path('teams/<int:team_id>/invitations/<int:pk>/reject/', views.team_invitation_respond_view, {'action': 'reject'}, name='team-invitation-reject'),

    # Direct Invitation Actions
    path('invitations/', views.invitation_list_view, name='invitation-list'),
    path('invitations/pending/', views.invitation_list_view, name='invitation-list-pending'),
    path('invitations/<int:pk>/accept/', views.team_invitation_respond_view, {'action': 'accept'}, name='invitation-accept'),
    path('invitations/<int:pk>/reject/', views.team_invitation_respond_view, {'action': 'reject'}, name='invitation-reject'),

    # -------------------------------------------------------------------------
    # Personal 1-on-1 Chat & Messages API (Workspace / Chat - Private Messages)
    # -------------------------------------------------------------------------
    path('chat/', views.chat_workspace_view, name='chat-workspace'),
    path('chat/contacts/', views.direct_chat_contacts_view, name='chat-contacts'),
    path('chat/read/', views.direct_chat_mark_read_view, name='chat-mark-read'),
    path('chat/<str:contact_identifier>/', views.chat_workspace_view, name='chat-direct-user'),
    path('workspace/chat/', views.chat_workspace_view, name='workspace-chat'),
    path('workspace/chat/read/', views.direct_chat_mark_read_view, name='workspace-chat-read'),

    path('messages/', views.message_list_create_view, name='message-list-create'),
    path('messages/contacts/', views.direct_chat_contacts_view, name='message-contacts'),
    path('messages/<int:pk>/', views.message_detail_view, name='message-detail'),
    path('messages/<int:pk>/read/', views.message_detail_view, name='message-mark-read'),
    path('messages/direct/<str:contact_identifier>/', views.chat_workspace_view, name='message-direct-user'),
    path('messages/direct/<str:contact_identifier>/read/', views.direct_chat_mark_read_view, name='message-direct-mark-read'),

    # -------------------------------------------------------------------------
    # Team Chat & Group Messaging API (Workspace / Team chat)
    # -------------------------------------------------------------------------
    path('teams/chat/', views.team_chat_view, name='team-chat'),
    path('workspace/team-chat/', views.team_chat_view, name='workspace-team-chat'),
    path('workspace/chat/team/', views.team_chat_view, name='workspace-chat-team'),
    path('teams/<int:pk>/chat/', views.team_message_list_create_view, name='team-chat-messages'),
    path('teams/<int:pk>/messages/', views.team_message_list_create_view, name='team-messages'),
    path('teams/<int:pk>/chat/read/', views.team_chat_mark_read_view, name='team-chat-read'),
    path('teams/<int:pk>/messages/read/', views.team_chat_mark_read_view, name='team-messages-read'),
    path('teams/<int:team_id>/messages/<int:pk>/', views.team_message_detail_view, name='team-message-detail'),
]
