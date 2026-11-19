from django.urls import path
from core import views

urlpatterns = [
    # Screen 1: Start with a fresh account (Create Account)
    path('register/', views.register_view, name='register'),
    
    # Screen 2: Welcome back (Login)
    path('login/', views.login_view, name='login'),
    
    # Session / Token Logout
    path('logout/', views.logout_view, name='logout'),
    
    # Authenticated User Profile
    path('me/', views.me_view, name='me'),
    
    # Account Types Dropdown Options
    path('account-types/', views.account_types_view, name='account-types'),
    
    # Real-time Duplicate Account Restriction Pre-check
    path('check-email/', views.check_email_view, name='check-email'),
    
    # CSRF Token
    path('csrf/', views.csrf_token_view, name='csrf'),
]
