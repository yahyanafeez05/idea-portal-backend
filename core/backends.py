from django.contrib.auth.backends import ModelBackend
from django.contrib.auth import get_user_model

User = get_user_model()


class EmailAuthBackend(ModelBackend):
    """
    Authenticate against settings.AUTH_USER_MODEL using case-insensitive email.
    Provides constant-time failure handling to prevent timing attacks.
    """

    def authenticate(self, request, username=None, password=None, email=None, **kwargs):
        email_to_check = email or username or kwargs.get('email')
        if not email_to_check or not password:
            return None

        clean_email = str(email_to_check).strip().lower()

        try:
            user = User.objects.get(email__iexact=clean_email)
        except User.DoesNotExist:
            # Run the default password hasher once to reduce the timing
            # difference between an existing and a non-existing user.
            User().set_password(password)
            return None
        except User.MultipleObjectsReturned:
            # Should not happen because email is unique, but safety first
            return None

        if user.check_password(password) and self.user_can_authenticate(user):
            return user

        return None
