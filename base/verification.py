
from django.contrib.auth.backends import ModelBackend
from .models import Users


def authenticate(email=None, password=None, **kwargs):
    try:
        user = Users.objects.get(email=email)
        if user.check_password(password):
            return user
    except Users.DoesNotExist:
        return None
