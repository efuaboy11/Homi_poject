from django.contrib.auth.backends import ModelBackend
from django.db.models import Q
from .models import Users

class EmailOrPhoneBackend(ModelBackend):
    def authenticate(self, request, username=None, password=None, **kwargs):
        try:
            user = Users.objects.get(
                Q(email=username) | Q(phone_number=username)
            )
        except Users.DoesNotExist:
            return None

        if user.check_password(password):
            return user
        return None