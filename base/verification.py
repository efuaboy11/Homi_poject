import logging
from django.contrib.auth.backends import ModelBackend
from django.db.models import Q
from .models import Users

logger = logging.getLogger(__name__)  # create logger

class EmailOrPhoneBackend(ModelBackend):
    def authenticate(self, request, username=None, password=None, **kwargs):
        logger.info(f"🔥 BACKEND CALLED: {username}")
        
        try:
            user = Users.objects.get(Q(email=username) | Q(phone_number=username))
            logger.info(f"✅ USER FOUND: {user}")
        except Users.DoesNotExist:
            logger.warning(f"❌ USER NOT FOUND: {username}")
            return None

        if user.check_password(password):
            logger.info(f"✅ PASSWORD OK: {username}")
            return user

        logger.warning(f"❌ WRONG PASSWORD: {username}")
        return None