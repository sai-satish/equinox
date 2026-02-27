from django.contrib.auth.signals import user_logged_in, user_login_failed
from django.dispatch import receiver
from authentication.models import LoginLog
from utils.auth_utils import get_client_ip

@receiver(user_logged_in)
def log_success_login(sender, request, user, **kwargs):
    LoginLog.objects.create(
        email=user.email,
        login_status=True,
        login_ip=get_client_ip(request) if request else None,
        user_agent=request.META.get("HTTP_USER_AGENT") if request else None,
        failure_reason=None,
        is_mfa_authenticated=getattr(user, "is_mfa_verified", False),
    )

@receiver(user_login_failed)
def log_failed_login(sender, credentials, request, **kwargs):
    LoginLog.objects.create(
        email=credentials.get("email", "unknown"),
        login_status=False,
        login_ip=get_client_ip(request) if request else None,
        user_agent=request.META.get("HTTP_USER_AGENT") if request else None,
        failure_reason="Invalid credentials",
        is_mfa_authenticated=False,
    )