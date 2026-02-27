from django.db import models
from django.contrib.auth.models import (
    AbstractBaseUser,
    PermissionsMixin,
    BaseUserManager,
    Group, 
    Permission,
)
from django.utils import timezone
import uuid
from fernet_fields import EncryptedTextField


class AuditQuerySet(models.QuerySet):
    def delete(self) -> tuple[int, dict[str, int]]:
        count = super().update(deleted_at=timezone.now())
        return count, {self.model.__name__: count}

    def hard_delete(self):
        return super().delete()

    def alive(self):
        return self.filter(deleted_at__isnull=True)

    def dead(self):
        return self.filter(deleted_at__isnull=False)


class AuditManager(models.Manager.from_queryset(AuditQuerySet)):
    def get_queryset(self):
        return super().get_queryset().filter(deleted_at__isnull=True)
    
    def dead(self):
        return self.get_queryset().filter(deleted_at__isnull=False)


class AuditModel(models.Model):
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    deleted_at = models.DateTimeField(null=True, blank=True)

    objects = AuditManager()
    all_objects = models.Manager()

    class Meta:
        abstract = True

    def delete(self, using=None, keep_parents=False) -> tuple[int, dict[str, int]]:
        if self.deleted_at is not None:
            return (0, {self.__class__.__name__: 0})

        self.deleted_at = timezone.now()
        self.save(update_fields=["deleted_at"])
        return (1, {self.__class__.__name__: 1})

    def hard_delete(self, using=None, keep_parents=False):
        return super().delete(using=using, keep_parents=keep_parents)
    
    def restore(self):
        self.deleted_at = None
        self.save(update_fields=["deleted_at"])
    

class AuthUserManager(BaseUserManager, AuditManager):

    def create_user(self, email, password=None, **extra_fields):
        if not email:
            raise ValueError("Email is required")

        email = self.normalize_email(email)
        user = self.model(email=email, **extra_fields)

        if password:
            user.set_password(password)
        else:
            user.set_unusable_password()

        user.save(using=self._db)
        return user

    def create_superuser(self, email, password=None, **extra_fields):
        extra_fields.setdefault("is_superuser", True)
        extra_fields.setdefault("is_staff", True)
        extra_fields.setdefault("is_active", True)

        if extra_fields.get("is_superuser") is not True:
            raise ValueError("Superuser must have is_superuser=True.")

        return self.create_user(email, password, **extra_fields)
    

class AuthUser(AbstractBaseUser, PermissionsMixin, AuditModel):
    id = models.UUIDField(
        primary_key=True,
        default=uuid.uuid4,
        editable=False,
    )
    email = models.EmailField(unique=True)
    username = models.CharField(max_length=150, unique=True, null=True, blank=True)
    is_email_verified = models.BooleanField(default=False)
    is_active = models.BooleanField(default=True)
    is_staff = models.BooleanField(default=False)
    
    objects = AuthUserManager()

    USERNAME_FIELD = "email"
    REQUIRED_FIELDS = []

    def delete(self, using=None, keep_parents=False) -> tuple[int, dict[str, int]]:
        self.deleted_at = timezone.now()
        self.is_active = False
        self.save(update_fields=["deleted_at", "is_active"])

        return 1, {self.__class__.__name__: 1}
    
    def restore(self):
        self.deleted_at = None
        self.is_active = True
        self.save(update_fields=["deleted_at", "is_active"])
    
    def __str__(self):
        return self.email
    
    groups = models.ManyToManyField(
        Group,
        related_name="authuser_set",
        blank=True,
        help_text="The groups this user belongs to.",
        verbose_name="groups",
    )

    user_permissions = models.ManyToManyField(
        Permission,
        related_name="authuser_set",
        blank=True,
        help_text="Specific permissions for this user.",
        verbose_name="user permissions",
    )

    failed_login_attempts = models.PositiveIntegerField(default=0)
    last_failed_login = models.DateTimeField(null=True, blank=True)
    is_locked = models.BooleanField(default=False)
    
    class Meta(AuditModel.Meta):
        db_table = "auth_users"
        indexes = [
        ]


class UserProfile(AuditModel):
    user = models.OneToOneField(
        "authentication.AuthUser", 
        on_delete=models.CASCADE, 
        related_name="profile"
    )

    first_name = models.CharField(max_length=50, blank=True)
    last_name = models.CharField(max_length=50, blank=True, null=True)
    phone_number = models.CharField(max_length=20, blank=True)
    is_phone_verified = models.BooleanField(default=False)
    date_of_birth = models.DateField(null=True, blank=True)
    profile_image = models.CharField(max_length=500, null=True, blank=True)
    organization = models.ForeignKey(
        "executive.Organization",
        on_delete=models.PROTECT,
        db_index=True,
    )

    def __str__(self):
        return f"{self.user.email} - {self.first_name} {self.last_name}"
    
    class Meta(AuditModel.Meta):
        db_table = "user_profiles"
        indexes = [
            models.Index(fields=["organization", "user"]),
        ]


class SocialAccount(AuditModel):
    PROVIDER_CHOICES = (
        ("google", "Google"),
        ("microsoft", "Microsoft"),
        ("apple", "Apple"),
    )

    id = models.UUIDField(
        primary_key=True,
        default=uuid.uuid4,
    )

    user = models.ForeignKey(
        "authentication.AuthUser",
        on_delete=models.CASCADE,
        related_name="social_accounts"
    )

    provider = models.CharField(max_length=20, choices=PROVIDER_CHOICES)

    # Unique ID from provider
    provider_user_id = models.CharField(max_length=255)

    access_token = EncryptedTextField(null=True, blank=True)
    refresh_token = EncryptedTextField(null=True, blank=True)
    id_token = EncryptedTextField(null=True, blank=True)

    token_expires_at = models.DateTimeField(null=True, blank=True)

    class Meta(AuditModel.Meta):
        db_table = "social_accounts"
        unique_together = ("provider", "provider_user_id")
        indexes = [
            models.Index(fields=["provider", "provider_user_id"]),
            models.Index(fields=["user", "provider"]),
        ]

    def __str__(self):
        return f"{self.provider} - {self.user.email}"


class LoginLog(models.Model):
    email = models.EmailField()
    login_attempt_time = models.DateTimeField(auto_now_add=True)
    login_status = models.BooleanField()
    login_ip = models.GenericIPAddressField(null=True, blank=True)
    user_agent = models.TextField(null=True, blank=True)
    failure_reason = models.CharField(max_length=255, null=True, blank=True)
    is_mfa_authenticated = models.BooleanField(default=False)

    class Meta(AuditModel.Meta):
        db_table = "login_logs"
        verbose_name = "Login Log"
        verbose_name_plural = "Login Logs"
        ordering = ["-login_attempt_time"]
        indexes = [
            models.Index(fields=["email", "login_attempt_time"]),
        ]


class UserPasswordHistory(models.Model):
    user = models.ForeignKey(
        "authentication.AuthUser",
        on_delete=models.DO_NOTHING,
        db_column="user_id"
    )
    password_hash = models.TextField()
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        db_table = "user_password_history"


class MFADevice(AuditModel):
    user = models.ForeignKey(AuthUser, on_delete=models.CASCADE)
    device_name = models.CharField(max_length=100)
    is_active = models.BooleanField(default=True)
    last_used_at = models.DateTimeField(null=True, blank=True)
    is_primary = models.BooleanField(default=False)
    
    class Meta(AuditModel.Meta):
        unique_together = ("user", "device_name")