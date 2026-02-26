from django.db import models
from authentication.models import AuditModel
from decimal import Decimal
import uuid


class Organization(AuditModel):
    id = models.UUIDField(primary_key=True, default=uuid.uuid4)
    organization_name = models.CharField(max_length=255, unique=True)
    support_email = models.EmailField(null=True, blank=True)
    support_phone = models.CharField(max_length=20, null=True, blank=True)

    subscription_plan = models.ForeignKey(
        "finance.SubscriptionPlan",
        on_delete=models.PROTECT,
        null=True,
        blank=True,
    )

    subscription_status = models.ForeignKey(
        "finance.SubscriptionStatus",
        on_delete=models.DO_NOTHING,
        db_column="subscription_status_id",
        db_index=True,
    )

    subscription_starts_at = models.DateTimeField()
    subscription_ends_at = models.DateTimeField()

    auto_renew = models.BooleanField(default=True)

    currency = models.CharField(max_length=3, default="INR")

    account_balance = models.DecimalField(
        max_digits=14,
        decimal_places=2,
        default=Decimal("0.00"),
    )
    frozen_amount = models.DecimalField(
        max_digits=14,
        decimal_places=2,
        default=Decimal("0.00"),
    )

    class Meta(AuditModel.Meta):
        db_table = "organizations"


class Role(AuditModel):
    id = models.SmallAutoField(primary_key=True)
    role_name = models.CharField(max_length=50, unique=True)
    organization = models.ForeignKey(
        "executive.Organization",
        on_delete=models.CASCADE,
        db_index=True,
    )

    class Meta(AuditModel.Meta):
        db_table = "roles"
        unique_together = ("role_name", "organization")


class Permission(AuditModel):
    code = models.CharField(max_length=100, primary_key=True)

    description = models.TextField(blank=True)

    class Meta(AuditModel.Meta):
        db_table = "permissions"

    def __str__(self):
        return self.code


class RolePermissionPerOrganization(AuditModel):
    id = models.UUIDField(primary_key=True, default=uuid.uuid4)

    role = models.ForeignKey(
        "executive.Role", on_delete=models.CASCADE, related_name="role_permissions"
    )

    permission = models.ForeignKey(
        "executive.Permission",
        on_delete=models.CASCADE,
        related_name="permission_roles",
    )

    organization = models.ForeignKey(
        "executive.Organization",
        on_delete=models.CASCADE,
        db_index=True,
    )

    class Meta(AuditModel.Meta):
        db_table = "role_permission_per_organization"
        unique_together = ("role", "organization")
        indexes = [
            models.Index(fields=["organization", "role"]),
        ]


class Invitation(AuditModel):
    id = models.UUIDField(primary_key=True, default=uuid.uuid4)

    email = models.EmailField(db_index=True)

    organization = models.ForeignKey(
        "executive.Organization",
        on_delete=models.CASCADE,
        db_index=True,
    )

    role = models.ForeignKey(
        "executive.Role",
        on_delete=models.PROTECT,
    )

    token = models.CharField(max_length=255, unique=True)

    expires_at = models.DateTimeField()

    is_accepted = models.BooleanField(default=False)
    accepted_at = models.DateTimeField(null=True, blank=True)

    invited_by = models.ForeignKey(
        "executive.OrganizationUser",
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name="sent_invitations",
    )

    class Meta(AuditModel.Meta):
        db_table = "invitations"
        unique_together = ("email", "organization")
        indexes = [
            models.Index(fields=["organization", "email"]),
        ]

    def __str__(self):
        return f"{self.email} - {self.organization.organization_name}"


class OrganizationUserStatus(models.Model):
    id = models.SmallAutoField(primary_key=True)
    status_name = models.CharField(max_length=50, unique=True)

    class Meta:
        db_table = "organization_user_status_lookup"

    def __str__(self):
        return self.status_name


class OrganizationUser(AuditModel):
    id = models.UUIDField(
        primary_key=True,
        default=uuid.uuid4,
    )

    user_profile = models.OneToOneField(
        "authentication.UserProfile",
        on_delete=models.CASCADE,
        related_name="organization_user",
    )

    organization = models.ForeignKey(
        "executive.Organization",
        on_delete=models.CASCADE,
        db_column="organization_id",
    )

    organization_user_status = models.ForeignKey(
        "executive.OrganizationUserStatus",
        on_delete=models.DO_NOTHING,
        db_column="organization_user_status_id",
    )

    role = models.ForeignKey(
        "executive.Role",
        on_delete=models.PROTECT,
        db_column="role_id",
    )

    manager = models.ForeignKey(
        "self",
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name="subordinates",
    )

    account_balance = models.DecimalField(
        max_digits=14,
        decimal_places=2,
        default=Decimal("0.00"),
    )
    freezed_amount = models.DecimalField(
        max_digits=14,
        decimal_places=2,
        default=Decimal("0.00"),
        null=True,
        blank=True,
    )

    individual_monthly_limit = models.DecimalField(
        max_digits=14,
        decimal_places=2,
        default=Decimal("0.00"),
    )
    second_stage_approval_limit = models.DecimalField(
        max_digits=14,
        decimal_places=2,
        default=Decimal(
            "0.00",
        ),
    )

    @property
    def joined_at(self):
        return self.created_at

    # we need to rename the field of created_at to joined_at, only for this model how?
    class Meta(AuditModel.Meta):
        db_table = "organization_users"
        indexes = [
            models.Index(fields=["organization", "role"]),
        ]


class Team(AuditModel):
    id = models.UUIDField(
        primary_key=True,
        default=uuid.uuid4,
    )

    organization = models.ForeignKey(
        "executive.Organization",
        on_delete=models.CASCADE,
        db_column="organization_id",
        db_index=True,
    )

    team_name = models.CharField(max_length=100)

    manager = models.ForeignKey(
        "executive.OrganizationUser",
        on_delete=models.PROTECT,
        db_column="manager_teams",
    )

    account_balance = models.DecimalField(
        max_digits=14,
        decimal_places=2,
        default=Decimal("0.00"),
    )
    monthly_limit = models.DecimalField(
        max_digits=14,
        decimal_places=2,
        default=Decimal("0.00"),
    )

    currency = models.CharField(max_length=3, default="INR")

    class Meta(AuditModel.Meta):
        db_table = "teams"
        unique_together = ("organization", "team_name")


class TeamAssignment(AuditModel):
    id = models.UUIDField(
        primary_key=True,
        default=uuid.uuid4,
    )

    team = models.ForeignKey(
        "executive.Team",
        on_delete=models.CASCADE,
        db_column="team_id",
    )

    organization_user = models.ForeignKey(
        "executive.OrganizationUser",
        on_delete=models.CASCADE,
    )

    account_balance = models.DecimalField(
        max_digits=14,
        decimal_places=2,
        default=Decimal("0.00"),
    )
    monthly_limit = models.DecimalField(
        max_digits=14,
        decimal_places=2,
        default=Decimal("0.00"),
    )

    currency = models.CharField(
        max_length=3,
        default="INR",
    )

    @property
    def joined_at(self):
        return self.created_at

    class Meta(AuditModel.Meta):
        db_table = "team_assignments"
        unique_together = ("team", "organization_user")

