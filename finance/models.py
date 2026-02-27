from django.db import models
from authentication.models import AuditModel
import uuid

# Create your models here.

class SubscriptionStatus(models.Model):
    id = models.SmallAutoField(primary_key=True)
    status_name = models.CharField(max_length=50, unique=True)

    class Meta:
        db_table = "subscription_status_lookup"
        verbose_name = "Subscription Status"
        verbose_name_plural = "Subscription Status"

    def __str__(self):
        return self.status_name


class SubscriptionPlan(AuditModel):
    BILLING_CHOICES = (
        ("monthly", "Monthly"),
        ("yearly", "Yearly"),
    )

    id = models.UUIDField(primary_key=True, default=uuid.uuid4)
    name = models.CharField(max_length=100, unique=True)

    max_users = models.PositiveIntegerField()
    max_teams = models.PositiveIntegerField()
    max_monthly_budget = models.DecimalField(max_digits=14, decimal_places=2)
    features = models.JSONField(default=dict, blank=True, null=True)

    price = models.DecimalField(max_digits=10, decimal_places=2)
    billing_cycle = models.CharField(max_length=20, choices=BILLING_CHOICES)

    currency = models.CharField(max_length=3, default="INR")

    class Meta(AuditModel.Meta):
        db_table = "subscription_plans"


class Budget(AuditModel):
    id = models.UUIDField(
        primary_key=True,
        default=uuid.uuid4,
    )

    organization = models.ForeignKey(
        "executive.Organization",
        on_delete=models.CASCADE,
    )

    allocated_to_user = models.ForeignKey(
        "executive.OrganizationUser",
        on_delete=models.DO_NOTHING,
        null=True,
        blank=True,
    )

    allocated_to_team = models.ForeignKey(
        "executive.Team",
        on_delete=models.DO_NOTHING,
        null=True,
        blank=True,
    )

    amount = models.DecimalField(max_digits=14, decimal_places=2)
    remaining_amount = models.DecimalField(max_digits=14, decimal_places=2)
    currency = models.CharField(max_length=3, default="INR")

    period_start = models.DateField()
    period_end = models.DateField()

    is_recurring = models.BooleanField(default=False)

    recurring_frequency = models.CharField(
        max_length=20,
        choices=(
            ("monthly", "Monthly"),
            ("quarterly", "Quarterly"),
        ),
        null=True,
        blank=True,
    )

    next_recurring_date = models.DateField(
        null=True,
        blank=True,
    )

    forecast_for_next_month = models.DecimalField(
        max_digits=14, decimal_places=2, null=True, blank=True
    )

    class Meta(AuditModel.Meta):
        db_table = "budgets"


class ExpenseLog(AuditModel):
    id = models.UUIDField(
        primary_key=True,
        default=uuid.uuid4,
    )

    organization = models.ForeignKey(
        "executive.Organization",
        on_delete=models.PROTECT,
    )

    organization_user = models.ForeignKey(
        "executive.OrganizationUser",
        on_delete=models.PROTECT,
        db_column="organization_user_id",
        null=True,
        blank=True,
    )

    team = models.ForeignKey(
        "executive.Team",
        on_delete=models.PROTECT,
        db_column="team_id",
        null=True,
        blank=True,
    )

    amount_used = models.DecimalField(max_digits=14, decimal_places=2)
    remaining_balance = models.DecimalField(max_digits=14, decimal_places=2)
    currency = models.CharField(max_length=3, default="INR")

    category = models.ForeignKey(
        "finance.Category",
        on_delete=models.PROTECT,
    )

    description = models.TextField(null=True, blank=True)

    class Meta(AuditModel.Meta):
        db_table = "expense_logs"
        indexes = [
            models.Index(fields=["organization", "created_at"]),
            models.Index(fields=["category"]),
            models.Index(fields=["organization", "category"]),
        ]


class FinanceAuditLog(AuditModel):
    id = models.UUIDField(
        primary_key=True,
        default=uuid.uuid4,
    )
    organization = models.ForeignKey(
        "executive.Organization",
        on_delete=models.PROTECT,
    )

    from_entity_type = models.CharField(max_length=50)
    from_entity_id = models.UUIDField()

    to_entity_type = models.CharField(max_length=50)
    to_entity_id = models.UUIDField()

    currency = models.CharField(max_length=3, default="INR")
    amount = models.DecimalField(max_digits=14, decimal_places=2)

    reason = models.TextField()

    category = models.ForeignKey(
        "finance.Category",
        on_delete=models.PROTECT,
    )
    is_caused_by_autopay = models.BooleanField(default=False)

    class Meta(AuditModel.Meta):
        db_table = "finance_audit_logs"
        indexes = [
            models.Index(fields=["organization", "-created_at"]),
        ]


class Category(AuditModel):
    id = models.SmallAutoField(primary_key=True)
    category_name = models.CharField(max_length=30)

    class Meta(AuditModel.Meta):
        db_table = "categories"

    def __str__(self):
        return self.category_name

