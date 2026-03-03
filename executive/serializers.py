from rest_framework import serializers
from executive.models import (
    Team,
    OrganizationUser,
    Role,
)
from finance.models import (
    BudgetRequest,
)


class TeamListSerializer(serializers.ModelSerializer):
    manager = serializers.CharField(
        source="manager.user_profile.first_name",
        read_only=True,
    )

    class Meta:
        model = Team
        fields = [
            "id",
            "team_name",
            "manager",
            "account_balance",
            "monthly_limit",
        ]


class ManagerListSerializer(serializers.ModelSerializer):
    name = serializers.CharField(
        source="user_profile.first_name",
        read_only=True,
    )
    email = serializers.EmailField(
        source="user_profile.user.email",
        read_only=True,
    )

    class Meta:
        model = OrganizationUser
        fields = [
            "id",
            "name",
            "email",
            "organization_user_status",
            "role",
            "account_balance",
            "freezed_amount",
            "individual_monthly_limit",
            "second_stage_approval_limit",
            "joined_at",
        ]


class OrganizationUserListSerializer(serializers.ModelSerializer):
    name = serializers.SerializerMethodField()
    role = serializers.CharField(
        source="role.role_name",
        read_only=True,
    )

    class Meta:
        model = OrganizationUser
        fields = [
            "id",
            "name",
            "role",
        ]

    def get_name(self, obj):
        profile = obj.user_profile
        if not profile:
            return None
        return f"{profile.first_name} {profile.last_name or ''}".strip()


class PendingBudgetRequestSerializer(serializers.ModelSerializer):
    requested_by = serializers.SerializerMethodField()
    amount = serializers.DecimalField(
        source="amount_requested", max_digits=14, decimal_places=2
    )

    class Meta:
        model = BudgetRequest
        fields = [
            "id",
            "requested_by",
            "amount",
            "status",
        ]

    def get_requested_by(self, obj):
        return obj.requested_by.user_profile.first_name


class ExecutiveAllocateSerializer(serializers.Serializer):
    target_user_id = serializers.UUIDField()
    amount = serializers.DecimalField(max_digits=14, decimal_places=2)
    period_start = serializers.DateField()
    period_end = serializers.DateField()

    def validate_amount(self, value):
        if value <= 0:
            raise serializers.ValidationError("Amount must be positive")
        return value


class CreateTeamSerializer(serializers.ModelSerializer):
    manager_id = serializers.UUIDField(
        write_only=True,
        required=False,
        allow_null=True,
    )

    class Meta:
        model = Team
        fields = [
            "team_name",
            "manager_id",
        ]


class RoleAssignmentSerializer(serializers.Serializer):
    user_id = serializers.UUIDField()
    role_id = serializers.IntegerField()

    def validate(self, attrs):
        user_id = attrs.get("user_id")
        role_id = attrs.get("role_id")

        # Check if user exists
        try:
            user = OrganizationUser.objects.get(id=user_id)
        except OrganizationUser.DoesNotExist:
            raise serializers.ValidationError("Target user does not exist")

        try:
            role = Role.objects.get(id=role_id, organization=user.organization)
        except Role.DoesNotExist:
            raise serializers.ValidationError(
                "Role does not exist in this organization"
            )

        attrs["user"] = user
        attrs["role"] = role
        return attrs


class CreateRoleSerializer(serializers.ModelSerializer):
    class Meta:
        model = Role
        fields = ["role_name", "role_level"]

    def create(self, validated_data):
        org_user = self.context["org_user"]
        validated_data["organization"] = org_user.organization
        return super().create(validated_data)
