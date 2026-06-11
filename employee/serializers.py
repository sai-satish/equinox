from rest_framework import serializers
from executive.models import (
    OrganizationUser,
    Role,
    TeamAssignment,
)
from finance.models import (
    BudgetRequest,
)


class TeamListSerializer(serializers.ModelSerializer):
    team_id = serializers.ReadOnlyField(
        source="team.id",
    )
    team_name = serializers.ReadOnlyField(
        source="team.team_name",
    )
    manager_name = serializers.ReadOnlyField(
        source="team.manager.user_profile.first_name",
    )
    manager_id = serializers.ReadOnlyField(
        source="team.manager.id",
    )
    my_account_balance = serializers.ReadOnlyField(
        source="account_balance",
    )
    my_monthly_limit = serializers.ReadOnlyField(
        source="monthly_limit",
    )
    team_account_balance = serializers.ReadOnlyField(
        source="team.account_balance",
    )
    team_monthly_limit = serializers.ReadOnlyField(
        source="team.monthly_limit",
    )

    class Meta:
        model = TeamAssignment
        fields = [
            "id",
            "team_id",
            "team_name",
            "manager_name",
            "manager_id",
            "my_account_balance",
            "my_monthly_limit",
            "team_account_balance",
            "team_monthly_limit",
        ]


class TeamMembersListSerializer(serializers.ModelSerializer):
    manager_name = serializers.ReadOnlyField(
        source="team.manager.user_profile.first_name",
    )
    manager_id = serializers.ReadOnlyField(
        source="team.manager.id",
    )
    organization_user_fname = serializers.ReadOnlyField(
        source="organization_user.user_profile.first_name",
    )
    organization_user_lname = serializers.ReadOnlyField(
        source="organization_user.user_profile.last_name",
    )

    class Meta:
        model = TeamAssignment
        fields = [
            "id",
            "manager_name",
            "manager_id",
            "organization_user_fname",
            "organization_user_lname",
        ]

class BudgetRequestSerializer(serializers.ModelSerializer):
    category_name = serializers.ReadOnlyField(
        source="category.category_name",
    )

    class Meta:
        model = BudgetRequest
        fields = [
            "id",
            "amount_requested",
            "category",
            "category_name",
            "description",
            "status",
            "created_at",
        ]
        read_only_fields = [
            "status",
        ]