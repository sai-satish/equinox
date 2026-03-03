from rest_framework import serializers
from executive.models import (
    Team,
    OrganizationUser,
)

class TeamListSerializer(serializers.ModelSerializer):
    manager = serializers.CharField(
        source="manager.user_profile.first_name",
        read_only=True
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
        read_only=True
    )
    email = serializers.EmailField(
        source="user_profile.user.email",
        read_only=True
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
        read_only=True
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