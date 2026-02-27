from django.db import transaction
from rest_framework import serializers
from authentication.models import AuthUser, UserProfile, UserPasswordHistory
from executive.models import (
    Organization,
    OrganizationUser,
    Role,
    OrganizationUserStatus,
)
from finance.models import SubscriptionPlan, SubscriptionStatus
from django.contrib.auth.hashers import make_password


class UserProfileSerializer(serializers.ModelSerializer):
    class Meta:
        model = UserProfile
        exclude = ("deleted_at",)
        read_only_fields = ("id", "created_at", "updated_at")


class UserRegistrationSerializer(serializers.ModelSerializer):
    password = serializers.CharField(write_only=True, min_length=8)
    first_name = serializers.CharField(source="profile.first_name")
    last_name = serializers.CharField(
        source="profile.last_name",
        required=False,
        allow_blank=True,
        allow_null=True,
    )
    phone_number = serializers.CharField(source="profile.phone_number")

    class Meta:
        model = AuthUser
        fields = (
            "email",
            "password",
            "username",
            "first_name",
            "last_name",
            "phone_number",
            "username",
        )

    def create(self, validated_data):
        # Extract profile data from the nested source mapping
        profile_data = validated_data.pop("profile")
        password = validated_data.pop("password")
        email = validated_data["email"]

        domain_name = email.split("@")[1]

        try:
            organization = Organization.objects.get(domain_name=domain_name)
        except Organization.DoesNotExist:
            raise serializers.ValidationError(
                "No organization found with this email domain."
            )

        with transaction.atomic():
            # Create the AuthUser using your AuthUserManager
            user = AuthUser.objects.create_user(
                password=password,
                **validated_data,
            )

            # Create the associated UserProfile
            user_profile = UserProfile.objects.create(
                user=user,
                organization=organization,
                **profile_data,
            )

            employee_role, created = Role.objects.get_or_create(
                role_name="employee", organization=organization
            )

            OrganizationUser.objects.create(
                user_profile=user_profile,
                organization=organization,
                role=employee_role,
                organization_user_status=OrganizationUserStatus.objects.get(
                    status_name="pending_approval"
                ),
            )

            UserPasswordHistory.objects.create(
                user = user,
                password_hash = user.password
            )

            return user, user_profile


class ExecutiveRegistrationSerializer(serializers.ModelSerializer):
    password = serializers.CharField(write_only=True, min_length=8)
    organization_name = serializers.CharField()
    domain_name = serializers.CharField()
    subscription_plan = serializers.PrimaryKeyRelatedField(
        queryset=SubscriptionPlan.objects.all()
    )
    subscription_status = serializers.PrimaryKeyRelatedField(
        queryset=SubscriptionStatus.objects.all()
    )
    first_name = serializers.CharField(source="profile.first_name")
    last_name = serializers.CharField(
        source="profile.last_name",
        required=False,
        allow_blank=True,
        allow_null=True,
    )
    subscription_starts_at = serializers.DateTimeField()
    subscription_ends_at = serializers.DateTimeField()
    support_email = serializers.EmailField(
        required=False,
        allow_blank=True,
        allow_null=True,
    )
    support_phone = serializers.CharField(
        required=False,
        allow_blank=True,
        allow_null=True,
    )
    phone_number = serializers.CharField(source="profile.phone_number")
    currency = serializers.CharField()

    class Meta:
        model = AuthUser
        fields = (
            "email",
            "password",
            "username",
            "organization_name",
            "domain_name",
            "first_name",
            "last_name",
            "phone_number",
            "username",
            "support_email",
            "support_phone",
            "subscription_plan",
            "subscription_status",
            "subscription_starts_at",
            "subscription_ends_at",
            "currency",
        )

    def create(self, validated_data):
        # Extract profile and organization data
        profile_data = validated_data.pop("profile", {})
        organization_data = {
            "organization_name": validated_data.pop("organization_name"),
            "domain_name": validated_data.pop("domain_name"),
            "subscription_plan": validated_data.pop("subscription_plan"),
            "subscription_status": validated_data.pop("subscription_status"),
            "subscription_starts_at": validated_data.pop("subscription_starts_at"),
            "subscription_ends_at": validated_data.pop("subscription_ends_at"),
            "support_email": validated_data.pop("support_email"),
            "support_phone": validated_data.pop("support_phone"),
            "currency": validated_data.pop("currency"),
        }

        with transaction.atomic():
            # Create the AuthUser using the custom manager
            password = validated_data.pop("password")
            user = AuthUser.objects.create_user(password=password, **validated_data)

            # Create the organization
            organization = Organization.objects.create(**organization_data)

            # Create the associated UserProfile
            user_profile = UserProfile.objects.create(
                user=user, organization=organization, **profile_data
            )

            # Create or get the CEO role in the organization
            ceo_role, created = Role.objects.get_or_create(
                role_name="CEO", organization=organization
            )

            # Link the user as the CEO for this organization in the OrganizationUser model
            OrganizationUser.objects.create(
                user_profile=user_profile,
                organization=organization,
                role=ceo_role,
                organization_user_status=OrganizationUserStatus.objects.get(
                    status_name="active"
                ),
            )

            UserPasswordHistory.objects.create(
                user = user,
                password_hash = user.password
            )

            return user, user_profile, organization
