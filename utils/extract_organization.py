from executive.models import OrganizationUser
from authentication.models import UserProfile


def extract_organization(request):
    """
    Utility function to extract the organization from the request's user.
    """
    user = request.user
    if not user.is_authenticated:
        return None

    try:
        user_profile = UserProfile.objects.select_related("organization").get(user=user)

        return user_profile.organization
    except UserProfile.DoesNotExist:
        return None


def extract_organization_user(request):
    try:
        org_user = OrganizationUser.objects.select_related("role", "organization").get(
            user_profile__user=request.user,
            deleted_at__isnull=True,
        )
    except OrganizationUser.DoesNotExist:
        return None

    return org_user
