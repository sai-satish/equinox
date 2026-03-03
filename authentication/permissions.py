from rest_framework.permissions import BasePermission
from executive.models import OrganizationUser
from typing import Any
from typing_extensions import override


class IsExecutive(BasePermission):
    message = "Only executives can perform this action"

    @override
    def has_permission(self, request: Any, view: Any) -> bool:
        try:
            org_user = OrganizationUser.objects.select_related(
                "role", "organization"
            ).get(
                user_profile__user=request.user,
                deleted_at__isnull=True,
            )
        except OrganizationUser.DoesNotExist:
            return False

        if org_user.role.role_name.lower() != "ceo":
            return False

        request.org_user = org_user
        return True
