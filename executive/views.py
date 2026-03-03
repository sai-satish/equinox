from rest_framework import status, permissions
from rest_framework.response import Response
from rest_framework.views import APIView
from django.db import transaction
from decimal import Decimal
import logging

from authentication.permissions import IsExecutive
from executive.models import (
    OrganizationUser,
    Team,
    Organization,
    Role,
)

from finance.models import (
    Budget,
    FinanceAuditLog,
    BudgetRequest,
    BudgetApprovalStatus,
)

from executive.serializers import (
    TeamListSerializer,
    ManagerListSerializer,
    OrganizationUserListSerializer,
    PendingBudgetRequestSerializer,
    ExecutiveAllocateSerializer,
    CreateTeamSerializer,
    CreateRoleSerializer,
    RoleAssignmentSerializer,
)
from utils.execption_utils import extract_execption_string
import constants.loggers

logger = logging.getLogger(constants.loggers.EXECUTIVE_LOGGER)


class ExecutiveTeamsView(APIView):
    permission_classes = [permissions.IsAuthenticated, IsExecutive]

    def get(self, request):
        try:
            org_user = request.org_user
            teams = Team.objects.filter(
                organization=org_user.organization
            ).select_related("manager__user_profile")

            serializer = TeamListSerializer(teams, many=True)

            logger.info(f"Executive {request.user.email} fetched teams list")
            return Response(
                serializer.data,
                status=status.HTTP_200_OK,
            )

        except Exception as e:
            logger.error(f"Error fetching teams: {str(e)}")
            return Response(
                {"error": "Failed to fetch teams"},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR,
            )
        
    def post(self, request):
        org_user = request.org_user
        serializer = CreateTeamSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        validated_data = serializer.validated_data

        team_data = {
            "team_name": validated_data["team_name"],
            "organization": org_user.organization,
        }
        manager_id = validated_data.get("manager_id")
        if manager_id:
            manager = OrganizationUser.objects.get(
                id=manager_id,
            )
            team_data["manager"] = manager

        team = Team.objects.create(**team_data)

        return Response(
            {
                "message": "Team created successfully",
                "team_id": team.id,
            },
            status=201,
        )


class ExecutiveManagerListView(APIView):
    permission_classes = [permissions.IsAuthenticated, IsExecutive]

    def get(self, request):
        try:
            org_user = request.org_user

            managers = OrganizationUser.objects.filter(
                organization=org_user.organization,
                role__role_name="Manager",
            ).select_related("user_profile__user")

            serializer = ManagerListSerializer(managers, many=True)

            logger.info(f"Executive {request.user.email} fetched managers list")
            return Response(
                serializer.data,
                status=status.HTTP_200_OK,
            )

        except Exception as e:
            logger.error(f"Error fetching managers: {str(e)}")
            return Response(
                {"error": "Failed to fetch managers"},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR,
            )


class ExecutiveUserListView(APIView):
    permission_classes = [permissions.IsAuthenticated, IsExecutive]

    def get(self, request):
        try:
            org_user = request.org_user

            users = OrganizationUser.objects.filter(
                organization=org_user.organization
            ).select_related("role", "user_profile")

            serializer = OrganizationUserListSerializer(users, many=True)
            logger.info(f"Executive {request.user.email} fetched organization users")

            return Response(
                serializer.data,
                status=status.HTTP_200_OK,
            )

        except Exception as e:
            logger.error(f"Error fetching users: {str(e)}")
            return Response(
                {"error": "Failed to fetch users"},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR,
            )


# implement individual person view with teams associated,
# implement individual manager view with teams associated


class ExecutiveBudgetRequestListView(APIView):
    permission_classes = [permissions.IsAuthenticated, IsExecutive]

    def get(self, request):
        try:
            org_user = request.org_user

            budget_pending_status = BudgetApprovalStatus.objects.get(status_name="Pending")
            requests = BudgetRequest.objects.filter(
                organization=org_user.organization, 
                status=budget_pending_status,
            ).select_related("requested_by", "requested_by__user_profile")

            serializer = PendingBudgetRequestSerializer(requests, many=True)

            logger.info(f"Executive {request.user.email} fetched budget requests")
            return Response(
                serializer.data,
                status=status.HTTP_200_OK,
            )

        except Exception as e:
            logger.error(f"Error fetching budget requests: {str(e)}")
            return Response(
                {"error": "Failed to fetch budget requests"},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR,
            )


# combine allocate and Reject budget views
class ExecutiveAllocateBudgetView(APIView):
    permission_classes = [permissions.IsAuthenticated, IsExecutive]

    def post(self, request):
        try:
            org_user = request.org_user

            serializer = ExecutiveAllocateSerializer(data=request.data)
            serializer.is_valid(raise_exception=True)

            data = serializer.validated_data

            target_user_id = data["target_user_id"]
            amount = data["amount"]
            period_start = data["period_start"]
            period_end = data["period_end"]

            if not target_user_id or not amount:
                return Response(
                    {"error": "target_user_id and amount required"},
                    status=status.HTTP_400_BAD_REQUEST,
                )

            target_user = OrganizationUser.objects.get(
                id=target_user_id, organization=org_user.organization
            )

            with transaction.atomic():
                organization = Organization.objects.select_for_update().get(
                    id=org_user.organization.id
                )

                if organization.account_balance < Decimal(amount):
                    return Response(
                        {
                            "error": "Insufficient funds",
                        },
                        status=400,
                    )

                organization.account_balance -= Decimal(amount)
                organization.save(update_fields=["account_balance"])

                budget = Budget.objects.create(
                    organization=org_user.organization,
                    allocated_to_user=target_user,
                    amount=amount,
                    remaining_amount=amount,
                    currency=org_user.organization.currency,
                    period_start=period_start,
                    period_end=period_end,
                )

                FinanceAuditLog.objects.create(
                    organization=org_user.organization,
                    from_entity_type="Organization",
                    from_entity_id=org_user.organization.id,
                    to_entity_type="OrganizationUser",
                    to_entity_id=target_user.id,
                    currency=budget.currency,
                    amount=amount,
                    reason="Executive Allocation",
                    category=None,
                )

            logger.info(
                f"Executive {request.user.email} allocated {amount} to {target_user.id}"
            )

            return Response(
                {"message": "Budget allocated successfully"},
                status=status.HTTP_201_CREATED,
            )

        except OrganizationUser.DoesNotExist:
            logger.warning("Target user not found")
            return Response(
                {"error": "Target user not found"},
                status=status.HTTP_404_NOT_FOUND,
            )

        except Exception as e:
            logger.error(f"Allocation failed: {str(e)}")
            try:
                error_message, error_code = extract_execption_string(str(e))
                return Response(
                    {
                        "error": error_message,
                        "code": error_code,
                    },
                    status=status.HTTP_500_INTERNAL_SERVER_ERROR,
                )
            except Exception:
                return Response(
                    {"error": "Budget allocation failed"},
                    status=status.HTTP_500_INTERNAL_SERVER_ERROR,
                )


class ExecutiveRejectBudgetRequestView(APIView):
    permission_classes = [permissions.IsAuthenticated, IsExecutive]

    def post(self, request, request_id):
        try:
            org_user = request.org_user

            budget_request = BudgetRequest.objects.get(
                id=request_id, organization=org_user.organization
            )

            budget_reject_status = BudgetApprovalStatus.objects.get(
                status_name="Rejected"
            )
            with transaction.atomic():
                budget_request.status = budget_reject_status
                budget_request.save(update_fields=["status"])

            logger.info(f"Executive {request.user.email} rejected request {request_id}")

            return Response(
                {"message": "Budget request rejected"},
                status=status.HTTP_200_OK,
            )

        except BudgetRequest.DoesNotExist:
            logger.warning("Budget request not found")
            return Response(
                {"error": "Budget request not found"},
                status=status.HTTP_404_NOT_FOUND,
            )

        except Exception as e:
            logger.error(f"Reject request failed: {str(e)}")
            return Response(
                {"error": "Failed to reject budget request"},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR,
            )


class ExecutiveAssignRoleView(APIView):
    permission_classes = [permissions.IsAuthenticated, IsExecutive]

    def post(self, request):
        org_user = request.org_user
        serializer = RoleAssignmentSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)

        target_user = serializer.validated_data["user"]
        role = serializer.validated_data["role"]

        if target_user.organization != org_user.organization:
            return Response(
                {"error": "User does not belong to your organization"}, status=403
            )

        target_user.role = role
        target_user.save(update_fields=["role"])

        return Response(
            {
                "message": f"{target_user.user_profile.first_name} assigned role {role.role_name}"
            },
            status=200,
        )


class ExecutiveRoleView(APIView):
    permission_classes = [permissions.IsAuthenticated, IsExecutive]

    def get(self, request):
        org_user = request.org_user
        roles = Role.objects.filter(organization=org_user.organization)
        data = [
            {
                "id": r.id,
                "role_name": r.role_name,
                "role_level": r.role_level,
            }
            for r in roles
        ]

        return Response(data, status=200)

    def post(self, request):
        org_user = request.org_user
        serializer = CreateRoleSerializer(
            data=request.data, context={"org_user": org_user}
        )
        serializer.is_valid(raise_exception=True)
        role = serializer.save()

        return Response(
            {
                "message": "Role created",
                "role_id": role.id,
                "role_name": role.role_name,
                "role_level": role.role_level,
            },
            status=201,
        )
