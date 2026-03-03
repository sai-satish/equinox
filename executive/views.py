from rest_framework import status, permissions
from rest_framework.response import Response
from rest_framework.views import APIView
from django.db import transaction
import logging

from executive.models import (
    OrganizationUser, 
    Team,
)

from finance.models import (
    Budget, 
    FinanceAuditLog, 
    BudgetRequest,
)

from executive.serializers import (
    TeamListSerializer,
    ManagerListSerializer,
    OrganizationUserListSerializer,
)
from utils.execption_utils import extract_execption_string
import constants.loggers

logger = logging.getLogger(constants.loggers.EXECUTIVE_LOGGER)


def _validate_executive(user):
    org_user = getattr(user, "organization", None)
    if not org_user or org_user.role.role_name.lower() != "executive":
        raise PermissionError("Only Executive can perform this action")
    return org_user

class ExecutiveTeamListView(APIView):
    permission_classes = [permissions.IsAuthenticated]

    def get(self, request):
        try:
            org_user = _validate_executive(request.user)
            teams = Team.objects.filter(
                organization=org_user.organization
            ).select_related("manager__user_profile")

            serializer = TeamListSerializer(teams, many=True)

            logger.info(f"Executive {request.user.email} fetched teams list")
            return Response(
                serializer.data, 
                status=status.HTTP_200_OK,
            )

        except PermissionError as pe:
            logger.warning(f"Unauthorized team listing attempt: {str(pe)}")
            return Response(
                {"error": str(pe)}, 
                status=status.HTTP_403_FORBIDDEN,
                )

        except Exception as e:
            logger.error(f"Error fetching teams: {str(e)}")
            return Response(
                {"error": "Failed to fetch teams"},
                            status=status.HTTP_500_INTERNAL_SERVER_ERROR,
                            )
        

class ExecutiveManagerListView(APIView):
    permission_classes = [permissions.IsAuthenticated]

    def get(self, request):
        try:
            org_user = _validate_executive(request.user)

            managers = OrganizationUser.objects.filter(
                organization=org_user.organization,
                role__role_name="Manager"
            ).select_related("user_profile__user")


            serializer = ManagerListSerializer(managers, many=True)

            logger.info(f"Executive {request.user.email} fetched managers list")
            return Response(
                serializer.data, 
                status=status.HTTP_200_OK,
            )

        except PermissionError as pe:
            logger.warning(str(pe))
            return Response({"error": str(pe)}, status=status.HTTP_403_FORBIDDEN)

        except Exception as e:
            logger.error(f"Error fetching managers: {str(e)}")
            return Response({"error": "Failed to fetch managers"},
                            status=status.HTTP_500_INTERNAL_SERVER_ERROR)


class ExecutivePeopleListView(APIView):
    permission_classes = [permissions.IsAuthenticated]

    def get(self, request):
        try:
            org_user = _validate_executive(request.user)

            users = OrganizationUser.objects.filter(
                organization=org_user.organization
            ).select_related("role", "user_profile")



            serializer = OrganizationUserListSerializer(users, many=True)
            logger.info(f"Executive {request.user.email} fetched organization users")

            return Response(
                serializer.data,
                status=status.HTTP_200_OK
            )

        except PermissionError as pe:
            logger.warning(str(pe))
            return Response({"error": str(pe)}, status=status.HTTP_403_FORBIDDEN)

        except Exception as e:
            logger.error(f"Error fetching users: {str(e)}")
            return Response({"error": "Failed to fetch users"},
                            status=status.HTTP_500_INTERNAL_SERVER_ERROR)
        

# implement individual person view with teams associated, 
# implement individual manager view with teams associated

class ExecutiveBudgetRequestListView(APIView):
    permission_classes = [permissions.IsAuthenticated]

    def get(self, request):
        try:
            org_user = _validate_executive(request.user)

            requests = BudgetRequest.objects.filter(
                organization=org_user.organization,
                status="Pending"
            ).select_related("requested_by")


            # replace with serializer
            data = [
                {
                    "id": str(req.id),
                    "requested_by": req.requested_by.user_profile.first_name,
                    "amount": str(req.amount_requested),
                    "status": req.status,
                }
                for req in requests
            ]

            logger.info(f"Executive {request.user.email} fetched budget requests")
            return Response(data, status=status.HTTP_200_OK)

        except PermissionError as pe:
            logger.warning(str(pe))
            return Response({"error": str(pe)}, status=status.HTTP_403_FORBIDDEN)

        except Exception as e:
            logger.error(f"Error fetching budget requests: {str(e)}")
            return Response({"error": "Failed to fetch budget requests"},
                            status=status.HTTP_500_INTERNAL_SERVER_ERROR)
        

# combine allocate and Reject budget views
class ExecutiveAllocateBudgetView(APIView):
    permission_classes = [permissions.IsAuthenticated]

    def post(self, request):
        try:
            org_user = _validate_executive(request.user)

            target_user_id = request.data.get("target_user_id")
            amount = request.data.get("amount")
            period_start = request.data.get("period_start")
            period_end = request.data.get("period_end")

            if not target_user_id or not amount:
                return Response(
                    {"error": "target_user_id and amount required"},
                    status=status.HTTP_400_BAD_REQUEST,
                )

            target_user = OrganizationUser.objects.get(
                id=target_user_id,
                organization=org_user.organization
            )

            with transaction.atomic():

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

        except PermissionError as pe:
            logger.warning(str(pe))
            return Response({"error": str(pe)}, status=status.HTTP_403_FORBIDDEN)

        except Exception as e:
            logger.error(f"Allocation failed: {str(e)}")
            try:
                error_message, error_code = extract_execption_string(str(e))
                return Response(
                    {"error": error_message, "code": error_code,},
                    status=status.HTTP_500_INTERNAL_SERVER_ERROR,
                )
            except Exception:
                return Response(
                    {"error": "Budget allocation failed"},
                    status=status.HTTP_500_INTERNAL_SERVER_ERROR,
                )
            

class ExecutiveRejectBudgetRequestView(APIView):
    permission_classes = [permissions.IsAuthenticated]

    def post(self, request, request_id):
        try:
            org_user = _validate_executive(request.user)

            budget_request = BudgetRequest.objects.get(
                id=request_id,
                organization=org_user.organization
            )

            budget_request.status = "Rejected"
            budget_request.save(update_fields=["status"])

            logger.info(
                f"Executive {request.user.email} rejected request {request_id}"
            )

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

        except PermissionError as pe:
            logger.warning(str(pe))
            return Response({"error": str(pe)}, status=status.HTTP_403_FORBIDDEN)

        except Exception as e:
            logger.error(f"Reject request failed: {str(e)}")
            return Response(
                {"error": "Failed to reject budget request"},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR,
            )