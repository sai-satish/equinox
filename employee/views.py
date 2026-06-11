from rest_framework import status, permissions
from rest_framework.response import Response
from rest_framework.views import APIView
from django.db import transaction
from decimal import Decimal
import logging

from executive.models import (
    OrganizationUser,
    TeamAssignment,
    Organization,
    Role,
)

from finance.models import (
    Budget,
    FinanceAuditLog,
    BudgetRequest,
    BudgetApprovalStatus,
)

from employee.serializers import (
    TeamListSerializer,
    TeamMembersListSerializer,
)
from utils.execption_utils import extract_execption_string
from utils.extract_organization import extract_organization, extract_organization_user
import constants.loggers

logger = logging.getLogger(constants.loggers.EMPLOYEE_LOGGER)


class EmployeeListTeams(APIView):
    permission_classes = [permissions.IsAuthenticated]

    def get(self, request):
        try:
            org_user = extract_organization_user(request)
            teams = TeamAssignment.objects.filter(
                organization_user=org_user,
            ).select_related(
                "team__manager__user_profile",
            )

            serializer = TeamListSerializer(teams, many=True)

            logger.info(f"Employee {request.user.email} fetched teams list")
            return Response(
                serializer.data,
                status=status.HTTP_200_OK,
            )

        except Exception as e:
            logger.error(f"Error fetching employee teams: {str(e)}")
            return Response(
                {"error": "Failed to fetch employee teams"},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR,
            )


class EmployeeListTeamMembers(APIView):
    permission_classes = [permissions.IsAuthenticated]

    def get(self, request, team_id):
        try:
            org_user = extract_organization_user(request)
            is_member = TeamAssignment.objects.filter(
                team_id=team_id, organization_user=org_user
            ).exists()

            if not is_member:
                return Response(
                    {"error": "You are not a member of this team"},
                    status=status.HTTP_403_FORBIDDEN,
                )

            team_member_details = TeamAssignment.objects.filter(
                team_id=team_id,
            ).select_related(
                "organization_user__user_profile",
                "team__manager__user_profile",
            )

            serializer = TeamMembersListSerializer(team_member_details, many=True)

            logger.info(f"Employee {request.user.email} fetched managers list")
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


class EmployeeRaiseBudgetRequestView(APIView):
    permission_classes = [permissions.IsAuthenticated]

    def post(self, request):
        try:
            org_user = extract_organization_user(request)
            if not org_user:
                return Response(
                    {"error": "Organization user not found."},
                    status=status.HTTP_403_FORBIDDEN,
                )
            amount = request.data.get("amount")
            if amount is None:
                return Response(
                    {"error": "Amount is required."},
                    status=status.HTTP_400_BAD_REQUEST,
                )

            try:
                amount = Decimal(amount)
                if amount <= 0:
                    raise ValueError("Amount must be greater than zero.")
            except (ValueError, TypeError) as e:
                logger.error(f"Invalid amount provided by user {request.user.email}: {str(e)}")
                return Response(
                    {"error": f"Invalid amount: {str(e)}"},
                    status=status.HTTP_400_BAD_REQUEST,
                )

            pending_status = BudgetApprovalStatus.objects.get(
                status_name="Pending",
            )

            with transaction.atomic():
                budget_request_details = {
                    "organization": org_user.organization,
                    "requested_by": org_user,
                    "amount_requested": amount,
                    "status": pending_status,
                    category
                }
                if 
                budget_request = BudgetRequest.objects.create(
                    **budget_request_details
                )

                FinanceAuditLog.objects.create(
                    organization=org_user.organization,
                    action="Raised Budget Request",
                    performed_by=org_user,
                    details=f"Budget request {budget_request.id} raised for amount {amount}",
                )

            logger.info(
                f"Employee {request.user.email} raised a budget request for amount {amount}"
            )
            return Response(
                {"message": "Budget request raised successfully."},
                status=status.HTTP_201_CREATED,
            )
        except Exception as e:
            logger.error(f"Error raising budget requests: {str(e)}")
            return Response(
                {"error": "Failed to raise budget request"},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR,
            )


class EmployeeBudgetRequestListView(APIView):
    permission_classes = [permissions.IsAuthenticated]

    def get(self, request):
        try:
            org_user = extract_organization_user(request)
            budget_requests = BudgetRequest.objects.filter(
                organization=org_user.organization,
                requested_by=org_user,
            ).select_related(
                "status",
                "approved_by__user_profile",
            )

            serializer = BudgetRequestSerializer(budget_requests, many=True)

            logger.info(f"Employee {request.user.email} fetched budget requests list")
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


class EmployeeBudgetRequestDetailView(APIView):
    permission_classes = [permissions.IsAuthenticated]

    def get(self, request, budget_request_id):
        try:
            org_user = request.org_user
            budget_request = BudgetRequest.objects.select_related(
                "requested_by__user_profile",
                "approved_by__user_profile",
            ).get(id=budget_request_id, organization=org_user.organization)

            serializer = BudgetRequestSerializer(budget_request)

            logger.info(
                f"Employee {request.user.email} fetched budget request details for request {budget_request_id}"
            )
            return Response(
                serializer.data,
                status=status.HTTP_200_OK,
            )

        except BudgetRequest.DoesNotExist:
            logger.error(f"Budget request not found: {budget_request_id}")
            return Response(
                {"error": "Budget request not found."},
                status=status.HTTP_404_NOT_FOUND,
            )
        except Exception as e:
            logger.error(f"Error fetching budget request details: {str(e)}")
            return Response(
                {"error": "Failed to fetch budget request details."},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR,
            )

    def patch(self, request, budget_request_id):
        try:
            org_user = request.org_user
            budget_request = BudgetRequest.objects.select_related(
                "requested_by__user_profile",
                "approved_by__user_profile",
            ).get(id=budget_request_id, organization=org_user.organization)

            if budget_request.requested_by != org_user:
                return Response(
                    {"error": "You are not authorized to update this budget request."},
                    status=status.HTTP_403_FORBIDDEN,
                )

            if budget_request.status.status_name != "Pending":
                return Response(
                    {"error": "Only pending budget requests can be updated."},
                    status=status.HTTP_400_BAD_REQUEST,
                )

            new_amount = request.data.get("amount")
            if new_amount is None:
                return Response(
                    {"error": "Amount is required."},
                    status=status.HTTP_400_BAD_REQUEST,
                )

            try:
                new_amount = Decimal(new_amount)
                if new_amount <= 0:
                    raise ValueError("Amount must be greater than zero.")
            except (ValueError, TypeError) as e:
                return Response(
                    {"error": f"Invalid amount: {str(e)}"},
                    status=status.HTTP_400_BAD_REQUEST,
                )

            with transaction.atomic():
                budget_request.amount_requested = new_amount
                budget_request.save()

                FinanceAuditLog.objects.create(
                    organization=org_user.organization,
                    action="Updated Budget Request",
                    performed_by=org_user,
                    details=f"Budget request {budget_request.id} updated to amount {new_amount}",
                )

            logger.info(
                f"Employee {request.user.email} updated budget request {budget_request.id}"
            )
            return Response(
                {"message": "Budget request updated successfully."},
                status=status.HTTP_200_OK,
            )

        except BudgetRequest.DoesNotExist:
            logger.error(f"Budget request not found: {budget_request_id}")
            return Response(
                {"error": "Budget request not found."},
                status=status.HTTP_404_NOT_FOUND,
            )
        except Exception as e:
            logger.error(f"Error updating budget request: {str(e)}")
            return Response(
                {"error": "Failed to update budget request."},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR,
            )

    def delete(self, request, budget_request_id):
        try:
            org_user = request.org_user
            budget_request = BudgetRequest.objects.get(
                id=budget_request_id, organization=org_user.organization
            )

            if budget_request.requested_by != org_user:
                return Response(
                    {"error": "You are not authorized to delete this budget request."},
                    status=status.HTTP_403_FORBIDDEN,
                )

            if budget_request.status.status_name != "Pending":
                return Response(
                    {"error": "Only pending budget requests can be deleted."},
                    status=status.HTTP_400_BAD_REQUEST,
                )

            with transaction.atomic():
                budget_request.delete()

                FinanceAuditLog.objects.create(
                    organization=org_user.organization,
                    action="Deleted Budget Request",
                    performed_by=org_user,
                    details=f"Budget request {budget_request.id} deleted",
                )

            logger.info(
                f"Employee {request.user.email} deleted budget request {budget_request.id}"
            )
            return Response(
                {"message": "Budget request deleted successfully."},
                status=status.HTTP_200_OK,
            )

        except BudgetRequest.DoesNotExist:
            logger.error(f"Budget request not found: {budget_request_id}")
            return Response(
                {"error": "Budget request not found."},
                status=status.HTTP_404_NOT_FOUND,
            )
        except Exception as e:
            logger.error(f"Error deleting budget request: {str(e)}")
            return Response(
                {"error": "Failed to delete budget request."},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR,
            )
