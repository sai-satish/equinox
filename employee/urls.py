from django.urls import path
from employee.views import (
    EmployeeListTeams,
    EmployeeListTeamMembers,
    EmployeeRaiseBudgetRequestView,
    EmployeeBudgetRequestListView,
    EmployeeBudgetRequestDetailView,
)

urlpatterns = [
    path('teams/', EmployeeListTeams.as_view(), name='employee-teams'),
    path('teams/members/<uuid:team_id>/', EmployeeListTeamMembers.as_view(), name='employee-team-members'),
    path('budget-request/raise/', EmployeeRaiseBudgetRequestView.as_view(), name='employee-budget-requests'),
    path('budget-requests/', EmployeeBudgetRequestListView.as_view(), name='employee-budget-requests'),
    path('budget-requests/<uuid:budget_request_id>/', EmployeeBudgetRequestDetailView.as_view(), name='employee-budget-request-detail'),
]
