from django.urls import path
from executive.views import (
    ExecutiveTeamsView,
    ExecutiveManagerListView,
    ExecutiveUserListView,
    ExecutiveBudgetRequestListView,
    ExecutiveAllocateBudgetView,
    ExecutiveRejectBudgetRequestView,
    ExecutiveAssignRoleView,
    ExecutiveRoleView,
)

urlpatterns = [
    path('teams/', ExecutiveTeamsView.as_view(), name='executive-teams'),
    path('managers/', ExecutiveManagerListView.as_view(), name='executive-managers'),
    path('users/', ExecutiveUserListView.as_view(), name='executive-users'),
    path('budget-requests/', ExecutiveBudgetRequestListView.as_view(), name='executive-budget-requests'),
    path('budget-requests/allocate/<uuid:budget_request_id>/', ExecutiveAllocateBudgetView.as_view(), name='executive-allocate-budget'),
    path('budget-requests/reject/<uuid:budget_request_id>/', ExecutiveRejectBudgetRequestView.as_view(), name='executive-reject-budget-request'),
    path('assign-role/', ExecutiveAssignRoleView.as_view(), name='executive-assign-role'),
    path('role/', ExecutiveRoleView.as_view(), name='executive-role'),
]
