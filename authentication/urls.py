from django.urls import path
from authentication.views import (
    RegisterView,
    LoginView,
    RefreshView,
    LogoutView,
    UserProfileView,
    ForgotPassword,
    ResetPassword,
)

urlpatterns = [
    path('register/', RegisterView.as_view(), name='register'),
    path('login/', LoginView.as_view(), name='login'),
    path('refresh/', RefreshView.as_view(), name='refresh'),
    path('forgot-password/', ForgotPassword.as_view(), name='forgot-password'),
    path('reset-password/<str:uidb64>/<str:token>/', ResetPassword.as_view(), name='reset-password'),
    path('logout/', LogoutView.as_view(), name='logout'),
    path('profile/', UserProfileView.as_view(), name='user-profile'),
]
