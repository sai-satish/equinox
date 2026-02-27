from rest_framework.response import Response
from rest_framework.views import APIView
from rest_framework import status, permissions
from rest_framework_simplejwt.tokens import RefreshToken
from rest_framework_simplejwt.exceptions import TokenError
from django.contrib.auth import authenticate
from django.contrib.auth.signals import user_logged_in
from django.contrib.auth.tokens import PasswordResetTokenGenerator
from django.core.exceptions import ValidationError
from django.db import transaction
from django.utils.http import urlsafe_base64_encode, urlsafe_base64_decode
from django.utils.encoding import force_bytes
import logging
from authentication.forms import LoginForm
from django.contrib.auth.forms import SetPasswordForm
from utils.execption_utils import extract_execption_string
from django.contrib.auth.hashers import check_password


from authentication.models import (
    AuthUser,
    UserProfile,
    UserPasswordHistory
)

from authentication.serializers import (
    UserRegistrationSerializer,
    UserProfileSerializer,
    ExecutiveRegistrationSerializer,
)
import constants.loggers

logger = logging.getLogger(constants.loggers.AUTH_LOGGER)


class RegisterView(APIView):
    permission_classes = [permissions.AllowAny]

    def post(self, request):
        registration_type = request.data.get("registration_type", "employee").lower()

        try:
            with transaction.atomic():
                if registration_type == "employee":
                    # Employee Registration: Only link to a tenant
                    serializer = UserRegistrationSerializer(data=request.data)
                    if serializer.is_valid():
                        user, user_profile = serializer.save()
                        # Profile is usually created via signals, but can be done here
                        logger.info(
                            f"Employee-{user_profile.first_name} {user_profile.last_name} created successfully"
                        )
                        return Response(
                            {
                                "message": "Employee created successfully",
                                "user_id": user.id,
                            },
                            status=status.HTTP_201_CREATED,
                        )
                    return Response(
                        serializer.errors, status=status.HTTP_400_BAD_REQUEST
                    )

                elif registration_type == "executive":
                    # Executive Registration: Create organization and link
                    serializer = ExecutiveRegistrationSerializer(data=request.data)
                    if serializer.is_valid():
                        user, user_profile, organization = serializer.save()

                        logger.info(
                            f"Executive (CEO)-{user_profile.first_name} {user_profile.last_name} and Organization-{organization.organization_name} created successfully"
                        )
                        return Response(
                            {
                                "message": "Executive (CEO) and Organization created successfully",
                                "user_id": user.id,
                                "organization_id": organization.id,
                            },
                            status=status.HTTP_201_CREATED,
                        )
                    return Response(
                        serializer.errors, status=status.HTTP_400_BAD_REQUEST
                    )

                else:
                    logger.error(f"Registration failed - Invalid registration type")
                    return Response(
                        {"error": "Invalid registration type"},
                        status=status.HTTP_400_BAD_REQUEST,
                    )

        except Exception as e:
            logger.error(f"Registration failed: {str(e)}")
            try:
                error_message, error_code = extract_execption_string(str(e))

                return Response(
                    {"error": error_message, "code": error_code},
                    status=status.HTTP_500_INTERNAL_SERVER_ERROR,
                )
            except Exception:
                return Response(
                    {"error": str(e)},
                    status=status.HTTP_500_INTERNAL_SERVER_ERROR,
                )


class LoginView(APIView):
    permission_classes = [permissions.AllowAny]

    def post(self, request):
        form = LoginForm(request.data)
        if not form.is_valid():
            return Response({"errors": form.errors}, status=status.HTTP_400_BAD_REQUEST)

        email = form.cleaned_data["email"]
        password = form.cleaned_data["password"]

        try:
            user = authenticate(request, email=email, password=password)

            if user:
                # Logging to LoginLog Model via authentication success signal
                user_logged_in.send(sender=user.__class__, request=request, user=user)

                refresh = RefreshToken.for_user(user)

                logger.info(f"Logged successfully as: {email}")
                return Response(
                    {
                        "refresh": str(refresh),
                        "access": str(refresh.access_token),
                    },
                    status=status.HTTP_202_ACCEPTED,
                )

            # Logging to LoginLog Model via authentication failure signal
            # user_login_failed signal is automatically fired by authenticate()
            logger.warning(f"Failed login attempt for {email}")
            return Response(
                {"error": "Invalid credentials"},
                status=status.HTTP_401_UNAUTHORIZED,
            )

        except Exception as e:
            logger.error(f"Login Error for {email}: {str(e)}")
            return Response(
                {"error": "An error occurred during login"},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR,
            )


class LogoutView(APIView):
    permission_classes = [permissions.IsAuthenticated]

    def post(self, request):
        try:
            refresh_token = request.data.get("refresh")
            if not refresh_token:
                return Response(
                    {"error": "Refresh token is required"},
                    status=status.HTTP_400_BAD_REQUEST,
                )
            token = RefreshToken(refresh_token)
            token.blacklist()
            logger.info(f"User {request.user.email} logged out successfully")

            return Response(
                {"message": "Logged out successfully"},
                status=status.HTTP_205_RESET_CONTENT,
            )

        except TokenError as e:
            logger.warning(f"Logout failed for {request.user.email}: {str(e)}")
            return Response(
                {"error": "Invalid or expired token"},
                status=status.HTTP_400_BAD_REQUEST,
            )


class RefreshView(APIView):
    permission_classes = [permissions.AllowAny]
    authentication_classes = []

    def post(self, request):
        refresh_token = request.data.get("refresh")
        if not refresh_token:
            return Response(
                {"error": "Refresh token required"},
                status=status.HTTP_400_BAD_REQUEST,
            )

        try:
            refresh = RefreshToken(refresh_token)
            user_id = refresh.payload["user_id"]
            logger.info(f"Refresh token generated successfully for user: {user_id}")
            return Response(
                {
                    "access": str(refresh.access_token),
                },
                status=status.HTTP_200_OK,
            )
        except TokenError as e:
            logger.warning(f"Refresh token invalid/expired: {str(e)}")
            return Response(
                {
                    "error": "Refresh token is invalid or expired",
                    "detail": str(e),
                },
                status=status.HTTP_401_UNAUTHORIZED,
            )


class UserProfileView(APIView):
    permission_classes = [permissions.IsAuthenticated]

    def get(self, request):
        try:
            # AuditModel Manager automatically filters out deleted profiles
            profile = request.user.profile
            serializer = UserProfileSerializer(profile)
            return Response(
                serializer.data,
                status=status.HTTP_200_OK,
            )
        except UserProfile.DoesNotExist:
            logger.warning(f"Profile not found for user {request.user.id}")
            return Response(
                {"error": "Profile not found"},
                status=status.HTTP_404_NOT_FOUND,
            )

    def patch(self, request):
        try:
            profile = request.user.profile
            serializer = UserProfileSerializer(profile, data=request.data, partial=True)
            if serializer.is_valid():
                serializer.save()

                logger.info(f"Profile updated for user {request.user.id}")
                return Response(
                    serializer.data,
                    status=status.HTTP_200_OK,
                )

            logger.warning(
                f"Invalid profile data for user {request.user.id}: {serializer.errors}"
            )
            return Response(
                serializer.errors,
                status=status.HTTP_400_BAD_REQUEST,
            )

        except Exception as e:
            logger.error(f"Profile update error for {request.user.id}: {str(e)}")
            return Response(
                {"error": "Profile update failed"},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR,
            )


class ForgotPassword(APIView):
    permission_classes = [permissions.AllowAny]

    def post(self, request):
        email = request.data.get("email")
        if not email:
            logger.warning("Reset password request failed - no email provided")
            return Response(
                {"error": "Email is required"},
                status=status.HTTP_400_BAD_REQUEST,
            )

        try:
            user = AuthUser.objects.filter(email=email).first()
            if not user:
                logger.warning(
                    f"Password reset request failed - user with email {email} not found"
                )
                return Response(
                    {"error": "User with this email not found"},
                    status=status.HTTP_404_NOT_FOUND,
                )

            # Generate reset token
            token_generator = PasswordResetTokenGenerator()
            token = token_generator.make_token(user)
            uid = urlsafe_base64_encode(force_bytes(user.pk))

            reset_url = (
                f"{request.build_absolute_uri('/auth/reset-password/')}{uid}/{token}/"
            )

            # add logic for sending reset link via email

            logger.info(f"Password reset link sent to {email}")

            return Response(
                {
                    "message": "Password reset email sent successfully",
                    "reset_url": reset_url,
                },
                status=status.HTTP_200_OK,
            )

        except Exception as e:
            logger.error(f"Error sending password reset for {email}: {str(e)}")
            return Response(
                {"error": "An error occurred while processing your request"},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR,
            )


class ResetPassword(APIView):
    permission_classes = [permissions.AllowAny]

    # Handle clicking on the reset password link and validating the token
    def get(self, request, uidb64, token):
        try:
            # Decode the user ID from the URL (UID is encoded in base64)
            uid = urlsafe_base64_decode(uidb64).decode()
            user = AuthUser.objects.get(pk=uid)

            # Verify the reset token
            token_generator = PasswordResetTokenGenerator()
            if not token_generator.check_token(user, token):
                logger.warning(f"Invalid or expired reset token for user {user.email}")
                return Response(
                    {"error": "Invalid or expired token"},
                    status=status.HTTP_400_BAD_REQUEST,
                )

            logger.info(
                f"Password Reset Token validated for user {user.email}. Waiting for new password"
            )
            return Response(
                {"message": "Please provide your new password"},
                status=status.HTTP_200_OK,
            )

        except (ValidationError, TypeError, ValueError, AuthUser.DoesNotExist):
            return Response(
                {"error": "Invalid token or user ID"},
                status=status.HTTP_400_BAD_REQUEST,
            )

    # Handle password reset submission
    def post(self, request, uidb64, token):
        try:
            # Decode user ID from URL
            uid = urlsafe_base64_decode(uidb64).decode()
            user = AuthUser.objects.get(pk=uid)

            # Check token validity
            with transaction.atomic():
                token_generator = PasswordResetTokenGenerator()
                if not token_generator.check_token(user, token):
                    logger.warning(f"Invalid or expired reset token for user {user.email}")
                    return Response(
                        {"error": "Invalid or expired token"},
                        status=status.HTTP_400_BAD_REQUEST,
                    )

                # Create a SetPasswordForm to handle new password
                form = SetPasswordForm(user, request.data)
                if form.is_valid():
                    new_password = form.cleaned_data['new_password1']
                    if self._is_password_in_history(user, new_password):
                        logger.warning(f"User {user.email} attempted to reset to a previously used password")
                        return Response(
                            {"error": "The new password cannot be the same as one of the previous 3 passwords"},
                            status=status.HTTP_400_BAD_REQUEST,
                        )
                    logger.info(f"Password reset successfully reset for user {user.email}")
                    form.save()
                    raise TypeError("type error for testing")
                    self._log_password_history(user)
                    return Response(
                        {"message": "Password reset successfully"},
                        status=status.HTTP_200_OK,
                    )
                else:
                    logger.warning(
                        f"Error resetting password for user {user.email}: {form.errors}"
                    )
                    return Response(
                        {"error": "Password reset form is invalid", "details": form.errors},
                        status=status.HTTP_400_BAD_REQUEST,
                    )

        except (TypeError, ValueError, AuthUser.DoesNotExist) as e:
            logger.error(f"Error during password reset submission: {str(e)}")
            return Response(
                {"error": "Invalid token or user ID"},
                status=status.HTTP_400_BAD_REQUEST,
            )

    def _is_password_in_history(self, user, new_password):
        """Check if the new password matches any of the last 3 passwords"""
        recent_passwords = UserPasswordHistory.objects.filter(user=user).order_by('-created_at')[:3]
        for entry in recent_passwords:
            if check_password(new_password, entry.password_hash):
                return True
        return False

    def _log_password_history(self, user):
        """Store the new password hash in the password history table"""
        
        UserPasswordHistory.objects.create(
            user=user,
            password_hash=user.password,
        )