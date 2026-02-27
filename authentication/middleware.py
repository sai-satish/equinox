from rest_framework.authentication import get_authorization_header
from rest_framework.exceptions import AuthenticationFailed
from rest_framework_simplejwt.tokens import AccessToken, RefreshToken
from rest_framework_simplejwt.exceptions import TokenError, ExpiredTokenError
from django.contrib.auth.models import AnonymousUser
from authentication.models import AuthUser
import logging
import constants.loggers
logger = logging.getLogger(constants.loggers.AUTH_LOGGER)

class UserIdentificationMiddleware:
    """
    Middleware to identify the user based on the JWT token in Authorization header.
    This assumes that tokens are passed via 'Authorization: Bearer <token>'
    """

    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        # Get Authorization Header (Usually in the format: Bearer <token>)
        self.process_request(request)

        response = self.get_response(request)
        return response
    
    def process_request(self, request):
        auth_header = get_authorization_header(request).decode("utf-8")
        
        if auth_header and auth_header.startswith("Bearer "):
            try:
                # Extract token from "Bearer <token>"
                token = auth_header.split(' ')[1]
                
                access_token = AccessToken(token)
                user_id = access_token.payload["user_id"]
                user = AuthUser.objects.get(id=user_id)
                request.user = user


            except (ExpiredTokenError, TokenError):
                request.user = AnonymousUser()
            except IndexError:
                request.user = AnonymousUser()
                # raise AuthenticationFailed("Token prefix is missing or incorrect")
            except (AuthenticationFailed, AuthUser.DoesNotExist):
                request.user = AnonymousUser()
                # raise AuthenticationFailed("Token is invalid or expired")

        else:
            # Attach anonymous user if no token found
            logger.warning("Authorization header is missing or not a valid Bearer token")
            request.user = AnonymousUser()