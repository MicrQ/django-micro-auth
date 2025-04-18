""" contains the views for the django-micro-auth application """
from django.conf import settings
from django.urls import reverse
from rest_framework import status
from django.core.mail import send_mail
from rest_framework.views import APIView
from rest_framework.response import Response
from django.utils.encoding import force_bytes
from django_micro_auth import MICRO_AUTH_MODE
from django.contrib.auth import get_user_model
from rest_framework.permissions import IsAuthenticated
from django.core.exceptions import ImproperlyConfigured
from django.contrib.auth import authenticate, login, logout
from .serializers import (
    PasswordChangeSerializer,
    PasswordResetSerializer,
    RegisterSerializer,
    LoginSerializer
)
from drf_spectacular.utils import extend_schema, OpenApiResponse
from rest_framework.authentication import (
    TokenAuthentication, SessionAuthentication
)
from django.contrib.auth.tokens import PasswordResetTokenGenerator
from django.utils.http import urlsafe_base64_decode, urlsafe_base64_encode


# importing Token if token auth is enabled
if MICRO_AUTH_MODE == 'token':
    try:
        from rest_framework.authtoken.models import Token
    except ImportError:
        Token = None


class RegisterAPIView(APIView):
    """ API view for handling user registration """

    authentication_classes = []

    @extend_schema(
        request=RegisterSerializer,
        responses={
            201: RegisterSerializer,
            400: OpenApiResponse(
                response={
                    'type': 'object',
                    'properties': {
                        'username': {
                            'type': 'string',
                            'example': 'This username is required/taken.'
                        },
                        'email': {'type': 'string',
                                  'example': 'This email is required/taken.'},
                        'password': {'type': 'string',
                                     'example': 'This field is required.'},
                    },
                    'additionalProperties': True
                },
                description="Invalid inputs or malformed data."
            )
        },
        description="Handles user registration. Email is required to verify."
    )
    def post(self, request):
        """ Handles HTTP POST requests for user registration """

        serializer = RegisterSerializer(
            data=request.data, context={'request': request}
        )
        if serializer.is_valid():
            serializer.save()
            return Response(serializer.data,
                            status=status.HTTP_201_CREATED)

        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


class LoginAPIView(APIView):
    """ API View for handling user login """

    authentication_classes = []

    @extend_schema(
        request=LoginSerializer,
        responses={
            200: LoginSerializer,
            400: OpenApiResponse(
                response={
                    'type': 'object',
                    'properties': {
                        'error': {
                            'type': 'string',
                            'example': 'Invalid username or password'
                        },
                        'password': {
                            'type': 'string',
                            'example': 'This field is required.'
                        },
                        'username': {
                            'type': 'string',
                            'example': 'This field is required.'
                        },
                    },
                    'additionalProperties': True
                },
                description="Invalid credentials or malformed request."
            ),
        },
        description="Authenticate a user and start \
            a session or return a token."
    )
    def post(self, request):
        """ Handles HTTP POST request for user login """

        serializer = LoginSerializer(data=request.data)

        if serializer.is_valid():
            UserModel = get_user_model()
            username_field = getattr(UserModel, 'USERNAME_FIELD', 'username')

            auth_kwargs = {
                username_field: serializer.validated_data[username_field],
                'password': serializer.validated_data['password']
            }

            user = authenticate(request=request, **auth_kwargs)
            if user:
                response = {"message": "Logged in successfully."}

                if MICRO_AUTH_MODE == 'token':
                    """ for token based authentications """

                    token, created = Token.objects.get_or_create(user=user)
                    response['micro-auth-token'] = token.key

                else:
                    """ for session based auth """
                    login(request, user)

                return Response(
                    response,
                    status=status.HTTP_200_OK
                )

            return Response(
                {"error": f"Invalid {username_field} or password."},
                status=status.HTTP_400_BAD_REQUEST
            )

        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


class LogoutAPIView(APIView):
    """ API view for handling user logout """

    permission_classes = [IsAuthenticated]

    if MICRO_AUTH_MODE == 'token':
        from rest_framework.authentication import TokenAuthentication
        authentication_classes = [TokenAuthentication]

    else:
        authentication_classes = []

    @extend_schema(
        request=None,
        responses={
            200: OpenApiResponse(
                response={
                    'type': 'object',
                    'properties': {
                        'message': {'type': 'string',
                                    'example': 'Logged out successfully'}
                    }
                },
                description="Logout successful,\
                      session ended or token deleted."
            ),
            401: OpenApiResponse(
                response={
                    'type': 'object',
                    'properties': {
                        'detail': {
                            'type': 'string',
                            'example': 'Authentication credentials were not provided.'
                        }
                    }
                },
                description="User is not authenticated."
            )
        },
        description="Log out the current user,\
              ending the session or deleting the token."
    )
    def post(self, request):
        """ Handles HTTP POST requests for user logout """

        if MICRO_AUTH_MODE == 'token':
            if Token is None:
                raise ImproperlyConfigured(
                    "Token authentication requires \
                        'rest_framework.authtoken' in INSTALLED_APPS."
                )

            # deleting user's token
            Token.objects.filter(user=request.user).delete()

        else:
            # ending session if session is used
            logout(request)

        return Response(
            {'message': 'Logged out successfully.'},
            status=status.HTTP_200_OK
        )


class PasswordChangeAPIView(APIView):
    """ Used for user password changing """

    permission_classes = [IsAuthenticated]
    if MICRO_AUTH_MODE == 'token':
        authentication_classes = [TokenAuthentication]
    else:
        authentication_classes = [SessionAuthentication]

    @extend_schema(
        request=PasswordChangeSerializer,
        responses={
            200: OpenApiResponse(
                response={
                    'type': 'object',
                    'properties': {
                        'message': {
                            'type': 'string',
                            'example': 'Password changed successfully.'
                        }
                    }
                }
            ),
            400: OpenApiResponse(
                response={
                    'type': 'object',
                    'properties': {
                        'old_password': {
                            'type': 'string',
                            'example': 'Old password is incorrect.'
                        },
                        'new_password': {
                            'type': 'string',
                            'example': 'Password must be at least 8 characters long.'
                        }
                    }
                }
            ),
            401: OpenApiResponse(
                response={
                    'type': 'object',
                    'properties': {
                        'detail': {
                            'type': 'string',
                            'example': 'Authentication credentials were not provided.'
                        }
                    }
                }
            )
        }
    )
    def post(self, request):
        """ Used to help user change password """

        serializer = PasswordChangeSerializer(
            data=request.data, context={'request': request})
        
        if serializer.is_valid():
            request.user.set_password(
                serializer.validated_data['new_password']
            )
            request.user.save()

            return Response(
                {'message': 'Password changed successfully.'},
                status=status.HTTP_200_OK
            )

        return Response(
            serializer.errors,
            status=status.HTTP_400_BAD_REQUEST
        )


class PasswordResetAPIView(APIView):
    permission_classes = []
    authentication_classes = []

    @extend_schema(
        request=PasswordResetSerializer,
        responses={
            200: OpenApiResponse(
                response={
                    'type': 'object',
                    'properties': {
                        'message': {
                            'type': 'string',
                            'example': 'Password reset email sent.'
                        }
                    }
                }
            ),
            400: OpenApiResponse(
                response={
                    'type': 'object',
                    'properties': {
                        'email': {
                            'type': 'string',
                            'example': 'No user found with this email address.'
                        }
                    }
                }
            )
        }
    )
    def post(self, request):
        serializer = PasswordResetSerializer(data=request.data)
        if serializer.is_valid():

            user = get_user_model().objects.get(
                email=serializer.validated_data['email']
            )
            uidb64 = urlsafe_base64_encode(force_bytes(user.pk))
            token = PasswordResetTokenGenerator().make_token(user)
            reset_url = self.context['request'].build_absolute_uri(
                reverse(
                    'verify-email',
                    kwargs={'uidb64': uidb64, 'token': token}
                )
            )

            send_mail(
                subject='Password Reset Request',
                message=f'Click this link to reset your password: {reset_url}',
                from_email=settings.DEFAULT_FROM_EMAIL,
                recipient_list=[user.email],
            )

            return Response(
                {'message': 'Password reset email sent.'},
                status=status.HTTP_200_OK
            )
        
        return  Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
