""" contains the views for the django-micro-auth application """
from rest_framework import status
from rest_framework.views import APIView
from rest_framework.response import Response
from django_micro_auth import MICRO_AUTH_MODE
from django.contrib.auth import get_user_model
from rest_framework.permissions import AllowAny
from django.contrib.auth import authenticate, login, logout
from .serializers import RegisterSerializer, LoginSerializer
from drf_spectacular.utils import extend_schema, OpenApiResponse


# importing Token if token auth is enabled
if MICRO_AUTH_MODE == 'token':
    from rest_framework.authtoken.models import Token


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
                        'username': {'type': 'string',
                                     'example': 'This username \
                                        is already taken.'},
                        'email': {'type': 'string',
                                  'example': 'This email is already taken.'},
                        'password': {'type': 'string',
                                     'example': 'This field is required.'},
                    },
                    'additionalProperties': True
                },
                description="Invalid inputs or malformed data."
            )
        },
        description="Handles user registration."
    )
    def post(self, request):
        """ Handles HTTP POST requests for user registration """

        serializer = RegisterSerializer(data=request.data)
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
