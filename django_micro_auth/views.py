""" contains the views for the django-micro-auth application """
from rest_framework import status
from rest_framework.views import APIView
from rest_framework.response import Response
from django.contrib.auth import get_user_model
from drf_spectacular.utils import extend_schema
from django.contrib.auth import authenticate, login, logout
from .serializers import RegisterSerializer, LoginSerializer


class RegisterAPIView(APIView):
    """ API view for handling user registration """

    authentication_classes = []

    @extend_schema(
        request=RegisterSerializer,
        responses={
            201: RegisterSerializer,
            400: RegisterSerializer
        }
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
    permission_classes = []

    @extend_schema(
        request=LoginSerializer,
        responses={
            200: "Logged in successfully.",
            400: "Invalid credentials or maformed request.",
        },
        description="Authenticate a user and start a session."
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
                login(request, user)

                return Response(
                    {"message": "Logged in successfully."},
                    status=status.HTTP_200_OK
                )

            return Response(
                {"error": f"Invalid {username_field} or password."},
                status=status.HTTP_400_BAD_REQUEST
            )

        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
