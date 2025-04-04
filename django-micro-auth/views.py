""" contains the views for the django-micro-auth application """
from rest_framework import status
from rest_framework.views import APIView
from .serializers import RegisterSerializer
from rest_framework.response import Response
from drf_spectacular.utils import extend_schema
from django.contrib.auth import authenticate, login, logout


class RegisterAPIView(APIView):
    """ API view for handling user registration """

    @extend_schema(
        request=RegisterSerializer,
        responses={
            201: "User created successfully.",
            400: "[ Validation Error ]",
        }
    )
    def post(self, request):
        """ Handle HTTP POST requests for user registration """

        serializer = RegisterSerializer(data=request.data)
        if serializer.is_valid():
            serializer.save()
            return Response({"message": "User created successfully."},
                            status=status.HTTP_201_CREATED)

        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
