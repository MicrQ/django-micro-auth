""" contains the views for the django-micro-auth application """
from rest_framework import status
from rest_framework.views import APIView
from .serializers import RegisterSerializer
from rest_framework.response import Response
from drf_spectacular.utils import extend_schema
from rest_framework.permissions import AllowAny
from django.contrib.auth import authenticate, login, logout


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
