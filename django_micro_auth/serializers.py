"""
    contains serializers forserialization and deserialization
    of authentication-related data
"""
from django.conf import settings
from django.db import IntegrityError
from rest_framework import serializers
from django.core.mail import send_mail
from django.contrib.auth import authenticate
from django.utils.encoding import force_bytes
from django.contrib.auth import get_user_model
from django.core.exceptions import ImproperlyConfigured
from django.utils.http import (
    urlsafe_base64_encode, urlsafe_base64_decode
)
from django.contrib.auth.tokens import PasswordResetTokenGenerator
from django.urls import reverse


UserModel = get_user_model()


class RegisterSerializer(serializers.ModelSerializer):
    """
        used to validate and process data for creating
        a new user instance.
    """

    email = serializers.EmailField(required=True)

    class Meta:
        """
            used to define the model and fields to be serialized
        """
        model = UserModel
        fields = ['username', 'email', 'password']  # default fields required
        extra_kwargs = {
            'password': {'write_only': True},
        }

    def __init__(self, *args, **kwargs):
        """
            Initialize the serializer.

            Args:
                *args: Variable length argument list.
                **kwargs: Arbitrary keyword arguments.
        """

        super().__init__(*args, **kwargs)

        available_fields = {
            field.name for field in self.Meta.model._meta.fields
        }

        if 'email' not in available_fields:
            raise ImproperlyConfigured(
                'User model must have an email field for verification.'
            )

        # Handling dynamic username_field
        username_field = getattr(
            self.Meta.model, 'USERNAME_FIELD', 'username'
        )
        if username_field != 'email':
            if username_field in available_fields:
                self.fields[username_field] = serializers.CharField(
                    required=True
                )
            else:
                self.fields.pop(username_field, None)

        # Removing fields not present in the custom/default user model
        requested_fields = set(self.Meta.fields) - {'email'}
        for field in requested_fields - available_fields:
            self.fields.pop(field, None)

    def validate(self, data):
        """ ensures valid user registration """
        username_field = getattr(UserModel, 'USERNAME_FIELD', 'username')
        if username_field == 'username':
            user = UserModel.objects.filter(
                username=data.get(username_field)
            )

            if user:
                raise serializers.ValidationError(
                    {'username': f'This username is already taken.'}
                )

        if UserModel.objects.filter(email=data.get('email')):
            raise serializers.ValidationError(
                {'email': 'This email is already taken.'}
            )
        
        return data

    def create(self, validated_data):
        """
        Creates and returns a new instance using the provided validated data.

        Args:
            validated_data (dict): The validated data
            used to create the instance.

        Returns:
            object: The newly created instance.
        """

        try:
            user = UserModel.objects.create_user(
                **validated_data, is_active=False
            )
            # sending verification email
            uidb64 = urlsafe_base64_encode(force_bytes(user.pk))
            token = PasswordResetTokenGenerator().make_token(user)
            verify_url = self.context['request'].build_absolute_uri(
                reverse(
                    'verify-email',
                    kwargs={'uidb64': uidb64, 'token': token}
                )
            )

            send_mail(
                subject="Verify Your Email Address",
                message="Please verify your email by clicking this link: {}".format(
                    verify_url
                ),
                from_email=settings.DEFAULT_FROM_EMAIL,
                recipient_list=[user.email],
            )

            return user

        except IntegrityError as e:
            username_field = getattr(UserModel, 'USERNAME_FIELD', 'username')

            raise serializers.ValidationError({
                username_field: f'This {username_field} is already taken.'
            }) from e


class LoginSerializer(serializers.ModelSerializer):
    """ used to validate login credentials based on the active user model. """

    class Meta:
        model = UserModel
        fields = [getattr(UserModel, 'USERNAME_FIELD', 'username'), 'password']
        extra_kwargs = {
            'password': {'write_only': True},
        }

    def __init__(self, *args, **kwargs):
        """
        Initialize the serializer instance.

        Args:
            *args: Variable length argument list.
            **kwargs: Arbitrary keyword arguments.
        """

        super().__init__(*args, **kwargs)
        username_field = getattr(UserModel, 'USERNAME_FIELD', 'username')

        if username_field == 'email':
            self.fields[username_field] = serializers.EmailField(required=True)
        else:
            self.fields[username_field] = serializers.CharField(required=True)

        self.fields['password'] = serializers.CharField(
            write_only=True, required=True
        )

    def validate(self, data):
        """ validates the provided credetials.

        Args:
            data (dict): The input data
        Returns:
            dict: Validated data ready for authentication
        """

        username_field = getattr(UserModel, 'USERNAME_FIELD', 'username')

        auth_kwargs = {
            username_field: data[username_field],
            'password': data['password']
        }
        user = authenticate(
            request=self.context.get('request'), **auth_kwargs
        )
        if not user:
            raise serializers.ValidationError(
                {'non_field_errors': f'Invalid {username_field} or password.'}
            )
        if not user.is_active:
            raise serializers.ValidationError(
                {'non_field_errors': 'Email address is not verified.'}
            )

        return user


class PasswordChangeSerializer(serializers.Serializer):
    """ used for changing user password """

    old_password = serializers.CharField(write_only=True)
    new_password = serializers.CharField(write_only=True)

    def validate_old_password(self, value):

        if not self.context['request'].user.check_password(value):
            raise serializers.ValidationError('Old password is incorrect.')

        return value

    def validate_new_password(self, value):

        if len(value) < 6:
            raise serializers.ValidationError(
                'Password must be at least 6 characters long.'
            )

        return value


class PasswordResetSerializer(serializers.Serializer):
    email = serializers.EmailField()

    def validate_email(self, value):
        request = self.context.get('request')
        allowed_urls = {reverse('resend_verify_email')}
        user = UserModel.objects.filter(email=value).first()

        if not user:
            raise serializers.ValidationError(
                'No user found with this email address.'
            )

        if not user.is_active and (
            not request or request.path not in allowed_urls):
            raise serializers.ValidationError('Email address is not verified.')
        
        return value


class PasswordResetConfirmSerializer(serializers.Serializer):

    new_password = serializers.CharField(write_only=True)
    uidb64 = serializers.CharField()
    token = serializers.CharField()

    def validate(self, data):

        try:
            uid = urlsafe_base64_decode(data['uidb64']).decode()
            user = get_user_model().objects.get(pk=uid)

        except (ValueError, get_user_model().DoesNotExist):
            raise serializers.ValidationError(
                {'uidb64': 'Invalid user ID.'}
            )
        
        token_genetator = PasswordResetTokenGenerator()
        if not token_genetator.check_token(user, data['token']):
            raise serializers.ValidationError(
                {'token': 'Invalid or expired token.'}
            )
        
        if len(data['new_password']) < 6:
            raise serializers.ValidationError(
                {'new_password': 'Password must be at least 6 characters.'}
            )
        
        return data


class VerifyEmailSerializer(serializers.Serializer):

    uidb64 = serializers.CharField()
    token = serializers.CharField()

    def validate(self, data):
        try:
            uid = urlsafe_base64_decode(data['uidb64']).decode()
            user = get_user_model().objects.filter(pk=uid).first()

        except (ValueError, get_user_model().DoesNotExist):
            raise serializers.ValidationError(
                {'uid64': 'Invalid user ID.'}
            )

        token_generator = PasswordResetTokenGenerator()
        if not token_generator.check_token(user, data['token']):
            raise serializers.ValidationError(
                {'token': 'Invalid or expired token.'}
            )

        if user.is_active:
            raise serializers.ValidationError(
                {'message': 'Email is already verified.'}
            )

        return data
