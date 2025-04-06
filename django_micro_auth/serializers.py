"""
    contains serializers forserialization and deserialization
    of authentication-related data
"""
from rest_framework import serializers
from django.contrib.auth import get_user_model
from django.db import IntegrityError


UserModel = get_user_model()


class RegisterSerializer(serializers.ModelSerializer):
    """
        used to validate and process data for creating
        a new user instance.
    """

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
        requested_fields = set(self.Meta.fields)

        # Removing fields not present in the custom/default user model
        for field in requested_fields - available_fields:
            self.fields.pop(field, None)

        # Ensure username field is available and required
        username_field = getattr(
            self.Meta.model, 'USERNAME_FIELD', 'username'
        )
        if username_field in available_fields:
            if username_field == 'email':
                self.fields[username_field] = serializers.EmailField(
                    required=True
                )
            else:
                self.fields[username_field] = serializers.CharField(
                    required=True
                )

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
            return UserModel.objects.create_user(**validated_data)

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

        return {
            username_field: data[username_field],
            'password': data['password']
        }
