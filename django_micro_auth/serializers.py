"""
    contains serializers forserialization and deserialization
    of authentication-related data
"""
from rest_framework import serializers
from django.contrib.auth import get_user_model
from django.db import IntegrityError


class RegisterSerializer(serializers.ModelSerializer):
    """
        used to validate and process data for creating
        a new user instance.
    """

    class Meta:
        """
            used to define the model and fields to be serialized
        """
        model = get_user_model()
        fields = ['username', 'email', 'password']  # default fields required
        extra_kwargs = {
            'password': {'write_only': True},
        }

    def __init__(self, *args, **kwargs):
        """
            Initialize the serializer with optional field filtering.

            Args:
                *args: Variable length argument list.
                fields (list, optional): List of fields to include.
                Defaults to None.

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
        username_field = getattr(self.Meta.model, 'USERNAME_FIELD', 'username')
        if username_field in available_fields:
            self.fields[username_field] = serializers.CharField(required=True)

    def create(self, validated_data):
        """
        Creates and returns a new instance using the provided validated data.

        Args:
            validated_data (dict): The validated data
            used to create the instance.

        Returns:
            object: The newly created instance.
        """

        UserModel = get_user_model()

        try:
            return UserModel.objects.create_user(**validated_data)

        except IntegrityError as e:
            username_field = getattr(UserModel, 'USERNAME_FIELD', 'username')

            raise serializers.ValidationError({
                username_field: f'This {username_field} is already taken.'
            }) from e
