"""
    contains serializers forserialization and deserialization
    of authentication-related data
"""
from rest_framework import serializers
from django.contrib.auth import get_user_model


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
        extra_fields = {'password': {'write_only': True}}

    def __init__(self, *args, fields=None, **kwargs):
        """
            Initialize the serializer with optional field filtering.

            Args:
                *args: Variable length argument list.
                fields (list, optional): List of fields to include.
                Defaults to None.

                **kwargs: Arbitrary keyword arguments.
        """

        super().__init__(*args, **kwargs)

        if fields is not None:
            self.Meta.fields = fields  # if user gave the fields explicitly

        else:
            #  filtering fields to those available in the model
            model_fields = {
                field.name for field in self.Meta.model._meta.fields
            }
            self.Meta.fields = [
                field for field in self.Meta.fields if field in model_fields
            ]

        # regenerating self.fields based on the updated Meta.fields
        self.fields = self.get_fields()

    def validate(self, data):
        """
            Used to perform validation logic on the input data.

            Args:
                data (dict): The input data to validate.

            Returns:
                dict: The validated data.

            Raises:
                ValidationError: If the validation fails.
        """

        UserModel = get_user_model()
        username_field = UserModel.USERNAME_FIELD

        if username_field not in data:
            raise serializers.ValidationError(f'{username_field} is required!')

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

        UserModel = get_user_model()

        return UserModel.objects.create_user(**validated_data)
