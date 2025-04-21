import json
from django.core import mail
from unittest.mock import patch
from rest_framework.test import APIClient
from django_micro_auth import MICRO_AUTH_MODE
from django.contrib.auth import get_user_model
from django.test import RequestFactory, TestCase
from django_micro_auth.serializers import LoginSerializer, RegisterSerializer


UserModel = get_user_model()


class BaseAuthTestCase(TestCase):

    def setUp(self):
        self.user_data = {
            'username': 'testuser',
            'email': 'test@user.com',
            'password': 'pass@123'
        }

        self.client = APIClient()
        self.factory = RequestFactory() # for creating moke request

    def create_user(self, **kwargs):
        data = self.user_data.copy()
        data.update(kwargs)

        return UserModel.objects.create_user(**data)


class RegisterSerializerTests(BaseAuthTestCase):
    """ complete test for regiseration serializer """

    def test_register_valid_data(self):
        """ tests user registration with valid data """

        request = self.factory.post('auth/register/')
        serializer = RegisterSerializer(
            data=self.user_data, context={'request': request}
        )
        self.assertTrue(serializer.is_valid())
        user = serializer.save()

        self.assertEqual(user.username, 'testuser')
        self.assertEqual(user.email, 'test@user.com')
        self.assertFalse(user.is_active)  # Should be unverified
        self.assertTrue(user.check_password('pass@123'))

    def test_register_missing_email(self):
        """ test to check if a user can register without email """

        request = self.factory.post('auth/register/')
        data = {'username': 'testuser', 'password': 'pass@123'}
        serializer = RegisterSerializer(
            data=data, context={'request': request}
        )
        self.assertFalse(serializer.is_valid())
        self.assertIn('email', serializer.errors)

    def test_register_duplicated_username(self):
        """ test to check if a user can register with already used username """

        self.create_user()
        request = self.factory.post('auth/register/')
        serializer = RegisterSerializer(
            data=self.user_data, context={'request': request}
        )
        self.assertFalse(serializer.is_valid())
        self.assertIn('username', serializer.errors)
        self.assertEqual(serializer.errors['username'][0], 'This username is already taken.')

    @patch('django.core.mail.send_mail')
    def test_register_sends_verification_email(self, mock_send_mail):
        """ test to check if verification email is being sent """

        request = self.factory.post('auth/register/')
        serializer = RegisterSerializer(
            data=self.user_data, context={'request': request}
        )
        self.assertTrue(serializer.is_valid())
        serializer.save()

        self.assertEqual(len(mail.outbox), 1)
        self.assertEqual(mail.outbox[0].subject, 'Verify Your Email Address')


class LoginSerializerTests(BaseAuthTestCase):
    """ Login functionality tests """

    def setUp(self):
        super().setUp()
        self.user = self.create_user(is_active=True) # Verified user for test
        self.context = {'request': self.factory.post('auth/login/')}

    def test_login_valid_credentials(self):
        """ test to check valid user login attempt """

        serializer = LoginSerializer(data={
            'username': 'testuser',
            'password': 'pass@123'
        }, context=self.context)

        self.assertTrue(serializer.is_valid())
        self.assertEqual(
            serializer.validated_data['username'], 'testuser'
        )

    def test_login_invalid_credentials(self):
        serializer = LoginSerializer(data={
            'username': 'testuser',
            'password': 'wrooooong'
        }, context=self.context)

        self.assertFalse(serializer.is_valid())
        self.assertIn('non_field_errors', serializer.errors)
