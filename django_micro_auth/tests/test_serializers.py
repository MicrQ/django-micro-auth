import json
from django.core import mail
from unittest.mock import patch
from django.urls import reverse
from rest_framework import status
from django_micro_auth import MICRO_AUTH_MODE
from django.contrib.auth import get_user_model
from django.test import RequestFactory, TestCase
from rest_framework.test import APITestCase, APIClient
from django_micro_auth.serializers import LoginSerializer, RegisterSerializer


UserModel = get_user_model()


class BaseAuthTestCase(TestCase):

    def setUp(self):
        self.user_data = {
            'username': 'testuser',
            'email': 'test@user.com',
            'password': 'pass@123'
        }

        self.factory = RequestFactory() # for creating moke request

    def create_user(self, **kwargs):
        data = self.user_data.copy()
        data.update(kwargs)

        return UserModel.objects.create_user(**data)


class RegisterSerializerTests(BaseAuthTestCase):
    """ complete test for regiseration serializer """

    def test_register_valid_data(self):
        """ tests user registration with valid data """

        request = self.factory.post(reverse('register'))
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

        request = self.factory.post(reverse('register'))
        data = {'username': 'testuser', 'password': 'pass@123'}
        serializer = RegisterSerializer(
            data=data, context={'request': request}
        )
        self.assertFalse(serializer.is_valid())
        self.assertIn('email', serializer.errors)

    def test_register_duplicated_username(self):
        """ test to check if a user can register with already used username """

        self.create_user()
        request = self.factory.post(reverse('register'))
        serializer = RegisterSerializer(
            data=self.user_data, context={'request': request}
        )
        self.assertFalse(serializer.is_valid())
        self.assertIn('username', serializer.errors)
        self.assertEqual(serializer.errors['username'][0], 'This username is already taken.')

    @patch('django.core.mail.send_mail')
    def test_register_sends_verification_email(self, mock_send_mail):
        """ test to check if verification email is being sent """

        request = self.factory.post(reverse('register'))
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
        self.context = {
            'request': self.factory.post(reverse('login'))
        }

    def test_login_valid_credentials(self):
        """ test to check valid user login attempt """

        serializer = LoginSerializer(data={
            'username': 'testuser',
            'password': 'pass@123'
        }, context=self.context)

        self.assertTrue(serializer.is_valid())
        self.assertEqual(
            serializer.validated_data, self.user
        )

    def test_login_invalid_credentials(self):
        serializer = LoginSerializer(data={
            'username': 'testuser',
            'password': 'wrooooong'
        }, context=self.context)

        self.assertFalse(serializer.is_valid())
        self.assertIn('non_field_errors', serializer.errors)

    def test_login_unverified_user(self):
        """ test to check logging in with unverified email """

        user = UserModel.objects.create_user(
            {
                'username': 'userx',
                'email': 'test@email.com',
                'password': 'pass@123'
            }
        )
        serializer = LoginSerializer(
            data={
                'username': 'userx',
                'password': 'pass@123'
            },
            context={'request': self.context}
        )
        self.assertFalse(serializer.is_valid())
        self.assertIn('non_field_errors', serializer.errors)


class MicroAuthIntegrationTests(APITestCase):
    """ Tests to check the whole authentication process works together """

    def setUp(self):
        self.user_data = {
            'username': 'testuser',
            'email': 'user@email.com',
            'password': 'pass@123'
        }
        self.client = APIClient()
        self.user = UserModel.objects.create_user(
            **self.user_data, is_active=False
        )

    def test_login_unverified_email(self):
        """ test to check unverified email login """

        res = self.client.post(
            reverse('login'), {
                'username': 'testuser',
                'password': 'pass@123'
            }, format='json'
        )
        self.assertEqual(res.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertIn('non_field_errors', res.data)

    def test_login_invalid_credentials(self):
        """ testing with invalid credentials """

        username_field = getattr(
            get_user_model(), 'USERNAME_FIELD', 'username'
        )
        self.user.is_active = True
        self.user.save()
        res = self.client.post(reverse('login'), {
            'username': 'testuser',
            'password': 'wrongpass'
        }, format='json')

        self.assertEqual(res.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertIn('non_field_errors', res.data)
        self.assertEqual(
            res.data['non_field_errors'][0],
            f'Invalid {username_field} or password.'
        )
