import json
from django.core import mail
from unittest.mock import patch
from django.urls import reverse
from rest_framework import status
from django.utils.encoding import force_bytes
from django_micro_auth import MICRO_AUTH_MODE
from django.contrib.auth import get_user_model
from django.test import RequestFactory, TestCase
from django.utils.http import (
    urlsafe_base64_decode, urlsafe_base64_encode
)
from rest_framework.test import APITestCase, APIClient
from django_micro_auth.serializers import (
    LoginSerializer,
    PasswordResetConfirmSerializer,
    RegisterSerializer,
    PasswordResetSerializer,
    PasswordChangeSerializer,
    VerifyEmailSerializer,
)
from django.contrib.auth.tokens import PasswordResetTokenGenerator


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


class PasswordChangeSerializerTests(BaseAuthTestCase):
    """ tests for password changing functionality """

    def setUp(self):
        super().setUp()
        self.user = self.create_user(is_active=True)

    def test_password_change_valid(self):
        """ test changing password """
        serializer = PasswordChangeSerializer(
            data={
                'old_password': 'pass@123',
                'new_password': 'new@123'
            }, context={'request': type('Request', (), {'user': self.user})}
        )
        self.assertTrue(serializer.is_valid())
        self.assertEqual(
            serializer.validated_data['new_password'], 'new@123'
        )

    def test_password_change_invalid(self):
        """ test changing password with invalid old password """
        serializer = PasswordChangeSerializer(
            data={
                'old_password': 'wongpass',
                'new_password': 'new@123'
            }, context={'request': type('Request', (), {'user': self.user})}
        )
        self.assertFalse(serializer.is_valid())
        self.assertIn('old_password', serializer.errors)


class PasswordResetSerializerTests(BaseAuthTestCase):
    """ tests for password resetting functionality """

    def setUp(self):
        super().setUp()
        self.user = self.create_user(is_active=True)

    def test_password_reset_valid_email(self):
        """ test changing passeword for valid account """
        serializer = PasswordResetSerializer(data={'email': 'test@user.com'})
        self.assertTrue(serializer.is_valid())
        self.assertEqual(serializer.validated_data['email'], 'test@user.com')

    def test_password_reset_nonexistent_email(self):
        """ test for invalid or unknown account/email """
        serializer = PasswordResetSerializer(data={'email': 'fake@email.com'})
        self.assertFalse(serializer.is_valid())
        self.assertIn('email', serializer.errors)

    def test_password_reset_unverified_user(self):
        """ test to check if unverified user can reset their password """

        self.user_data['email'] = 'new@user.com'
        self.user_data['username'] = 'testuser1'
        self.user = self.create_user(is_active=False)
        serializer = PasswordResetSerializer(data={'email': 'new@user.com'})
        self.assertFalse(serializer.is_valid())
        self.assertIn('email', serializer.errors)
        self.assertEqual(serializer.errors['email'][0], 'Email address is not verified.')


class PasswordResetConfirmSerializerTests(BaseAuthTestCase):
    """ tests to check functionality of resetting password """
    def setUp(self):
        super().setUp()
        self.user = self.create_user(is_active=True)
        self.uidb64 = urlsafe_base64_encode(force_bytes(self.user.pk))
        self.token = PasswordResetTokenGenerator().make_token(self.user)

    def test_confirm_valid(self):
        """ test with valid data """
        serializer = PasswordResetConfirmSerializer(data={
            'uidb64': self.uidb64,
            'token': self.token,
            'new_password': 'new@123'
        })
        self.assertTrue(serializer.is_valid())
        self.assertEqual(serializer.validated_data['new_password'], 'new@123')

    def test_confirm_invalid_uidb64(self):
        """ test with invalid uidb64 """
        serializer = PasswordResetConfirmSerializer(data={
            'uidb64': 'invalid',
            'token': self.token,
            'new_password': 'new@pass'
        })
        self.assertFalse(serializer.is_valid())
        self.assertIn('uidb64', serializer.errors)

    def test_confirm_invalid_token(self):
        """ test with invalid token """
        serializer = PasswordResetConfirmSerializer(data={
            'uidb64': self.uidb64,
            'token': 'invalid-token',
            'new_password': 'new@123'
        })
        self.assertFalse(serializer.is_valid())
        self.assertIn('token', serializer.errors)


class VerifyEmailSerializerTests(BaseAuthTestCase):
    def setUp(self):
        super().setUp()
        self.user = self.create_user(is_active=False)
        self.uidb64 = urlsafe_base64_encode(force_bytes(self.user.pk))
        self.token = PasswordResetTokenGenerator().make_token(self.user)

    def test_verify_valid(self):
        serializer = VerifyEmailSerializer(data={
            'uidb64': self.uidb64,
            'token': self.token
        })
        self.assertTrue(serializer.is_valid())

    def test_verify_already_verified(self):
        self.user.is_active = True
        self.user.save()
        serializer = VerifyEmailSerializer(data={
            'uidb64': self.uidb64,
            'token': self.token
        })
        self.assertFalse(serializer.is_valid())
        self.assertIn('message', serializer.errors)


class MicroAuthIntegrationTests(APITestCase):
    """ Tests to check the whole authentication process works together """

    def setUp(self):
        self.user_data = {
            'username': 'testuser',
            'email': 'test@user.com',
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

    def test_login_verified_user_token(self):
        """ test to check if a token is in the response body """
        with self.settings(MICRO_AUTH_MODE='token'):
            self.user.is_active = True
            self.user.save()
            response = self.client.post(reverse('login'), {
                'username': 'testuser',
                'password': 'pass@123'
            }, format='json')
            self.assertEqual(response.status_code, status.HTTP_200_OK)
            self.assertEqual(response.data['message'], 'Logged in successfully.')
            self.assertIn('micro-auth-token', response.data)

    def test_logout_session(self):
        """ test logging out """

        self.user.is_active = True
        self.user.save()
        token = self.client.post(
            reverse('login'),
            {
                'username': 'testuser',
                'password': 'pass@123'
            }, format='json'
        ).data['micro-auth-token']

        self.client.credentials(HTTP_AUTHORIZATION=f'Token {token}')
        res = self.client.post(reverse('logout'))
        self.assertEqual(res.status_code, status.HTTP_200_OK)
        self.assertEqual(res.data['message'], 'Logged out successfully.')

    def test_logout_unauthenticated(self):
        """ test: trying to log out without logging in """
        response = self.client.post(reverse('logout'), format='json')
        self.assertEqual(response.status_code, status.HTTP_401_UNAUTHORIZED)
        self.assertIn('detail', response.data)

    def test_password_change_success(self):
        """ test to check password changing endpoint """
        self.user.is_active = True
        self.user.save()
        token = self.client.post(
            reverse('login'),
            {
                'username': 'testuser',
                'password': 'pass@123'
            }, format='json'
        ).data['micro-auth-token']

        self.client.credentials(HTTP_AUTHORIZATION=f'Token {token}')
        response = self.client.post(reverse('password_change'), {
            'old_password': 'pass@123',
            'new_password': 'new@123'
        }, format='json')
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(response.data['message'], 'Password changed successfully.')
        self.user.refresh_from_db()
        self.assertTrue(self.user.check_password('new@123'))

    def test_password_reset_success(self):
        """ test user password resetting """
        self.user.is_active = True
        self.user.save()
        response = self.client.post(
            reverse('password_reset'),
            {'email': 'test@user.com'},
            format='json'
        )
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(response.data['message'], 'Password reset email sent.')
        self.assertEqual(len(mail.outbox), 1)
        self.assertIn('Password Reset Request', mail.outbox[0].subject)

    def test_password_reset_unverified(self):
        """ test: trying to reset password of unverified account """
        response = self.client.post(
            reverse('password_reset'),
            {'email': 'test@user.com'},
            format='json')
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertIn('email', response.data)
        self.assertEqual(response.data['email'][0], 'Email address is not verified.')

    def test_password_reset_confirm_success(self):
        """ test: confirm password reset using link """
        self.user.is_active = True
        self.user.save()
        uidb64 = urlsafe_base64_encode(force_bytes(self.user.pk))
        token = PasswordResetTokenGenerator().make_token(self.user)
        response = self.client.post(
            reverse(
                'password_reset_confirm',
                kwargs={'uidb64': uidb64, 'token': token}
            ),
            {'new_password': 'new@123'},
            format='json',
        )
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(response.data['message'], 'Password reset successfully.')
        self.user.refresh_from_db()
        self.assertTrue(self.user.check_password('new@123'))

    def test_verify_email_success(self):
        """ test: verifiying user email """
        uidb64 = urlsafe_base64_encode(force_bytes(self.user.pk))
        token = PasswordResetTokenGenerator().make_token(self.user)
        response = self.client.post(
            reverse(
                'verify-email',
                kwargs={'uidb64': uidb64, 'token': token}
            ),
            format='json'
        )
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(response.data['message'], 'Email verified successfully.')
        self.user.refresh_from_db()
        self.assertTrue(self.user.is_active)

    def test_resend_verify_email_success(self):
        response = self.client.post(
            reverse('resend_verify_email'),
            {'email': 'test@user.com'},
            format='json'
        )
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(response.data['message'], 'Verification email resent.')
        self.assertEqual(len(mail.outbox), 1)
