""" definitions of URL patterns for the application """
from django.urls import path
from .views import (
    LoginAPIView,
    LogoutAPIView,
    RegisterAPIView,
    PasswordResetAPIView,
    PasswordChangeAPIView,
    PasswordResetConfirmAPIView,
)


urlpatterns = [
    path('register/', RegisterAPIView.as_view(), name='register'),
    path('login/', LoginAPIView.as_view(), name='login'),
    path('logout/', LogoutAPIView.as_view(), name='logout'),
    path(
        'password/change/',
        PasswordChangeAPIView.as_view(),
        name='password_change'
    ),
    path(
        'password/reset/',
        PasswordResetAPIView.as_view(),
        name='password_reset'
    ), # requires EMAIL_BACKEND and DEFAULT_FROM_EMAIL set
    path(
        'password/reset/confirm/<uidb64>/<token>/',
        PasswordResetConfirmAPIView.as_view(),
        name='password_reset_confirm'),
]
