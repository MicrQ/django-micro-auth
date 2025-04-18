""" definitions of URL patterns for the application """
from django.urls import path
from .views import (
    RegisterAPIView,
    LoginAPIView,
    LogoutAPIView,
    PasswordChangeAPIView
)


urlpatterns = [
    path('register/', RegisterAPIView.as_view(), name='register'),
    path('login/', LoginAPIView.as_view(), name='login'),
    path('logout/', LogoutAPIView.as_view(), name='logout'),
    path(
        'password/change/',
        PasswordChangeAPIView.as_view(),
        name='password_change'
    )
]
