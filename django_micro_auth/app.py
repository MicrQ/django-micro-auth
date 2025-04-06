""" The entry point for the django-micro-auth """
from django.apps import AppConfig


class DjangoMicroAuthConfig(AppConfig):
    """ used to define application-specific settings and metadata """

    default_auto_field = 'django.db.models.BigAutoField'
    name = 'django_micro_auth'
