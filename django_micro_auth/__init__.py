from django.conf import settings


__version__ = '0.1.0'
MICRO_AUTH_MODE = getattr(settings, 'MICRO_AUTH_MODE', 'session')
