<!-- Header -->
<div align="center">

# **Welcome to django-micro-auth**
** _A lightweight Django authentication library with DRF and drf-spectacular support._ **
<hr>

<img src="./docs/logo.django-micro-auth.png" alt="django-micro-auth_logo" width="400">

</div>
<hr>
<!-- Header End -->

<!-- Body -->
## Overview

`django-micro-auth` is a lightweight, modular authentication library for Django, built on Django REST Framework (DRF) with seamless integration for `drf-spectacular` to provide OpenAPI schema documentation. It offers a flexible authentication system supporting session-based and token-based authentication, email verification, and password management. Designed for simplicity, it works with Django’s default user model or custom user models, making it ideal for microservices or standalone applications.

### Key Features
- User registration with email verification.
- Session or token-based authentication.
- Password change and reset functionality.
- Email verification for secure account activation.
- Support for custom user models with dynamic `USERNAME_FIELD` (e.g., `username` or `email`).
- OpenAPI documentation via `drf-spectacular`.
- Minimal dependencies and easy integration.

## Installation

### Prerequisites (not tested with other versions)
- Python 3.8+
- Django 5+
- Django REST Framework
- drf-spectacular

### Steps
**Install the Package**:
   Install from GitHub (for now;):
   ```bash
   pip install git+https://github.com/MicrQ/django-micro-auth.git
   ```

**Add to INSTALLED_APPS**:
    Update your Django project’s settings.py:
```python

INSTALLED_APPS = [
    # others,
    'rest_framework',
    'rest_framework.authtoken',
    'drf_spectacular',
    'django_micro_auth', # the OG :)
    # others,
]
```

**Include URLs**:
    Add the django_micro_auth URLs to your project’s urls.py:
```python
from django.urls import path, include

urlpatterns = [
    path('auth/', include('django_micro_auth.urls')),
]
```

**Include specific urls**
    You can also add only endpoints you need:
```python
from django.urls import path
from django_micro_auth.views import (
    LoginAPIView, LogoutAPIView, ...
)

urlpatterns = [
    path('login/', LoginAPIView.as_view(), name='micro-auth-login'),
    path('logout/', LogoutAPIView.as_view(), name='micro-auth-logout'),
    ...
]
```

## Setup and Configuration

### Authentication Mode

`django-micro-auth` supports two authentication modes:

- **Session Mode**: Utilizes Django’s session framework, storing a `sessionid` cookie.
- **Token Mode**: Leverages Django REST Framework’s token authentication, returning a token for API access.

Set the mode in `settings.py`:

```python
MICRO_AUTH_MODE = 'session'  # or 'token'
```

---

### Email Configuration

The library sends emails for account verification and password resets. To enable this, configure the email backend in `settings.py`:

```python
EMAIL_BACKEND = 'django.core.mail.backends.smtp.EmailBackend'
EMAIL_HOST = 'smtp.provider.com'
EMAIL_PORT = 587 # or any
EMAIL_USE_TLS = True
EMAIL_HOST_USER = 'smtp-email@example.com'
EMAIL_HOST_PASSWORD = 'smtp-password'
DEFAULT_FROM_EMAIL = 'smtp-email@example.com'
```

For development or testing, you can use the console email backend:

```python
EMAIL_BACKEND = 'django.core.mail.backends.console.EmailBackend'
```

---

### Custom User Models

`django-micro-auth` adapts to your user model’s `USERNAME_FIELD` (e.g., `username` or `email`).

To use a custom user model, define it in `settings.py`:

```python
AUTH_USER_MODEL = 'myapp.MyUser'
```

> **Note:** Ensure your custom user model includes both `email` and `is_active` fields. These are essential for email verification and password reset functionalities.

---

### OpenAPI Documentation

To enable OpenAPI schema generation using [`drf-spectacular`](https://drf-spectacular.readthedocs.io/), update your `settings.py` as follows:

```python
REST_FRAMEWORK = {
    'DEFAULT_SCHEMA_CLASS': 'drf_spectacular.openapi.AutoSchema',
}

SPECTACULAR_SETTINGS = {
    'TITLE': 'Title tha fits best for you project',
    'DESCRIPTION': 'Of course, if you have any ...',
    'VERSION': '0.1.0', # or whatever
}
```

Then, add the schema and documentation views to your `urls.py`:

```python
from drf_spectacular.views import SpectacularAPIView, SpectacularSwaggerView

urlpatterns = [
    path('auth/', include('django_micro_auth.urls')),
    path('schema/', SpectacularAPIView.as_view(), name='schema'),
    path('docs/', SpectacularSwaggerView.as_view(url_name='schema'), name='swagger-ui'),
]
```

## Conclusion

**MORE TO COME!**

_Feel free to collaboarate!_

<!-- Body End -->

<!-- Footer -->
<br>
<hr>
<div align="center">

_Made with ❤️ by [Abenet Gebre](https://www.linkedin.com/in/abenetg/)_ - (2025)

</div>
<hr>
<!-- Footer End -->