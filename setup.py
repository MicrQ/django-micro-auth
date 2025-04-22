from setuptools import setup, find_packages
""" setup script for the `django-micro-auth` package """

setup(
    name='django-micro-auth',
    version='0.1.0',
    packages=find_packages(),
    author='Abenet Gebre',
    author_email='mail.micrq@proton.me',
    description='A lightweight Django authentication library with DRF and drf-spectacular support.',
    url='https://github.com/MicrQ/django-micro-auth',
    license='MIT',
    install_requires=[
        "Django>=5",
        "djangorestframework>=3.16",
        "drf-spectacular>=0.28",
    ],
    python_requires='>=3.8'
)
