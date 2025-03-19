"""
Django settings for mlm project.

Generated by 'django-admin startproject' using Django 5.1.3.

For more information on this file, see
https://docs.djangoproject.com/en/5.1/topics/settings/

For the full list of settings and their values, see
https://docs.djangoproject.com/en/5.1/ref/settings/
"""
import os
from datetime import timedelta 
from pathlib import Path

# Build paths inside the project like this: BASE_DIR / 'subdir'.
BASE_DIR = Path(__file__).resolve().parent.parent


# Quick-start development settings - unsuitable for production
# See https://docs.djangoproject.com/en/5.1/howto/deployment/checklist/

# SECURITY WARNING: keep the secret key used in production secret!
SECRET_KEY = 'django-insecure-c0%h0nvj=pe7%6=!2$)!3$dj3#sykbb4axg@)_jo#cg$xp#@%z'

# SECURITY WARNING: don't run with debug turned on in production!
DEBUG = True

ALLOWED_HOSTS = [
    '195.35.20.31' ,
    'herbalapi.trygon.tech' , 
    '127.0.0.1' , 
    '127.0.0.1:3002' , 
    'http://localhost' , 
    'http://localhost:3002'
    ]

CORS_ALLOW_METHODS = [
    "GET",
    "POST",
    "PUT",
    "PATCH",
    "DELETE",
    "OPTIONS",
]

# Application definition

INSTALLED_APPS = [
    'django.contrib.admin',
    'django.contrib.auth',
    'django.contrib.contenttypes',
    'django.contrib.sessions',
    'django.contrib.messages',
    'django.contrib.staticfiles',
    'corsheaders',
    'django_filters',
    'rest_framework',
    'rest_framework_simplejwt',
    'appAuth',
    'home',
]

MIDDLEWARE = [
    'corsheaders.middleware.CorsMiddleware', 
    'django.middleware.security.SecurityMiddleware',
    'django.contrib.sessions.middleware.SessionMiddleware',
    'django.middleware.common.CommonMiddleware',
    'django.middleware.csrf.CsrfViewMiddleware',
    'django.contrib.auth.middleware.AuthenticationMiddleware',
    'django.contrib.messages.middleware.MessageMiddleware',
    'django.middleware.clickjacking.XFrameOptionsMiddleware',
]

ROOT_URLCONF = 'mlm.urls'

TEMPLATES = [
    {
        'BACKEND': 'django.template.backends.django.DjangoTemplates',
        'DIRS': [
            os.path.join(BASE_DIR, 'templates'),
        ],
        'APP_DIRS': True,
        'OPTIONS': {
            'context_processors': [
                'django.template.context_processors.debug',
                'django.template.context_processors.request',
                'django.contrib.auth.context_processors.auth',
                'django.contrib.messages.context_processors.messages',
            ],
        },
    },
]

WSGI_APPLICATION = 'mlm.wsgi.application'


# Database
# https://docs.djangoproject.com/en/5.1/ref/settings/#databases

DATABASES = {
    # 'default': {
    #     'ENGINE': 'django.db.backends.sqlite3',
    #     'NAME': BASE_DIR / 'db.sqlite3',
    # }

    'default': {
        'ENGINE': 'django.db.backends.postgresql',
        'NAME': 'mlmv8',
        'USER': 'postgres',
        'PASSWORD': 'Trygon@123',
        'HOST': 'localhost',
        'PORT': '5432'
    }
}  

# Site Information
SITE_NAME = 'Herbal Power'
SITE_URL = 'https://herbalpower.trygon.tech/'  # Change to your actual domain
CONTACT_EMAIL = 'support@herbalpower.com'  # Change to your support email

# Email Configuration
EMAIL_BACKEND = 'django.core.mail.backends.smtp.EmailBackend'
EMAIL_HOST = 'smtp.hostinger.com'  # e.g., smtp.gmail.com
EMAIL_PORT = 465  # or 465 for SSL
EMAIL_USE_TLS = True  # or False if using SSL
EMAIL_HOST_USER = 'info@trygon.in'
EMAIL_HOST_PASSWORD = 'Trygon@123!'  # Consider using environment variables for security
DEFAULT_FROM_EMAIL = 'Your MLM Platform <noreply@yourmlmwebsite.com>'

FRONTEND_URL = 'http://localhost:3002'

# Django settings.py
MSG91_AUTH_KEY = '440798AeOvHXDvG2p67a9fb37P1'
# Password validation
#test
# https://docs.djangoproject.com/en/5.1/ref/settings/#auth-password-validators

AUTH_PASSWORD_VALIDATORS = [
    {
        'NAME': 'django.contrib.auth.password_validation.UserAttributeSimilarityValidator',
    },
    {
        'NAME': 'django.contrib.auth.password_validation.MinimumLengthValidator',
    },
    {
        'NAME': 'django.contrib.auth.password_validation.CommonPasswordValidator',
    },
    {
        'NAME': 'django.contrib.auth.password_validation.NumericPasswordValidator',
    },
]


# Internationalization
# https://docs.djangoproject.com/en/5.1/topics/i18n/

LANGUAGE_CODE = 'en-us'

TIME_ZONE = 'UTC'

USE_I18N = True

USE_TZ = True


# Static files (CSS, JavaScript, Images)
# https://docs.djangoproject.com/en/5.1/howto/static-files/

# STATIC_URL = 'static/'
STATIC_URL = '/static/'
# STATICFILES_DIRS = [
#     BASE_DIR / "static",
# ]
STATIC_ROOT = os.path.join(BASE_DIR, 'static')
MEDIA_URL = '/media/'
MEDIA_ROOT = os.path.join(BASE_DIR, 'media')
# STATIC_ROOT = os.path.join(BASE_DIR, 'staticfiles')  # or your preferred path
# STATICFILES_DIRS = [
#     os.path.join(BASE_DIR, 'static')
# ]

# Default primary key field type
# https://docs.djangoproject.com/en/5.1/ref/settings/#default-auto-field

DEFAULT_AUTO_FIELD = 'django.db.models.BigAutoField'

# AUTH_USER_MODEL = 'home.User'
AUTH_USER_MODEL = 'home.User'
#extra configurations 

REST_FRAMEWORK = {
    # Use Django's standard `django.contrib.auth` permissions,
    # or allow read-only access for unauthenticated users.
    'DEFAULT_PERMISSION_CLASSES': [
        'rest_framework.permissions.DjangoModelPermissionsOrAnonReadOnly'
    ],
     'DEFAULT_FILTER_BACKENDS': [
        'django_filters.rest_framework.DjangoFilterBackend',
        'rest_framework.filters.SearchFilter',
        'rest_framework.filters.OrderingFilter',
    ],
    'DEFAULT_AUTHENTICATION_CLASSES': (
        'rest_framework_simplejwt.authentication.JWTAuthentication',
        
    ),
    
}

# Optional: Configure CORS if needed
CORS_ALLOW_ALL_ORIGINS = True  # For development only
CORS_ALLOW_CREDENTIALS = True

SIMPLE_JWT = {
    'ACCESS_TOKEN_LIFETIME': timedelta(hours=6),  # Extended from 5 minutes
    'REFRESH_TOKEN_LIFETIME': timedelta(days=7),  # Extended from 1 day
    'ROTATE_REFRESH_TOKENS': True,  # Issues new refresh token on refresh
    'BLACKLIST_AFTER_ROTATION': True,  # Important for security
}

RAZORPAY_KEY_ID = 'rzp_test_x05a9xxCjRkVBx'
RAZORPAY_KEY_SECRET = '47qySM0t0VJeRl1V1xMlVcP1'

# shipping settings
QUIXGO_API_BASE_URL = 'https://api.quixgo.com/clientApi'  # Use prod URL for production
QUIXGO_EMAIL = 'herbalpowerindia@gmail.com'  # Replace with your QuixGo account email dharampal@quixgo.in
QUIXGO_PASSWORD = 'Herbal@1234'  # Replace with your QuixGo account password Test@123
QUIXGO_CUSTOMER_ID = '9y2J'  # This will be obtained after the first login


# MSG91_EMAIL_AUTH_KEY = '440929ANN27nHYNBZ67badd81P1'
# MSG91_EMAIL_SENDER = 'noreply@mail.herbalpowerindia.com'
# MSG91_EMAIL_SENDER_NAME = 'Herbal Power Marketing Private Limited'
# MSG91_EMAIL_DOMAIN = 'mail.herbalpowerindia.com'
MSG91_EMAIL_AUTH_KEY = '440929ANN27nHYNBZ67badd81P1'
MSG91_EMAIL_DOMAIN = 'mail.herbalpowerindia.com'
MSG91_FROM_EMAIL = 'noreply@mail.herbalpowerindia.com'
MSG91_FROM_NAME = 'Herbal Power Marketing Private Limited'

# Email templates
MSG91_EMAIL_TEMPLATES = {
    'KYC_APPROVED': 'kyc_approved_3',
    # Add other templates as needed
}


LOGGING = {
    'version': 1,
    'disable_existing_loggers': False,
    'formatters': {
        'verbose': {
            'format': '{levelname} {asctime} {module} {process:d} {thread:d} {message}',
            'style': '{',
        },
        'simple': {
            'format': '{levelname} {message}',
            'style': '{',
        },
    },
    'handlers': {
        'console': {
            'class': 'logging.StreamHandler',
            'formatter': 'verbose',
        },
        'file': {
            'class': 'logging.FileHandler',
            'filename': 'debug.log',
            'formatter': 'verbose',
        },
    },
    'loggers': {
        '': {  # Root logger
            'handlers': ['console', 'file'],
            'level': 'INFO',
        },
        'home': {  # Your app name
            'handlers': ['console', 'file'],
            'level': 'DEBUG',
            'propagate': False,
        },
    },
}