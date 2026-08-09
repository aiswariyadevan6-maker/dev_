from pathlib import Path
import os

BASE_DIR = Path(__file__).resolve().parent.parent
SECRET_KEY = 'django-insecure-zdh-key-2024'
DEBUG = True
ALLOWED_HOSTS = ['*']
INSTALLED_APPS = [
    'django.contrib.admin','django.contrib.auth','django.contrib.contenttypes',
    'django.contrib.sessions','django.contrib.messages','django.contrib.staticfiles',
    'dashboard',
]
MIDDLEWARE = [
    'django.middleware.security.SecurityMiddleware',
    'django.contrib.sessions.middleware.SessionMiddleware',
    'django.middleware.common.CommonMiddleware',
    'django.middleware.csrf.CsrfViewMiddleware',
    'django.contrib.auth.middleware.AuthenticationMiddleware',
    'django.contrib.messages.middleware.MessageMiddleware',
    'django.middleware.clickjacking.XFrameOptionsMiddleware',
]
ROOT_URLCONF = 'nids_core.urls'
TEMPLATES = [{'BACKEND':'django.template.backends.django.DjangoTemplates','DIRS':[],'APP_DIRS':True,
    'OPTIONS':{'context_processors':['django.template.context_processors.debug',
    'django.template.context_processors.request','django.contrib.auth.context_processors.auth',
    'django.contrib.messages.context_processors.messages']}}]
DATABASES = {'default':{'ENGINE':'django.db.backends.sqlite3','NAME':BASE_DIR/'db.sqlite3'}}
STATIC_URL = 'static/'
STATICFILES_DIRS = [BASE_DIR / 'dashboard' / 'static']
DEFAULT_AUTO_FIELD = 'django.db.models.BigAutoField'
LOGIN_URL = 'dashboard:login'
DATA_UPLOAD_MAX_MEMORY_SIZE = 1024*1024*1024
FILE_UPLOAD_MAX_MEMORY_SIZE = 1024*1024*1024
MODELS_DIR = BASE_DIR.parent / 'models' / 'saved'
import os
_m = os.environ.get('NIDS_MODELS_DIR')
if _m:
    MODELS_DIR = Path(_m)
else:
    MODELS_DIR = Path('/home/kali/Dissertation__/models/saved')
_EXTRA = os.environ.get('NIDS_MODELS_DIR')
if _EXTRA: MODELS_DIR = Path(_EXTRA)
# Live detection dataset cache (set by live feed view on first load)
LIVE_DATASET_CACHE = None
