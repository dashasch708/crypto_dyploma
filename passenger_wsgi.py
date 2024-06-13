#import django.template.loader

#def reset_template_cache():
#    if django.template.loader.template_source_loaders:
#        for t in django.template.loader.template_source_loaders:
#            t.reset()
    
    # -*- coding: utf-8 -*-
import os, sys
sys.path.insert(0, '/var/www/u2254756/data/www/constructionmachines.ru/constructionmachines/')
sys.path.insert(1, '/var/www/u2254756/data/djangoenv/lib/python3.10/site-packages')
os.environ['DJANGO_SETTINGS_MODULE'] = 'constructionmachines.settings'
from django.core.wsgi import get_wsgi_application
application = get_wsgi_application()

#PYTHONDONTWRITEBYTECODE=1
#export PYTHONDONTWRITEBYTECODE