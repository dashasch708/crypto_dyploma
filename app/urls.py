from django.contrib.auth import views as auth_views
from django.contrib.staticfiles.views import serve
from django.contrib import admin
from django.views.static import serve as media_serve
from django.conf import settings
from django.conf.urls.static import static
from django.urls import path, include

urlpatterns = [
    path('account/reset_password', auth_views.PasswordResetView.as_view(template_name='users/password_reset_form.html'), name='reset_password'),
    path('account/reset_password_sent', auth_views.PasswordResetDoneView.as_view(template_name='users/password_reset_done.html'), name='password_reset_done'),
    path('account/reset/<uidb64>/<token>', auth_views.PasswordResetConfirmView.as_view(template_name='users/password_reset_confirm.html'), name='password_reset_confirm'),
    path('account/reset_password_complete', auth_views.PasswordResetCompleteView.as_view(template_name='users/password_reset_complete.html'), name='password_reset_complete'),
    path('admin/', admin.site.urls),
    path('captcha/', include('captcha.urls')),
    path('', include('main.urls'))
]

#handler404 = 'main.views.error404'
#handler500 = 'main.views.error500'

if not settings.DEBUG:
    urlpatterns.append(path('static/<path:path>', serve, {'insecure': True}))
    urlpatterns.append(path('media/<path:path>', media_serve, {'document_root': settings.MEDIA_ROOT}))

if settings.DEBUG:
    urlpatterns += static(settings.MEDIA_URL, document_root=settings.MEDIA_ROOT)