from django.urls import path
from .views import *

app_name = 'main'
urlpatterns = [
    path('account/encrypts', EncryptsView.as_view(), name='encrypts'),
    path('account/activate/<str:sign>', user_activate, name='activate'),
    path('account/register/done', RegisterDoneView.as_view(), name='register_done'),
    path('account/register', RegisterView.as_view(), name='register'),
    path('account/profile/password/edit', PasswordEditView.as_view(), name='password_edit'),
    path('account/profile/delete', ProfileDeleteView.as_view(), name='profile_delete'),
    path('account/profile/edit', ProfileEditView.as_view(), name='profile_edit'),
    path('account/profile', profile, name='profile'),
    path('account/logout', AccountLogout.as_view(), name='logout'),
    path('account/login', AccountLogin.as_view(), name='login'),
    path('algorithms/<str:algo>', algorithms, name='algorithms'),
    path('encrypts', uncrypts, name='uncrypts'),
    path('contacts', contacts, name='contacts'),
    path('pages/<str:page>', static_pages),
    path('', index, name='index'),
]
