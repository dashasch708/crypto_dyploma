from django.contrib import admin
from django.utils.html import format_html
import datetime

from .models import *
from .utilities import send_activation_notification


@admin.register(Methods)
class ChanelAdmin(admin.ModelAdmin):
    list_display = ['title', 'sort', 'description']
    list_editable = ['sort']


@admin.register(Encrypts)
class EncryptsAdmin(admin.ModelAdmin):
    list_display = ['created', 'algorithm', 'created', 'before', 'result', 'key']
    list_filter = ['algorithm']
    search_fields = ('before',)
    readonly_fields = ('algorithm', 'before', 'result', 'key',)


@admin.register(Algorithms)
class AlgorithmsAdmin(admin.ModelAdmin):
    list_display = ['created', 'sort', 'title', 'method', 'active']
    list_editable = ['sort', 'active']
    readonly_fields = ('title',)


@admin.register(Contacts)
class ContactsAdmin(admin.ModelAdmin):
    list_display = ['created', 'username', 'from_email']


@admin.action(description='Отправить письма с требованием активации')
def send_notifications(modeladmin, request, queryset):
    for rec in queryset:
        if not rec.is_activated:
            send_activation_notification(rec)
    modeladmin.message_user(request, 'Письма с требованиями отправлены')


class NonactivatedFilter(admin.SimpleListFilter):
    title = 'Прошли авторизацию?'
    parameter_name = 'actstate'

    def lookups(self, request, model_admin):
        return (
            ('activated', 'Прошли'),
            ('threedays', 'Не прошли более 3 дней'),
            ('week', 'Не прошли более недели'),
        )

    def queryset(self, request, queryset):
        val = self.value()
        if val == 'activated':
            return queryset.filter(is_active=True, is_activated=True)
        elif val == 'threedays':
            d = datetime.date.today() - datetime.timedelta(days=3)
            return queryset.filter(is_active=False, is_activated=False, date_joined__date__lt=d)
        elif val == 'week':
            d = datetime.date.today() - datetime.timedelta(weeks=1)
            return queryset.filter(is_active=False, is_activated=False, date_joined__date__lt=d)


@admin.register(ModelUser)
class ModelUserAdmin(admin.ModelAdmin):
    list_display = ('__str__', 'email', 'date_joined', 'is_activated')
    search_fields = ('username', 'email', 'first_name', 'last_name')
    list_filter = (NonactivatedFilter,)
    fields = (('username', 'email'), ('first_name', 'last_name'),
              ('send_messages', 'is_activated'),
              ('is_staff', 'is_superuser'), ('last_login', 'date_joined'))
    readonly_fields = ('last_login', 'date_joined')
    actions = (send_notifications,)

    def get_queryset(self, request, *args, **kwargs):
        queryset = super().get_queryset(request, *args, **kwargs)
        queryset = queryset.exclude(pk=1)
        return queryset


