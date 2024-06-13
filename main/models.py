from django.contrib.auth.models import AbstractUser
from django.db import models


class Contacts(models.Model):
    username = models.CharField(max_length=30, verbose_name='Автор')
    from_email = models.EmailField(max_length=50, verbose_name='E-mail')
    message = models.TextField(verbose_name='Сообщение')
    created = models.DateTimeField(auto_now_add=True, db_index=True, verbose_name='Создано')

    class Meta:
        ordering = ('-id',)
        verbose_name = 'Сообщение'
        verbose_name_plural = 'Сообщения'

    def __str__(self):
        return f'{self.username}'


class Methods(models.Model):
    sort = models.CharField(max_length=2, blank=True, null=True, verbose_name='Сортировка')
    title = models.CharField(max_length=60, db_index=True, verbose_name='Название')
    description = models.TextField(verbose_name='Описание', blank=True, null=True)

    class Meta:
        ordering = ('sort', 'title',)
        verbose_name = 'Метод'
        verbose_name_plural = 'Методы'

    def __str__(self):
        return f'{self.title}'


class Algorithms(models.Model):
    sort = models.CharField(max_length=2, blank=True, null=True, verbose_name='Сортировка')
    active = models.BooleanField(default=True, verbose_name='Активен')
    method = models.ForeignKey(Methods, on_delete=models.CASCADE, related_name='Метод', verbose_name='Метод')
    title = models.CharField(max_length=60, verbose_name='Название')
    description = models.TextField(verbose_name='Описание', blank=True, null=True)
    created = models.DateTimeField(auto_now_add=True, db_index=True, verbose_name='Создан')

    class Meta:
        ordering = ('sort', 'title',)
        verbose_name = 'Алгоритм'
        verbose_name_plural = 'Алгоритмы'

    def __str__(self):
        return f'{self.title}'


class ModelUser(AbstractUser):
    is_activated = models.BooleanField(default=True, db_index=True, verbose_name='Активирован')
    send_messages = models.BooleanField(default=True, verbose_name='Получать оповещения')
    privacy = models.BooleanField(blank=False, null=True, verbose_name='Политика конфиденциальности',
                                  error_messages='Чтобы пройти регистраницию, необходимо принять политику конфиденциальности.')

    class Meta(AbstractUser.Meta):
        verbose_name = 'Пользователь'
        verbose_name_plural = 'Пользователи'
        ordering = ['-last_login']


class Encrypts(models.Model):
    user = models.ForeignKey(ModelUser, on_delete=models.CASCADE, verbose_name='Автор', blank=True, null=True)
    algorithm = models.ForeignKey(Algorithms, on_delete=models.CASCADE, related_name='Алгоритм', verbose_name='Алгоритм')
    before = models.CharField(max_length=60, verbose_name='Значение')
    result = models.TextField(verbose_name='Результат')
    key = models.TextField(verbose_name='Ключ')
    created = models.DateTimeField(auto_now_add=True, db_index=True, verbose_name='Создан')

    class Meta:
        ordering = ('-created',)
        verbose_name = 'Шифрование'
        verbose_name_plural = 'Шифрования'

    def __str__(self):
        return f'{self.before}'


