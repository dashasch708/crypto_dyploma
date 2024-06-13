from captcha.fields import CaptchaField
from django import forms
from django.contrib.auth import password_validation
from django.core.exceptions import ValidationError
from django.forms import TextInput

from .models import ModelUser, Contacts
from .signals import post_register


class EncryptForm(forms.Form):
    key = forms.CharField(label='Ключ шифрования (необязательно)', required=False, widget=TextInput(attrs={'type':'number'}))
    before = forms.CharField(label='Текстовое сообщение', required=True, widget=forms.Textarea)

    class Meta:
        fields = ('key', 'before',)


class ContactForm(forms.Form):
    username = forms.CharField(label='Ваше Имя', required=True)
    from_email = forms.EmailField(label='Эл. почта', required=True)
    message = forms.CharField(label='Сообщение', required=True, widget=forms.Textarea)
    captcha = CaptchaField(label='Текст с картинки', error_messages={'invalid': 'Неправильный текст'})

    class Meta:
        fields = ('from_email', 'username', 'message', 'captcha')


class RegisterForm(forms.ModelForm):
    captcha = CaptchaField(label='Текст с картинки', error_messages={'invalid': 'Неправильный текст'})
    username = forms.CharField(max_length=30, required=True, label='Имя',
                               help_text='Обязательное поле')
    email = forms.EmailField(required=True, label='Ваш e-mail',
                             help_text='Обязательное поле. На этот e-mail будет отправлено сообщение с подтверждением регистрации')
    password1 = forms.CharField(label='Пароль от 8 до 20 символов', min_length=8, max_length=20,
                                widget=forms.PasswordInput(render_value=True),
                                help_text=password_validation.password_validators_help_text_html())
    password2 = forms.CharField(label='Пароль (повторно)', min_length=8, max_length=20,
                                widget=forms.PasswordInput(render_value=True), help_text='Укажите пароль повторно')
    privacy = forms.BooleanField(label='Политика конфиденциальности')
    field_order = ('username', 'password1', 'password2', 'email', 'send_messages', 'privacy')

    def clean_password1(self):
        password1 = self.cleaned_data['password1']
        try:
            password_validation.validate_password(password1)
        except forms.ValidationError as error:
            self.add_error('password1', error)
        return password1

    def clean(self):
        super().clean()
        password1 = self.cleaned_data['password1']
        password2 = self.cleaned_data['password2']
        if password1 and password2 and password1 != password2:
            errors = {'password2': ValidationError('ВВеденные пароли не совпадают', code='password_mismath')}
            raise ValidationError(errors)

    def save(self, commit=True):
        user = super().save(commit=False)
        user.set_password(self.cleaned_data['password1'])
        #    user.is_active = False
        user.is_activated = False
        if commit:
            user.save()
        post_register.send(RegisterForm, instance=user)
        return user

    class Meta:
        model = ModelUser
        fields = ('username', 'email', 'send_messages', 'privacy')


class ProfileEditForm(forms.ModelForm):
    email = forms.EmailField(required=True, label='Ваш e-mail')
    first_name = forms.CharField(max_length=50, required=False, label='Ваше имя')
    last_name = forms.CharField(max_length=50, required=False, label='Фамилия')

    class Meta:
        model = ModelUser
        fields = ('email', 'first_name', 'last_name', 'send_messages')
