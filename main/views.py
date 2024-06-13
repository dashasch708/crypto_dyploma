from functools import lru_cache

from django.contrib import messages
from django.contrib.auth import logout
from django.contrib.auth.mixins import LoginRequiredMixin
from django.contrib.auth.views import LogoutView, LoginView, PasswordChangeView
from django.contrib.messages.views import SuccessMessageMixin
from django.core.mail import EmailMessage
from django.core.signing import BadSignature
from django.http import JsonResponse, HttpResponse, Http404
from django.shortcuts import render, redirect, get_object_or_404
from django.template import TemplateDoesNotExist
from django.template.loader import get_template
from django.urls import reverse_lazy
from django.views.generic import UpdateView, TemplateView, DeleteView, CreateView
from django.views.generic.list import ListView

from .forms import ContactForm, ProfileEditForm, RegisterForm, EncryptForm
from .models import *
from .utilities import signer

from passlib.hash import md5_crypt, sha256_crypt, sha512_crypt
from Cryptodome.Cipher import AES, Blowfish, DES, PKCS1_OAEP
from Cryptodome.Random import get_random_bytes
from Cryptodome.PublicKey import DSA, ECC, RSA
from Cryptodome.Signature import DSS
from Cryptodome.Hash import SHA256
from Cryptodome.Util.Padding import pad, unpad
from arc4 import ARC4
from os import urandom
from struct import pack
import base64


def csrf_failure_view(request, reason=""):
    return render(request, "main/csrf_failure.html", {"reason": request.user})


def error404(request, exception):
    return render(request, 'main/404.html', status=404)


def error500(request):
    return render(request, 'main/500.html', status=500)


def public(request):
    pass


def algorithms(request, algo):
    algorithm = Algorithms.objects.get(title__iexact=algo, active=True)
    user = request.user.pk
    if user:
        user_id = user
    else:
        user_id = 1
    form = EncryptForm()
    result = 'Результат шифрования'
    if request.method == 'POST':
        form = EncryptForm(request.POST)
        if form.is_valid():
            key = form.cleaned_data['key']
            before = form.cleaned_data['before']
            if algorithm.method_id == 1:
                algs = {'md5': md5_crypt, 'sha256': sha256_crypt, 'sha512': sha512_crypt}
                result = algs[algo].using(salt=key).hash(before)
            elif algorithm.method_id == 2:
                if algorithm.id == 4:
                    key = get_random_bytes(16)
                    cipher = AES.new(key, AES.MODE_EAX)
                    ciphertext, tag = cipher.encrypt_and_digest(bytes(before, encoding='utf-8'))
                    result = f'text: {ciphertext} tag: {tag}'
                elif algorithm.id == 5:
                    key = get_random_bytes(8)
                    des = DES.new(key, DES.MODE_ECB)
                    l_text = b'{before}'
                    while len(l_text) % 8 != 0:
                        l_text += b' '
                    padded_text = l_text
                    result = des.encrypt(padded_text)
                elif algorithm.id == 6:
                    key = key if key else 'key'
                    arc4 = ARC4(bytes(key, encoding='utf-8'))
                    result = arc4.encrypt(bytes(before, encoding='utf-8'))
                elif algorithm.id == 8:
                    bs = Blowfish.block_size
                    key = bytes(key, encoding='utf-8') if key else get_random_bytes(8)
                    text = bytes(before, encoding='utf-8')
                    cipher = Blowfish.new(key, Blowfish.MODE_CBC)
                    plen = bs - len(text) % bs
                    padding = [plen] * plen
                    padding = pack('b' * plen, *padding)
                    result = cipher.iv + cipher.encrypt(text + padding)
            elif algorithm.method_id == 3:
                if algorithm.id == 9:
                    data = bytes(before, encoding='utf-8')
                    session_key = get_random_bytes(16)
                    cipher_aes = AES.new(session_key, AES.MODE_EAX)
                    ciphertext, tag = cipher_aes.encrypt_and_digest(data)
                    result = f'text: {ciphertext} tag: {tag}'
                elif algorithm.id == 10:
                    key = DSA.generate(2048)
                    hash_obj = SHA256.new(bytes(before, encoding='utf-8'))
                    signed = DSS.new(key, 'fips-186-3')
                    result = signed.sign(hash_obj)
                elif algorithm.id == 11:
                    key = ECC.generate(curve='p256')
                    private_key = key.export_key(format='PEM', passphrase=bytes(before, encoding='utf-8'), protection='PBKDF2WithHMAC-SHA512AndAES256-CBC', prot_params={'iteration_count': 131072})
                    public_key = key.public_key()
                    result = f'{public_key}\n\n{private_key}'
            Encrypts.objects.create(before=before, result=result, key=key, user_id=user_id, algorithm_id=algorithm.pk)
    context = {'algorithm': algorithm, 'form': form, 'result': result}
    return render(request, 'main/algorithms.html', context)


@lru_cache(maxsize=20)
def index(request):
    methods = Methods.objects.all()
    algorithms = Algorithms.objects.filter(active=True)
    context = {'methods': methods, 'algorithms': algorithms}
    return render(request, 'main/index.html', context)


def uncrypts(request):
    return render(request, 'main/encrypts.html')


class EncryptsView(ListView):
    template_name = 'users/encrypts.html'
    context_object_name = 'encrypts'
    paginate_by = 3

    def get_queryset(self, **kwargs):
        return Encrypts.objects.filter(user_id=self.request.user.pk)


def profile(request):
    context = {'user': request.user}
    if request.user.username:
        return render(request, 'users/profile.html', context)
    else:
        return redirect('/account/login')


def static_pages(request, page):
    try:
        template = get_template(f'main/{page}.html')
    except TemplateDoesNotExist:
        raise Http404
    return HttpResponse(template.render(request=request))


def contacts(request):
    DEFAULT_FROM_EMAIL = 'zashifr@yandex.ru'
    status = ''
    if request.method == 'GET':
        form = ContactForm()
    elif request.method == 'POST':
        form = ContactForm(request.POST)
        if form.is_valid():
            subject = 'Сообщение с сайта ЗАШИФРУЙ'
            message = form.cleaned_data['message']
            username = form.cleaned_data['username']
            from_email = form.cleaned_data['from_email']
            message = f'Автор: {username}\n\nСообщение: {message}'
            em = EmailMessage(subject=subject, body=message, to=[DEFAULT_FROM_EMAIL], from_email=from_email)
            em.send()
            Contacts.objects.create(username=username, from_email=from_email, message=message)
            status = 'Ваше сообщение успешно отправлено. Спасибо за обращение!'

            return render(request, 'main/contact.html', {'status': status})
    else:
        return HttpResponse('Неверный запрос.')
    return render(request, 'main/contact.html', {'form': form, 'status': status})


def user_activate(request, sign):
    try:
        username = signer.unsign(sign)
    except BadSignature:
        return render(request, 'main/activation_failed.html')
    user = get_object_or_404(ModelUser, username=username)
    if user.is_activated:
        template = 'users/activation_done_earlier.html'
    else:
        template = 'users/activation_done.html'
        user.is_active = True
        user.is_activated = True
        user.save()
    return render(request, template)


class ProfileDeleteView(SuccessMessageMixin, LoginRequiredMixin, DeleteView):
    model = ModelUser
    template_name = 'users/profile_delete.html'
    success_url = reverse_lazy('users:index')
    success_message = 'Ваш профиль удален'

    def setup(self, request, *args, **kwargs):
        self.user_id = request.user.pk
        return super().setup(request, *args, **kwargs)

    def post(self, request, *args, **kwargs):
        logout(request)
        return super().post(request, *args, **kwargs)

    def get_object(self, queryset=None):
        if not queryset:
            queryset = self.get_queryset()
        return get_object_or_404(queryset, pk=self.user_id)


class RegisterView(CreateView):
    model = ModelUser
    template_name = 'users/register.html'
    form_class = RegisterForm
    success_url = reverse_lazy('main:register_done')


class RegisterDoneView(TemplateView):
    template_name = 'users/register_done.html'


class PasswordEditView(SuccessMessageMixin, LoginRequiredMixin, PasswordChangeView):
    template_name = 'users/password_edit.html'
    success_url = reverse_lazy('main:profile')
    success_message = 'Ваш пароль изменен'


class ProfileEditView(SuccessMessageMixin, LoginRequiredMixin, UpdateView):
    model = ModelUser
    template_name = 'users/profile_edit.html'
    form_class = ProfileEditForm
    success_url = reverse_lazy('main:profile')
    success_message = 'Ваши данные обновлены'

    def setup(self, request, *args, **kwargs):
        self.user_id = request.user.pk
        return super().setup(request, *args, **kwargs)

    def get_object(self, queryset=None):
        if not queryset:
            queryset = self.get_queryset()
        return get_object_or_404(queryset, pk=self.user_id)


class AccountLogin(LoginView):
    template_name = 'users/login.html'


class AccountLogout(LogoutView):
    pass

