from datetime import datetime
from os.path import splitext

from django.template.loader import render_to_string
from django.core.signing import Signer
from django.core.mail import EmailMessage
from django.conf import settings

signer = Signer()


def send_activation_notification(user):
    if settings.ALLOWED_HOSTS:
        host = 'https://' + settings.ALLOWED_HOSTS[0]
    else:
        host = 'http://localhost:8000'
    user = user
    context = {'user': user, 'host': host, 'sign': signer.sign(user.username)}
    subject = render_to_string('email/activation_letter_subject.txt', context)
    body_text = render_to_string('email/activation_letter_body.txt', context)
    user.email_user(subject, body_text)


def get_client_ip(request):
    x_forwarded_for = request.META.get('HTTP_X_FORWARDED_FOR')
    if x_forwarded_for:
        ip = x_forwarded_for.split(',')[0]
    else:
        ip = request.META.get('REMOTE_ADDR')
    return ip

