# Generated by Django 5.0.6 on 2024-05-20 13:15

import django.db.models.deletion
from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('main', '0001_initial'),
    ]

    operations = [
        migrations.CreateModel(
            name='Methods',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('title', models.CharField(db_index=True, max_length=60, verbose_name='Название')),
                ('description', models.TextField(null=True, verbose_name='Описание')),
            ],
            options={
                'verbose_name': 'Метод',
                'verbose_name_plural': 'Методы',
                'ordering': ('title',),
            },
        ),
        migrations.AlterField(
            model_name='algorithms',
            name='method',
            field=models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, related_name='Метод', to='main.methods', verbose_name='Метод'),
        ),
    ]
