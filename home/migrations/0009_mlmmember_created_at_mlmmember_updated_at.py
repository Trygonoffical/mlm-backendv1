# Generated by Django 5.1.4 on 2025-02-16 15:17

import django.utils.timezone
from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('home', '0008_notification'),
    ]

    operations = [
        migrations.AddField(
            model_name='mlmmember',
            name='created_at',
            field=models.DateTimeField(default=django.utils.timezone.now),
        ),
        migrations.AddField(
            model_name='mlmmember',
            name='updated_at',
            field=models.DateTimeField(default=django.utils.timezone.now),
        ),
    ]
