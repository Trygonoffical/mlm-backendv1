# Generated by Django 5.1.4 on 2025-02-21 13:16

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('home', '0012_alter_notification_recipient'),
    ]

    operations = [
        migrations.AddField(
            model_name='product',
            name='HSN_Code',
            field=models.SlugField(null=True, unique=True),
        ),
    ]
