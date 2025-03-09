# Generated by Django 5.1.4 on 2025-03-06 09:46

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('home', '0002_commission_is_reversed_commission_reversed_at_and_more'),
    ]

    operations = [
        migrations.CreateModel(
            name='ShippingConfig',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('quixgo_api_base_url', models.CharField(default='https://dev.api.quixgo.com/clientApi', max_length=255)),
                ('quixgo_email', models.EmailField(max_length=254)),
                ('quixgo_password', models.CharField(max_length=255)),
                ('quixgo_customer_id', models.CharField(max_length=20)),
                ('enable_shipping', models.BooleanField(default=True)),
                ('default_service_type', models.CharField(choices=[('SF', 'Surface'), ('EXP', 'Express')], default='SF', max_length=5)),
                ('default_courier', models.CharField(choices=[('DTC', 'DTDC'), ('DLV', 'Delhivery'), ('SFX', 'Shadowfax'), ('quixgo', 'Quixgo Priority')], default='DTC', max_length=10)),
                ('auth_token', models.TextField(blank=True, null=True)),
                ('token_expiry', models.DateTimeField(blank=True, null=True)),
                ('created_at', models.DateTimeField(auto_now_add=True)),
                ('updated_at', models.DateTimeField(auto_now=True)),
            ],
            options={
                'verbose_name': 'Shipping Configuration',
                'verbose_name_plural': 'Shipping Configuration',
            },
        ),
    ]
