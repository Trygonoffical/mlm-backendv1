# Generated by Django 5.1.4 on 2025-02-25 09:49

import django.db.models.deletion
from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('home', '0019_alter_commissionactivationrequest_current_position_and_more'),
    ]

    operations = [
        migrations.CreateModel(
            name='PickupAddress',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('name', models.CharField(max_length=100)),
                ('address_id', models.CharField(blank=True, max_length=20, null=True)),
                ('customer_id', models.CharField(blank=True, max_length=20, null=True)),
                ('contact_person', models.CharField(max_length=100)),
                ('address_line1', models.CharField(max_length=255)),
                ('address_line2', models.CharField(blank=True, max_length=255)),
                ('city', models.CharField(max_length=100)),
                ('state', models.CharField(max_length=100)),
                ('country', models.CharField(default='India', max_length=100)),
                ('pincode', models.CharField(max_length=10)),
                ('phone', models.CharField(max_length=15)),
                ('alternate_phone', models.CharField(blank=True, max_length=15)),
                ('email', models.EmailField(blank=True, max_length=254)),
                ('landmark', models.CharField(blank=True, max_length=255)),
                ('address_type', models.CharField(default='Office', max_length=20)),
                ('is_default', models.BooleanField(default=False)),
                ('is_active', models.BooleanField(default=True)),
                ('created_at', models.DateTimeField(auto_now_add=True)),
                ('updated_at', models.DateTimeField(auto_now=True)),
            ],
        ),
        migrations.CreateModel(
            name='ShippingCredential',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('provider_name', models.CharField(max_length=100)),
                ('api_key', models.CharField(max_length=255)),
                ('api_secret', models.CharField(blank=True, max_length=255, null=True)),
                ('base_url', models.URLField()),
                ('is_active', models.BooleanField(default=True)),
                ('created_at', models.DateTimeField(auto_now_add=True)),
                ('updated_at', models.DateTimeField(auto_now=True)),
            ],
        ),
        migrations.AlterModelOptions(
            name='commissionactivationrequest',
            options={},
        ),
        migrations.AlterUniqueTogether(
            name='commissionactivationrequest',
            unique_together=set(),
        ),
        migrations.CreateModel(
            name='Shipment',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('awb_number', models.CharField(blank=True, max_length=50, null=True)),
                ('shipment_id', models.CharField(blank=True, max_length=50, null=True)),
                ('courier_name', models.CharField(blank=True, max_length=50, null=True)),
                ('service_type', models.CharField(default='SF', max_length=10)),
                ('status', models.CharField(choices=[('PENDING', 'Pending'), ('BOOKED', 'Booked'), ('PICKED_UP', 'Picked Up'), ('IN_TRANSIT', 'In Transit'), ('OUT_FOR_DELIVERY', 'Out for Delivery'), ('DELIVERED', 'Delivered'), ('FAILED_DELIVERY', 'Failed Delivery'), ('RETURNED', 'Returned'), ('CANCELLED', 'Cancelled')], default='PENDING', max_length=20)),
                ('status_details', models.JSONField(blank=True, default=dict)),
                ('tracking_url', models.URLField(blank=True, null=True)),
                ('weight', models.DecimalField(decimal_places=2, default=1.0, max_digits=5)),
                ('length', models.DecimalField(decimal_places=2, default=10.0, max_digits=5)),
                ('width', models.DecimalField(decimal_places=2, default=10.0, max_digits=5)),
                ('height', models.DecimalField(decimal_places=2, default=10.0, max_digits=5)),
                ('is_cod', models.BooleanField(default=False)),
                ('cod_amount', models.DecimalField(decimal_places=2, default=0.0, max_digits=10)),
                ('shipping_charge', models.DecimalField(decimal_places=2, default=0.0, max_digits=10)),
                ('is_cancelled', models.BooleanField(default=False)),
                ('created_at', models.DateTimeField(auto_now_add=True)),
                ('updated_at', models.DateTimeField(auto_now=True)),
                ('order', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, related_name='shipments', to='home.order')),
                ('pickup_address', models.ForeignKey(on_delete=django.db.models.deletion.PROTECT, to='home.pickupaddress')),
            ],
        ),
        migrations.CreateModel(
            name='ShipmentStatusUpdate',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('status', models.CharField(max_length=50)),
                ('status_details', models.TextField(blank=True)),
                ('location', models.CharField(blank=True, max_length=100)),
                ('timestamp', models.DateTimeField()),
                ('created_at', models.DateTimeField(auto_now_add=True)),
                ('shipment', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, related_name='status_updates', to='home.shipment')),
            ],
            options={
                'ordering': ['-timestamp'],
            },
        ),
    ]
