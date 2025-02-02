# Generated by Django 5.1.4 on 2025-01-29 08:45

import django.core.validators
import django.db.models.deletion
import django.utils.timezone
from django.conf import settings
from django.db import migrations, models


class Migration(migrations.Migration):

    initial = True

    dependencies = [
        ('auth', '0012_alter_user_first_name_max_length'),
    ]

    operations = [
        migrations.CreateModel(
            name='About',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('type', models.CharField(choices=[('HOME', 'Homepage About'), ('MAIN', 'Main About Page')], default='MAIN', max_length=4)),
                ('title', models.CharField(max_length=200)),
                ('content', models.TextField()),
                ('feature_content', models.TextField(blank=True, null=True)),
                ('left_image', models.ImageField(upload_to='about/')),
                ('vision_description', models.TextField(blank=True, null=True)),
                ('mission_description', models.TextField(blank=True, null=True)),
                ('objective_content', models.TextField(blank=True, null=True)),
                ('is_active', models.BooleanField(default=True)),
                ('created_at', models.DateTimeField(auto_now_add=True)),
                ('updated_at', models.DateTimeField(auto_now=True)),
            ],
            options={
                'verbose_name': 'About',
                'verbose_name_plural': 'About',
                'db_table': 'about',
            },
        ),
        migrations.CreateModel(
            name='Advertisement',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('title', models.CharField(blank=True, max_length=200, null=True)),
                ('image', models.ImageField(upload_to='advertisements/')),
                ('link', models.URLField(blank=True, null=True)),
                ('position', models.CharField(blank=True, max_length=100, null=True)),
                ('is_active', models.BooleanField(default=True)),
                ('created_at', models.DateTimeField(auto_now_add=True)),
                ('updated_at', models.DateTimeField(auto_now=True)),
            ],
            options={
                'db_table': 'advertisements',
                'ordering': ['-created_at'],
            },
        ),
        migrations.CreateModel(
            name='CompanyInfo',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('company_name', models.CharField(max_length=200)),
                ('logo', models.ImageField(upload_to='company/')),
                ('gst_number', models.CharField(blank=True, max_length=15)),
                ('email', models.EmailField(max_length=254)),
                ('mobile_1', models.CharField(max_length=15)),
                ('mobile_2', models.CharField(blank=True, max_length=15)),
                ('address_line1', models.CharField(max_length=255)),
                ('address_line2', models.CharField(blank=True, max_length=255)),
                ('city', models.CharField(max_length=100)),
                ('state', models.CharField(max_length=100)),
                ('pincode', models.CharField(max_length=10)),
                ('country', models.CharField(default='India', max_length=100)),
                ('facebook_link', models.URLField(blank=True)),
                ('instagram_link', models.URLField(blank=True)),
                ('twitter_link', models.URLField(blank=True)),
                ('youtube_link', models.URLField(blank=True)),
                ('footer_bg_image', models.ImageField(blank=True, help_text='Background image for website footer', upload_to='company/backgrounds/')),
                ('testimonial_bg_image', models.ImageField(blank=True, help_text='Background image for testimonials section', upload_to='company/backgrounds/')),
                ('is_active', models.BooleanField(default=True)),
                ('created_at', models.DateTimeField(auto_now_add=True)),
                ('updated_at', models.DateTimeField(auto_now=True)),
            ],
            options={
                'verbose_name': 'Company Information',
                'verbose_name_plural': 'Company Information',
                'db_table': 'company_info',
            },
        ),
        migrations.CreateModel(
            name='CustomerPickReview',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('title', models.CharField(max_length=200)),
                ('description', models.TextField(blank=True, null=True)),
                ('youtube_link', models.URLField(help_text='YouTube video link')),
                ('thumbnail', models.ImageField(blank=True, help_text='Thumbnail image for the video', null=True, upload_to='customer_picks/')),
                ('position', models.PositiveIntegerField(default=0)),
                ('is_active', models.BooleanField(default=True)),
                ('created_at', models.DateTimeField(auto_now_add=True)),
                ('updated_at', models.DateTimeField(auto_now=True)),
            ],
            options={
                'verbose_name': 'Customer Pick Review',
                'verbose_name_plural': 'Customer Pick Reviews',
                'db_table': 'customer_pick_reviews',
                'ordering': ['position', '-created_at'],
            },
        ),
        migrations.CreateModel(
            name='CustomPage',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('title', models.CharField(max_length=200)),
                ('slug', models.SlugField(max_length=200, unique=True)),
                ('content', models.TextField()),
                ('is_active', models.BooleanField(default=True)),
                ('show_in_footer', models.BooleanField(default=False)),
                ('show_in_header', models.BooleanField(default=False)),
                ('order', models.PositiveIntegerField(default=0)),
                ('created_at', models.DateTimeField(auto_now_add=True)),
                ('updated_at', models.DateTimeField(auto_now=True)),
            ],
            options={
                'db_table': 'custom_pages',
                'ordering': ['order', 'title'],
            },
        ),
        migrations.CreateModel(
            name='HomeSection',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('section_type', models.CharField(choices=[('TRENDING', 'Trending Products'), ('FEATURED', 'Featured Products'), ('NEW_ARRIVAL', 'New Arrivals'), ('BESTSELLER', 'Best Sellers')], max_length=20, unique=True)),
                ('title', models.CharField(max_length=200)),
                ('subtitle', models.CharField(blank=True, max_length=200)),
                ('description', models.TextField(blank=True)),
                ('image', models.ImageField(upload_to='home_sections/')),
                ('is_active', models.BooleanField(default=True)),
                ('display_order', models.PositiveIntegerField(default=0)),
                ('created_at', models.DateTimeField(auto_now_add=True)),
                ('updated_at', models.DateTimeField(auto_now=True)),
            ],
            options={
                'db_table': 'home_sections',
                'ordering': ['display_order'],
            },
        ),
        migrations.CreateModel(
            name='HomeSlider',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('title', models.CharField(max_length=200)),
                ('desktop_image', models.ImageField(upload_to='slider/desktop/')),
                ('mobile_image', models.ImageField(blank=True, null=True, upload_to='slider/mobile/')),
                ('link', models.URLField(max_length=500)),
                ('order', models.PositiveIntegerField(blank=True, null=True, unique=True)),
                ('is_active', models.BooleanField(default=True)),
                ('created_at', models.DateTimeField(auto_now_add=True)),
                ('updated_at', models.DateTimeField(auto_now=True)),
            ],
            options={
                'verbose_name': 'Home Slider',
                'verbose_name_plural': 'Home Sliders',
                'db_table': 'home_sliders',
                'ordering': ['order'],
            },
        ),
        migrations.CreateModel(
            name='PhoneOTP',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('phone_number', models.CharField(max_length=17)),
                ('otp', models.CharField(max_length=6)),
                ('created_at', models.DateTimeField(auto_now_add=True)),
                ('is_verified', models.BooleanField(default=False)),
                ('count', models.IntegerField(default=0)),
                ('last_attempt', models.DateTimeField(auto_now=True)),
            ],
            options={
                'db_table': 'phone_otps',
            },
        ),
        migrations.CreateModel(
            name='Position',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('name', models.CharField(max_length=100)),
                ('bp_required_min', models.PositiveIntegerField()),
                ('bp_required_max', models.PositiveIntegerField()),
                ('discount_percentage', models.DecimalField(decimal_places=2, max_digits=5, validators=[django.core.validators.MinValueValidator(0), django.core.validators.MaxValueValidator(100)])),
                ('commission_percentage', models.DecimalField(decimal_places=2, max_digits=5, validators=[django.core.validators.MinValueValidator(0), django.core.validators.MaxValueValidator(100)])),
                ('can_earn_commission', models.BooleanField(default=False)),
                ('monthly_quota', models.DecimalField(decimal_places=2, max_digits=10)),
                ('level_order', models.PositiveIntegerField(unique=True)),
                ('is_active', models.BooleanField(default=True)),
            ],
            options={
                'db_table': 'positions',
                'ordering': ['level_order'],
            },
        ),
        migrations.CreateModel(
            name='SuccessStory',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('title', models.CharField(max_length=200)),
                ('description', models.TextField(blank=True, null=True)),
                ('youtube_link', models.URLField(help_text='YouTube video link')),
                ('thumbnail', models.ImageField(blank=True, help_text='Thumbnail image for the video', null=True, upload_to='success_stories/')),
                ('position', models.PositiveIntegerField(default=0)),
                ('is_active', models.BooleanField(default=True)),
                ('created_at', models.DateTimeField(auto_now_add=True)),
                ('updated_at', models.DateTimeField(auto_now=True)),
            ],
            options={
                'verbose_name': 'Success Story',
                'verbose_name_plural': 'Success Stories',
                'db_table': 'success_stories',
                'ordering': ['position', '-created_at'],
            },
        ),
        migrations.CreateModel(
            name='Testimonial',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('name', models.CharField(max_length=100, validators=[django.core.validators.MinLengthValidator(2, 'Name must be at least 2 characters long')])),
                ('designation', models.CharField(help_text='Job title or role of the person', max_length=100)),
                ('content', models.TextField(validators=[django.core.validators.MinLengthValidator(10, 'Testimonial must be at least 10 characters long')])),
                ('image', models.ImageField(blank=True, help_text='Profile picture of the person', null=True, upload_to='testimonials/')),
                ('rating', models.PositiveSmallIntegerField(choices=[(1, '1 Stars'), (2, '2 Stars'), (3, '3 Stars'), (4, '4 Stars'), (5, '5 Stars')], default=5)),
                ('is_active', models.BooleanField(default=True)),
                ('display_order', models.PositiveIntegerField(default=0, help_text='Order in which testimonials are displayed')),
                ('created_at', models.DateTimeField(auto_now_add=True)),
                ('updated_at', models.DateTimeField(auto_now=True)),
            ],
            options={
                'verbose_name': 'Testimonial',
                'verbose_name_plural': 'Testimonials',
                'db_table': 'testimonials',
                'ordering': ['display_order', '-created_at'],
            },
        ),
        migrations.CreateModel(
            name='User',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('password', models.CharField(max_length=128, verbose_name='password')),
                ('last_login', models.DateTimeField(blank=True, null=True, verbose_name='last login')),
                ('is_superuser', models.BooleanField(default=False, help_text='Designates that this user has all permissions without explicitly assigning them.', verbose_name='superuser status')),
                ('first_name', models.CharField(blank=True, max_length=150, verbose_name='first name')),
                ('last_name', models.CharField(blank=True, max_length=150, verbose_name='last name')),
                ('is_staff', models.BooleanField(default=False, help_text='Designates whether the user can log into this admin site.', verbose_name='staff status')),
                ('is_active', models.BooleanField(default=True, help_text='Designates whether this user should be treated as active. Unselect this instead of deleting accounts.', verbose_name='active')),
                ('date_joined', models.DateTimeField(default=django.utils.timezone.now, verbose_name='date joined')),
                ('username', models.CharField(max_length=50, unique=True)),
                ('role', models.CharField(choices=[('ADMIN', 'Admin'), ('CUSTOMER', 'Customer'), ('MLM_MEMBER', 'MLM Member')], default='CUSTOMER', max_length=20)),
                ('phone_number', models.CharField(blank=True, max_length=10, null=True, unique=True)),
                ('email', models.EmailField(blank=True, max_length=254, null=True, unique=True)),
                ('groups', models.ManyToManyField(blank=True, help_text='The groups this user belongs to. A user will get all permissions granted to each of their groups.', related_name='user_set', related_query_name='user', to='auth.group', verbose_name='groups')),
                ('user_permissions', models.ManyToManyField(blank=True, help_text='Specific permissions for this user.', related_name='user_set', related_query_name='user', to='auth.permission', verbose_name='user permissions')),
            ],
            options={
                'db_table': 'users',
            },
        ),
        migrations.CreateModel(
            name='Category',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('name', models.CharField(max_length=100)),
                ('slug', models.SlugField(blank=True, max_length=150, null=True, unique=True)),
                ('description', models.TextField(blank=True, null=True)),
                ('image', models.ImageField(blank=True, null=True, upload_to='categories/')),
                ('is_active', models.BooleanField(default=True)),
                ('created_at', models.DateTimeField(auto_now_add=True)),
                ('updated_at', models.DateTimeField(auto_now=True)),
                ('parent', models.ForeignKey(blank=True, null=True, on_delete=django.db.models.deletion.SET_NULL, related_name='children', to='home.category')),
            ],
            options={
                'verbose_name': 'Category',
                'verbose_name_plural': 'Categories',
                'db_table': 'categories',
                'ordering': ['name'],
            },
        ),
        migrations.CreateModel(
            name='Customer',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('shipping_address', models.TextField()),
                ('billing_address', models.TextField()),
                ('user', models.OneToOneField(on_delete=django.db.models.deletion.CASCADE, related_name='customer', to=settings.AUTH_USER_MODEL)),
            ],
            options={
                'db_table': 'customers',
            },
        ),
        migrations.CreateModel(
            name='Menu',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('position', models.PositiveIntegerField(default=0)),
                ('is_active', models.BooleanField(default=True)),
                ('created_at', models.DateTimeField(auto_now_add=True)),
                ('updated_at', models.DateTimeField(auto_now=True)),
                ('category', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, related_name='menu_items', to='home.category')),
            ],
            options={
                'verbose_name': 'Menu',
                'verbose_name_plural': 'Menu',
                'db_table': 'menus',
                'ordering': ['position'],
            },
        ),
        migrations.CreateModel(
            name='MLMMember',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('member_id', models.CharField(max_length=50, unique=True)),
                ('current_month_purchase', models.DecimalField(decimal_places=2, default=0, max_digits=10)),
                ('total_bp', models.PositiveIntegerField(default=0)),
                ('is_active', models.BooleanField(default=True)),
                ('join_date', models.DateTimeField(default=django.utils.timezone.now)),
                ('total_earnings', models.DecimalField(decimal_places=2, default=0, max_digits=10)),
                ('sponsor', models.ForeignKey(null=True, on_delete=django.db.models.deletion.SET_NULL, related_name='downline', to='home.mlmmember')),
                ('user', models.OneToOneField(on_delete=django.db.models.deletion.CASCADE, related_name='mlm_profile', to=settings.AUTH_USER_MODEL)),
                ('position', models.ForeignKey(on_delete=django.db.models.deletion.PROTECT, to='home.position')),
            ],
            options={
                'db_table': 'mlm_members',
            },
        ),
        migrations.CreateModel(
            name='BankDetails',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('account_holder_name', models.CharField(max_length=100)),
                ('account_number', models.CharField(max_length=50)),
                ('ifsc_code', models.CharField(max_length=20)),
                ('bank_name', models.CharField(max_length=100)),
                ('branch_name', models.CharField(max_length=100)),
                ('is_verified', models.BooleanField(default=False)),
                ('verification_date', models.DateTimeField(blank=True, null=True)),
                ('created_at', models.DateTimeField(auto_now_add=True)),
                ('updated_at', models.DateTimeField(auto_now=True)),
                ('verified_by', models.ForeignKey(blank=True, null=True, on_delete=django.db.models.deletion.SET_NULL, related_name='verified_bank_accounts', to=settings.AUTH_USER_MODEL)),
                ('mlm_member', models.OneToOneField(on_delete=django.db.models.deletion.CASCADE, related_name='bank_details', to='home.mlmmember')),
            ],
            options={
                'db_table': 'bank_details',
            },
        ),
        migrations.CreateModel(
            name='Order',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('order_number', models.CharField(max_length=50, unique=True)),
                ('order_date', models.DateTimeField(auto_now_add=True)),
                ('status', models.CharField(choices=[('PENDING', 'Pending'), ('CONFIRMED', 'Confirmed'), ('SHIPPED', 'Shipped'), ('DELIVERED', 'Delivered'), ('CANCELLED', 'Cancelled')], default='PENDING', max_length=20)),
                ('total_amount', models.DecimalField(decimal_places=2, max_digits=10)),
                ('discount_amount', models.DecimalField(decimal_places=2, default=0, max_digits=10)),
                ('final_amount', models.DecimalField(decimal_places=2, max_digits=10)),
                ('shipping_address', models.TextField()),
                ('billing_address', models.TextField()),
                ('total_bp', models.PositiveIntegerField(default=0)),
                ('user', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, related_name='orders', to=settings.AUTH_USER_MODEL)),
            ],
            options={
                'db_table': 'orders',
            },
        ),
        migrations.CreateModel(
            name='Commission',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('amount', models.DecimalField(decimal_places=2, max_digits=10)),
                ('date', models.DateTimeField(auto_now_add=True)),
                ('is_paid', models.BooleanField(default=False)),
                ('payment_date', models.DateTimeField(blank=True, null=True)),
                ('level', models.PositiveIntegerField()),
                ('from_member', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, related_name='generated_commissions', to='home.mlmmember')),
                ('member', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, related_name='earned_commissions', to='home.mlmmember')),
                ('order', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, to='home.order')),
            ],
            options={
                'db_table': 'commissions',
            },
        ),
        migrations.CreateModel(
            name='Product',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('name', models.CharField(max_length=200)),
                ('slug', models.SlugField(max_length=250, unique=True)),
                ('description', models.TextField()),
                ('regular_price', models.DecimalField(decimal_places=2, max_digits=10)),
                ('selling_price', models.DecimalField(decimal_places=2, max_digits=10)),
                ('bp_value', models.PositiveIntegerField(default=0)),
                ('stock', models.PositiveIntegerField(default=0)),
                ('gst_percentage', models.DecimalField(decimal_places=2, default=0, max_digits=5)),
                ('is_featured', models.BooleanField(default=False, help_text='Show on homepage featured section')),
                ('is_bestseller', models.BooleanField(default=False, help_text='Show in bestseller section')),
                ('is_new_arrival', models.BooleanField(default=False, help_text='Show in new arrivals section')),
                ('is_trending', models.BooleanField(default=False, help_text='Show in trending section')),
                ('is_active', models.BooleanField(default=True)),
                ('created_at', models.DateTimeField(auto_now_add=True)),
                ('updated_at', models.DateTimeField(auto_now=True)),
                ('categories', models.ManyToManyField(related_name='products', to='home.category')),
            ],
            options={
                'db_table': 'products',
                'ordering': ['-created_at'],
            },
        ),
        migrations.CreateModel(
            name='OrderItem',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('quantity', models.PositiveIntegerField()),
                ('price', models.DecimalField(decimal_places=2, max_digits=10)),
                ('discount_percentage', models.DecimalField(decimal_places=2, default=0, max_digits=5)),
                ('final_price', models.DecimalField(decimal_places=2, max_digits=10)),
                ('bp_points', models.PositiveIntegerField(default=0)),
                ('order', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, related_name='items', to='home.order')),
                ('product', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, to='home.product')),
            ],
            options={
                'db_table': 'order_items',
            },
        ),
        migrations.CreateModel(
            name='ProductFeature',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('title', models.CharField(max_length=200)),
                ('content', models.TextField()),
                ('order', models.PositiveIntegerField(default=1)),
                ('product', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, related_name='features', to='home.product')),
            ],
            options={
                'db_table': 'product_features',
                'ordering': ['order'],
            },
        ),
        migrations.CreateModel(
            name='ProductImage',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('image', models.ImageField(upload_to='products/')),
                ('alt_text', models.CharField(blank=True, max_length=200)),
                ('is_feature', models.BooleanField(default=False)),
                ('order', models.PositiveIntegerField(default=1)),
                ('created_at', models.DateTimeField(auto_now_add=True)),
                ('product', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, related_name='images', to='home.product')),
            ],
            options={
                'db_table': 'product_images',
                'ordering': ['order'],
            },
        ),
        migrations.CreateModel(
            name='Wallet',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('balance', models.DecimalField(decimal_places=2, default=0, max_digits=10)),
                ('last_updated', models.DateTimeField(auto_now=True)),
                ('user', models.OneToOneField(on_delete=django.db.models.deletion.CASCADE, related_name='wallet', to=settings.AUTH_USER_MODEL)),
            ],
            options={
                'db_table': 'wallets',
            },
        ),
        migrations.CreateModel(
            name='WalletTransaction',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('amount', models.DecimalField(decimal_places=2, max_digits=10)),
                ('transaction_type', models.CharField(choices=[('COMMISSION', 'Commission'), ('WITHDRAWAL', 'Withdrawal'), ('REFUND', 'Refund')], max_length=20)),
                ('description', models.TextField()),
                ('created_at', models.DateTimeField(auto_now_add=True)),
                ('reference_id', models.CharField(blank=True, max_length=100, null=True)),
                ('wallet', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, related_name='transactions', to='home.wallet')),
            ],
            options={
                'db_table': 'wallet_transactions',
            },
        ),
        migrations.CreateModel(
            name='KYCDocument',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('document_type', models.CharField(choices=[('AADHAR', 'Aadhar Card'), ('PAN', 'PAN Card'), ('BANK_STATEMENT', 'Bank Statement'), ('CANCELLED_CHEQUE', 'Cancelled Cheque')], max_length=20)),
                ('document_number', models.CharField(max_length=50)),
                ('document_file', models.FileField(upload_to='kyc_documents/%Y/%m/')),
                ('status', models.CharField(choices=[('PENDING', 'Pending'), ('VERIFIED', 'Verified'), ('REJECTED', 'Rejected')], default='PENDING', max_length=20)),
                ('verification_date', models.DateTimeField(blank=True, null=True)),
                ('rejection_reason', models.TextField(blank=True)),
                ('created_at', models.DateTimeField(auto_now_add=True)),
                ('updated_at', models.DateTimeField(auto_now=True)),
                ('verified_by', models.ForeignKey(blank=True, null=True, on_delete=django.db.models.deletion.SET_NULL, related_name='verified_documents', to=settings.AUTH_USER_MODEL)),
                ('mlm_member', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, related_name='kyc_documents', to='home.mlmmember')),
            ],
            options={
                'db_table': 'kyc_documents',
                'unique_together': {('mlm_member', 'document_type')},
            },
        ),
        migrations.CreateModel(
            name='MetaTag',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('title', models.CharField(max_length=200)),
                ('description', models.TextField()),
                ('keywords', models.TextField(blank=True, help_text='Comma separated keywords')),
                ('og_title', models.CharField(blank=True, max_length=200, verbose_name='Open Graph Title')),
                ('og_description', models.TextField(blank=True, verbose_name='Open Graph Description')),
                ('og_image', models.ImageField(blank=True, upload_to='meta/og/', verbose_name='Open Graph Image')),
                ('twitter_title', models.CharField(blank=True, max_length=200)),
                ('twitter_description', models.TextField(blank=True)),
                ('twitter_image', models.ImageField(blank=True, upload_to='meta/twitter/')),
                ('canonical_url', models.URLField(blank=True)),
                ('page_type', models.CharField(choices=[('HOME', 'Home Page'), ('ABOUT', 'About Page'), ('CONTACT', 'Contact Page'), ('PRODUCT', 'Product Page'), ('CATEGORY', 'Category Page'), ('CUSTOM', 'Custom Page'), ('BLOG', 'Blog Page')], max_length=20)),
                ('is_default', models.BooleanField(default=False, help_text='Use as default meta for this page type')),
                ('created_at', models.DateTimeField(auto_now_add=True)),
                ('updated_at', models.DateTimeField(auto_now=True)),
                ('category', models.OneToOneField(blank=True, null=True, on_delete=django.db.models.deletion.CASCADE, to='home.category')),
                ('custom_page', models.OneToOneField(blank=True, null=True, on_delete=django.db.models.deletion.CASCADE, to='home.custompage')),
                ('product', models.OneToOneField(blank=True, null=True, on_delete=django.db.models.deletion.CASCADE, to='home.product')),
            ],
            options={
                'db_table': 'meta_tags',
                'constraints': [models.UniqueConstraint(condition=models.Q(('is_default', True)), fields=('page_type', 'is_default'), name='unique_default_meta_per_page_type'), models.CheckConstraint(condition=models.Q(models.Q(('category__isnull', True), ('custom_page__isnull', True), ('product__isnull', True)), models.Q(('category__isnull', True), ('custom_page__isnull', True), ('product__isnull', False)), models.Q(('category__isnull', False), ('custom_page__isnull', True), ('product__isnull', True)), models.Q(('category__isnull', True), ('custom_page__isnull', False), ('product__isnull', True)), _connector='OR'), name='only_one_reference_set')],
            },
        ),
    ]
