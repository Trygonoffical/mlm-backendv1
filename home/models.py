
import re
import os
import random
import string
from django.db import models
from django.contrib.auth.models import AbstractUser, BaseUserManager
from django.core.validators import EmailValidator, MinValueValidator, MaxValueValidator
from django.utils import timezone
from decimal import Decimal
from django.core.validators import RegexValidator

from datetime import timedelta
from django.core.exceptions import ValidationError
from django.db.models import Q, Max, F
from django.core.validators import MinLengthValidator
from django.db.models.signals import post_save
from django.dispatch import receiver 
import logging
from django.db.models import Sum,  Q
from django.dispatch import receiver
from django.db import transaction

logger = logging.getLogger(__name__)

# ------------------------ Cusom User Model Area ------------------------------------
class CustomUserManager(BaseUserManager):
    def create_user(self, username, password=None, **extra_fields):
        if not username:
            raise ValueError('Username is required')
            
        user = self.model(username=username, **extra_fields)
        
        # Set default password for customers, actual password for others
        if extra_fields.get('role') == 'CUSTOMER':
            user.set_password('default123')  # Default password for customers
        else:
            if not password:
                raise ValueError('Password required for non-customer users')
            user.set_password(password)
            
        user.save(using=self._db)
        return user

    def create_superuser(self, username, password=None, **extra_fields):
        extra_fields.setdefault('is_staff', True)
        extra_fields.setdefault('is_superuser', True)
        extra_fields.setdefault('role', 'ADMIN')
        return self.create_user(username, password, **extra_fields)

class User(AbstractUser):
    class Role(models.TextChoices):
        ADMIN = 'ADMIN', 'Admin'
        CUSTOMER = 'CUSTOMER', 'Customer'
        MLM_MEMBER = 'MLM_MEMBER', 'MLM Member'

    username = models.CharField(max_length=50, unique=True)
    role = models.CharField(max_length=20, choices=Role.choices, default=Role.CUSTOMER)
    phone_number = models.CharField(max_length=10, unique=True, null=True, blank=True)
    email = models.EmailField(unique=True, blank=True, null=True)
    
    objects = CustomUserManager()

    class Meta:
        db_table = 'users'
    
    def get_active_address(self):
        """Get the user's currently active address."""
        return self.addresses.filter(is_active=True).first()

    def set_active_address(self, address_id):
        """Set a specific address as active."""
        try:
            address = self.addresses.get(id=address_id)
            address.is_active = True
            address.save()
            return True
        except Address.DoesNotExist:
            return False

    def add_address(self, address_data):
        """Add a new address for the user."""
        if self.role not in ['CUSTOMER', 'MLM_MEMBER']:
            raise ValidationError("Only customers and MLM members can add addresses")
        
        address = Address.objects.create(
            user=self,
            **address_data
        )
        return address

# --------------------------------------Mulitple Address  -----------------------------------------

class Address(models.Model):
    user = models.ForeignKey('User', on_delete=models.CASCADE, related_name='addresses')
    name = models.CharField(max_length=100, help_text="Name for this address (e.g. Home, Office)")
    street_address = models.CharField(max_length=255)
    city = models.CharField(max_length=100)
    state = models.CharField(max_length=100)
    postal_code = models.CharField(max_length=10)
    is_active = models.BooleanField(default=False)
    
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        db_table = 'user_addresses'
        verbose_name_plural = 'Addresses'
        

    def save(self, *args, **kwargs):
        # If this address is being set as active
        if self.is_active:
            # Deactivate all other addresses for this user
            Address.objects.filter(user=self.user).exclude(pk=self.pk).update(is_active=False)
        
        # If this is the user's first address, make it active by default
        if not self.pk and not Address.objects.filter(user=self.user).exists():
            self.is_active = True

        super().save(*args, **kwargs)

    def clean(self):
        if self.user and self.user.role not in ['CUSTOMER' 'Member']:
            raise ValidationError("Only customers and Admin can have addresses")

    def __str__(self):
        return f"{self.name} - {self.user.username}"

# --------------------------------------Phone OTp -----------------------------------------
class PhoneOTP(models.Model):
    phone_number = models.CharField(max_length=17)
    otp = models.CharField(max_length=6)
    created_at = models.DateTimeField(auto_now_add=True)
    is_verified = models.BooleanField(default=False)
    count = models.IntegerField(default=0)
    last_attempt = models.DateTimeField(auto_now=True)
    
    def is_blocked(self):
        """Check if this phone number is currently blocked from receiving OTPs"""
        if self.count >= 5:
            time_elapsed = timezone.now() - self.last_attempt
            return time_elapsed < timedelta(minutes=30)
        return False

    def reset_if_expired(self):
        """Reset the counter if the blocking period has expired"""
        if self.count >= 5:
            time_elapsed = timezone.now() - self.last_attempt
            if time_elapsed >= timedelta(minutes=30):
                self.count = 0
                # Also important: update the last_attempt time
                self.last_attempt = timezone.now()
                self.save()
                return True
        return False
    
    def time_remaining(self):
        """Return the time remaining in minutes before unblocking"""
        if not self.is_blocked():
            return 0
            
        time_elapsed = timezone.now() - self.last_attempt
        remaining_seconds = max(0, (timedelta(minutes=30) - time_elapsed).total_seconds())
        return int(remaining_seconds // 60)

    class Meta:
        db_table = 'phone_otps'


#------------------------------------ Categoeis Model -----------------------------------------
class Category(models.Model):
    name = models.CharField(max_length=100)
    slug = models.SlugField(max_length=150, unique=True , null=True, blank=True)
    description = models.TextField(null=True, blank=True)
    image = models.ImageField(upload_to='categories/', null=True, blank=True)
    parent = models.ForeignKey('self', on_delete=models.SET_NULL, null=True, blank=True, related_name='children')
    is_active = models.BooleanField(default=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        db_table = 'categories'
        verbose_name = 'Category'
        verbose_name_plural = 'Categories'
        ordering = ['name']

    def __str__(self):
        return self.name

# -------------------------------------------------- Product Model and featues -----------------------------
class ProductImage(models.Model):
    product = models.ForeignKey('Product', on_delete=models.CASCADE, related_name='images')
    image = models.ImageField(upload_to='products/')
    alt_text = models.CharField(max_length=200, blank=True)
    is_feature = models.BooleanField(default=False)
    order = models.PositiveIntegerField(default=1)
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        db_table = 'product_images'
        ordering = ['order']

    def save(self, *args, **kwargs):
        if self.is_feature:
            # Set all other images of this product to not feature
            ProductImage.objects.filter(product=self.product).exclude(id=self.id).update(is_feature=False)
        super().save(*args, **kwargs)

class Product(models.Model):
    name = models.CharField(max_length=200)
    slug = models.SlugField(max_length=250, unique=True)
    HSN_Code = models.SlugField(max_length=50, null=True)
    description = models.TextField()
    regular_price = models.DecimalField(max_digits=10, decimal_places=2)
    selling_price = models.DecimalField(max_digits=10, decimal_places=2)
    bp_value = models.PositiveIntegerField(default=0)  # BP points for this product
    categories = models.ManyToManyField(Category, related_name='products')
    stock = models.PositiveIntegerField(default=0)

    # GST field
    gst_percentage = models.DecimalField(max_digits=5, decimal_places=2, default=0)

    # Homepage Display Fields
    is_featured = models.BooleanField(default=False, help_text="Show on homepage featured section")
    is_bestseller = models.BooleanField(default=False, help_text="Show in bestseller section")
    is_new_arrival = models.BooleanField(default=False, help_text="Show in new arrivals section")
    is_trending = models.BooleanField(default=False, help_text="Show in trending section")


    is_active = models.BooleanField(default=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        db_table = 'products'
        ordering = ['-created_at']

    def __str__(self):
        return self.name

    @property
    def discount_percentage(self):
        if self.regular_price > 0:
            discount = ((self.regular_price - self.selling_price) / self.regular_price) * 100
            return round(discount, 2)
        return 0

    @property
    def feature_image(self):
        return self.images.filter(is_feature=True).first() or self.images.first()

    def get_absolute_url(self):
        return f"/product/{self.slug}/"

    def get_feature_image_url(self, request=None):
        """
        Get the full URL of the feature image
        """
        try:
            image = self.images.filter(is_feature=True).first() or self.images.first()
            if image and image.image:
                if request:
                    # If request is provided, use build_absolute_uri
                    return request.build_absolute_uri(image.image.url)
                # Fallback to a more generic method
                from django.conf import settings
                return f"{settings.SITE_URL}{image.image.url}"
            return None
        except Exception as e:
            logger.error(f"Error getting feature image URL: {str(e)}")
            return None

class ProductFeature(models.Model):
    product = models.ForeignKey(Product, on_delete=models.CASCADE, related_name='features')
    title = models.CharField(max_length=200)
    content = models.TextField()
    order = models.PositiveIntegerField(default=1)
    
    class Meta:
        db_table = 'product_features'
        ordering = ['order']
    
    def __str__(self):
        return f"{self.product.name} - {self.title}"
    

class ProductFAQ(models.Model):
    product = models.ForeignKey(Product, on_delete=models.CASCADE, related_name='faq')
    title = models.CharField(max_length=200)
    content = models.TextField()
    order = models.PositiveIntegerField(default=1)
    
    class Meta:
        db_table = 'product_faq'
        ordering = ['order']
    
    def __str__(self):
        return f"{self.product.name} - {self.title}"
    

    
class Customer(models.Model):
    user = models.OneToOneField(
        User,
        on_delete=models.CASCADE,
        related_name='customer'
    )
    shipping_address = models.TextField()
    billing_address = models.TextField()

    class Meta:
        db_table = 'customers'

# ------------------------------------------------------ Order Area --------------------------------------------------------
class Order(models.Model):
    class OrderStatus(models.TextChoices):
        PENDING = 'PENDING', 'Pending'
        CONFIRMED = 'CONFIRMED', 'Confirmed'
        SHIPPED = 'SHIPPED', 'Shipped'
        DELIVERED = 'DELIVERED', 'Delivered'
        CANCELLED = 'CANCELLED', 'Cancelled'
        RETURN_INITIATED = 'RETURN_INITIATED', 'Return Initiated'
        RETURNED = 'RETURNED', 'Returned'

    class OrderType(models.TextChoices):
        ONLINE = 'ONLINE', 'Online'
        COD = 'COD', 'Cod'
        

    user = models.ForeignKey(User, on_delete=models.CASCADE, related_name='orders')
    order_number = models.CharField(max_length=50, unique=True)
    order_date = models.DateTimeField(auto_now_add=True)
    status = models.CharField(max_length=20, choices=OrderStatus.choices, default=OrderStatus.PENDING)
    orderType = models.CharField(max_length=20, choices=OrderType.choices, default=OrderType.ONLINE)
    total_amount = models.DecimalField(max_digits=10, decimal_places=2)
    discount_amount = models.DecimalField(max_digits=10, decimal_places=2, default=0)
    
    final_amount = models.DecimalField(max_digits=10, decimal_places=2)
    shipping_address = models.TextField()
    billing_address = models.TextField()
    total_bp = models.PositiveIntegerField(default=0)  # Total BP points for the order
    razorpay_order_id = models.CharField(max_length=100, null=True, blank=True)
    payment_id = models.CharField(max_length=100, null=True, blank=True)
    discount_percentage = models.DecimalField(max_digits=5, decimal_places=2, default=0)
    bp_processed = models.BooleanField(default=False, help_text="Flag to track if BP has been processed for this order")
    class Meta:
        db_table = 'orders'

    
        
class OrderItem(models.Model):
    order = models.ForeignKey(Order, on_delete=models.CASCADE, related_name='items')
    product = models.ForeignKey(Product, on_delete=models.CASCADE)
    quantity = models.PositiveIntegerField()
    price = models.DecimalField(max_digits=10, decimal_places=2)
    discount_percentage = models.DecimalField(max_digits=5, decimal_places=2, default=0)
    final_price = models.DecimalField(max_digits=10, decimal_places=2)
    bp_points = models.PositiveIntegerField(default=0)  # BP points for this item
    gst_amount = models.DecimalField(max_digits=10, decimal_places=2, default=0)
    discount_amount = models.DecimalField(max_digits=10, decimal_places=2, default=0)
    class Meta:
        db_table = 'order_items'


# ----------------------------------- MLM Member Model Area -----------------------------------------------

class Position(models.Model):
    name = models.CharField(max_length=100)  # e.g., "Basic Member", "Silver", "Gold"
    bp_required_min = models.PositiveIntegerField() # Min BP points required for this position
    bp_required_max = models.PositiveIntegerField()  # Max BP points required for this position

    discount_percentage = models.DecimalField(
        max_digits=5, 
        decimal_places=2,
        validators=[MinValueValidator(0), MaxValueValidator(100)]
    )

    commission_percentage = models.DecimalField(
        max_digits=5, 
        decimal_places=2,
        validators=[MinValueValidator(0), MaxValueValidator(100)]
    )

    can_earn_commission = models.BooleanField(default=False)  # False for Basic Member, True for others
    monthly_quota = models.DecimalField(max_digits=10, decimal_places=2)  # Required monthly purchase
    level_order = models.PositiveIntegerField(unique=True)  # To maintain hierarchy
    is_active = models.BooleanField(default=True)

    class Meta:
        db_table = 'positions'
        ordering = ['level_order']

    def __str__(self):
        return f"{self.name} (BP Required: {self.bp_required_min}-{self.bp_required_max})"


class MLMMember(models.Model):
    user = models.OneToOneField(User, on_delete=models.CASCADE, related_name='mlm_profile')
    member_id = models.CharField(max_length=50, unique=True)
    position = models.ForeignKey(Position, on_delete=models.PROTECT)
    sponsor = models.ForeignKey('self', on_delete=models.SET_NULL, null=True, related_name='downline')
    current_month_purchase = models.DecimalField(max_digits=10, decimal_places=2, default=0)
    total_bp = models.PositiveIntegerField(default=0)
    is_active = models.BooleanField(default=True)
    join_date = models.DateTimeField(default=timezone.now)
    total_earnings = models.DecimalField(max_digits=10, decimal_places=2, default=0)
    created_at = models.DateTimeField(default=timezone.now ) 
    updated_at = models.DateTimeField(default=timezone.now ) 

    # Add this to your existing MLMMember model
    first_purchase_bonus_received = models.BooleanField(
        default=False, 
        help_text="Flag to track if first purchase bonus has been received"
    )

    first_payment_complete = models.BooleanField(
        default=False, 
        help_text="Flag to track if first payment requirement has been met"
    )

    first_payment_amount = models.DecimalField(
        max_digits=10, 
        decimal_places=2, 
        default=0, 
        help_text="Amount of first payment made by member"
    )

    # Additional commission tracking fields
    monthly_quota_maintained = models.BooleanField(
        default=False,
        help_text="Flag indicating if monthly quota is maintained for current month"
    )
    last_commission_calculation = models.DateTimeField(
        null=True, 
        blank=True,
        help_text="Date of last commission calculation"
    )

    class Meta:
        db_table = 'mlm_members'

    def generate_member_id(self):
        # Generate an 8-digit member ID
        while True:
            # Generate random 8-digit number
            member_id = ''.join(random.choices(string.digits, k=8))
            
            # Check if this ID already exists
            if not MLMMember.objects.filter(member_id=member_id).exists():
                return member_id
            
    def save(self, *args, **kwargs):
        if not self.member_id:
            self.member_id = self.generate_member_id()
        super().save(*args, **kwargs)

    def check_position_upgrade(self):
        """Check and upgrade position based on BP points"""
        if self.position.level_order == 1:
            return False
        
        higher_position = Position.objects.filter(
            bp_required_min__lte=self.total_bp,
            level_order__gt=self.position.level_order,
            is_active=True
        ).order_by('level_order').first()
        
        if higher_position:
            self.position = higher_position
            self.save()

            # Create a notification about position upgrade
            Notification.objects.create(
                title='Position Upgraded',
                message=f'Congratulations! Your position has been upgraded to {higher_position.name}.',
                notification_type='SYSTEM',
                recipient=self
            )
            return True

        return False
    
    def add_bp(self, bp_points):
        """
        Add BP points with cap for Level 1 (Preferred Customer)
        
        Args:
            bp_points: The BP points to add
            
        Returns:
            int: The actual BP points added
        """
        # Check if this is a Level 1 position (Preferred Customer)
        is_preferred_customer = self.position.level_order == 1
        
        if is_preferred_customer:
            # Cap BP at 99 for Preferred Customers
            max_bp = 99
            current_bp = self.total_bp
            
            # Calculate how many points we can add without exceeding the cap
            points_to_add = min(bp_points, max_bp - current_bp)
            
            # If already at or over cap, add no points
            if points_to_add <= 0:
                return 0
                
            # Update BP with capped value
            self.total_bp += points_to_add
            self.save(update_fields=['total_bp'])
            
            return points_to_add
        else:
            # For higher levels, add BP normally
            self.total_bp += bp_points
            self.save(update_fields=['total_bp'])
            
            return bp_points
        
    def toggle_status(self):
        """Toggle status for both MLMMember and associated User"""
        
        
        with transaction.atomic():
            # Toggle MLMMember status
            self.is_active = not self.is_active
            self.save(update_fields=['is_active'])
            
            # Toggle User status
            self.user.is_active = self.is_active
            self.user.save(update_fields=['is_active'])
            
        return self.is_active
    
    # def check_monthly_quota_maintenance(self, month=None):
    #     """
    #     Check if the member has met their monthly purchase quota
        
    #     Args:
    #         month (datetime, optional): Month to check. 
    #                                     Defaults to current month.
        
    #     Returns:
    #         bool: Whether monthly quota is maintained
    #     """
    #     if not month:
    #         month = timezone.now()
        
    #     # Calculate total purchases for the given month
    #     total_monthly_purchases = Order.objects.filter(
    #         user=self.user,
    #         order_date__year=month.year,
    #         order_date__month=month.month,
    #         status__in=['CONFIRMED', 'SHIPPED', 'DELIVERED']
    #     ).aggregate(
    #         total_purchase=models.Sum('final_amount')
    #     )['total_purchase'] or Decimal('0.00')
        
    #     # Compare with position's monthly quota
    #     quota_maintained = total_monthly_purchases >= self.position.monthly_quota
        
    #     # Update the monthly_quota_maintained field
    #     if self.monthly_quota_maintained != quota_maintained:
    #         self.monthly_quota_maintained = quota_maintained
    #         self.save(update_fields=['monthly_quota_maintained'])
            
    #     return quota_maintained
    def check_monthly_quota_maintenance(self, month=None):
        """
        Check if the member has met their monthly purchase quota
        
        Args:
            month (datetime, optional): Month to check. 
                                        Defaults to current month.
        
        Returns:
            bool: Whether monthly quota is maintained
        """
        from django.db.models import Sum
        from django.utils import timezone
        from decimal import Decimal
        
        if not month:
            month = timezone.now()
        
        try:
            # Get the member's monthly quota requirement
            monthly_quota = self.position.monthly_quota or Decimal('0.00')
            
            # Calculate total purchases for the given month
            total_monthly_purchases = Order.objects.filter(
                user=self.user,
                order_date__year=month.year,
                order_date__month=month.month,
                status__in=['CONFIRMED', 'SHIPPED', 'DELIVERED']
            ).aggregate(
                total_purchase=Sum('final_amount')
            )['total_purchase'] or Decimal('0.00')
            
            # Special case: If monthly quota is 0, always return True
            if monthly_quota <= 0:
                quota_maintained = True
            else:
                # Compare with position's monthly quota
                quota_maintained = total_monthly_purchases >= monthly_quota
            
            # Log the values for debugging
            print(f"Member {self.member_id}: Monthly quota = {monthly_quota}, " 
                f"Total purchases = {total_monthly_purchases}, " 
                f"Is maintained: {quota_maintained}")
            
            # Update the monthly_quota_maintained field
            if not hasattr(self, 'monthly_quota_maintained') or self.monthly_quota_maintained != quota_maintained:
                self.monthly_quota_maintained = quota_maintained
                self.save(update_fields=['monthly_quota_maintained'])
            
            return quota_maintained
            
        except Exception as e:
            # Log any errors
            print(f"Error checking monthly quota for member {self.member_id}: {str(e)}")
            # Default to False in case of errors
            return False
        
    def get_current_month_commission_estimate(self):
        """
        Calculate estimated commission for current month based on downline purchases
        
        Returns:
            Decimal: Estimated commission amount
        """
        from decimal import Decimal
        from django.utils import timezone
        from django.db.models import Sum
        
        # Only members with positions that can earn commission are eligible
        if not self.position.can_earn_commission:
            return Decimal('0.00')
            
        # Only members who maintain monthly quota are eligible
        if not self.monthly_quota_maintained:
            return Decimal('0.00')
            
        # Get current month period
        today = timezone.now()
        first_day_current_month = today.replace(day=1, hour=0, minute=0, second=0, microsecond=0)
        
        # Initialize total commission
        total_commission = Decimal('0.00')
        
        # Get all direct downline members
        direct_downline = MLMMember.objects.filter(sponsor=self, is_active=True)
        
        for downline in direct_downline:
            # Skip if downline's position percentage is equal or higher
            if downline.position.discount_percentage >= self.position.discount_percentage:
                continue
                
            # Calculate percentage difference
            percentage_diff = self.position.discount_percentage - downline.position.discount_percentage
            
            # Get downline's current month orders
            downline_orders = Order.objects.filter(
                user=downline.user,
                order_date__gte=first_day_current_month,
                status__in=['CONFIRMED', 'SHIPPED', 'DELIVERED']
            )
            
            # Calculate purchase amount
            purchase_amount = downline_orders.aggregate(
                total=Sum('final_amount')
            )['total'] or Decimal('0.00')
            
            # Calculate commission
            commission = (purchase_amount * Decimal(str(percentage_diff)) / 100)
            total_commission += commission
            
        return total_commission
    
    def __str__(self):
        return f"{self.member_id} - {self.user.username} ({self.position.name})"
    # def check_monthly_quota_maintenance(self, month=None):
    #     """
    #     Check if the member has met their monthly purchase quota
        
    #     Args:
    #         month (datetime, optional): Month to check. 
    #                                     Defaults to current month.
        
    #     Returns:
    #         bool: Whether monthly quota is maintained
    #     """
    #     if not month:
    #         month = timezone.now()
        
    #     # Calculate total purchases for the given month
    #     total_monthly_purchases = Order.objects.filter(
    #         user=self.user,
    #         order_date__year=month.year,
    #         order_date__month=month.month,
    #         status__in=['CONFIRMED', 'SHIPPED', 'DELIVERED']
    #     ).aggregate(
    #         total_purchase=models.Sum('final_amount')
    #     )['total_purchase'] or Decimal('0.00')
        
    #     # Compare with position's monthly quota
    #     return total_monthly_purchases >= self.position.monthly_quota

class KYCDocument(models.Model):
    class DocumentType(models.TextChoices):
        AADHAR = 'AADHAR', 'Aadhar Card'
        PAN = 'PAN', 'PAN Card'
        BANK_STATEMENT = 'BANK_STATEMENT', 'Bank Statement'
        CANCELLED_CHEQUE = 'CANCELLED_CHEQUE', 'Cancelled Cheque'

    class VerificationStatus(models.TextChoices):
        PENDING = 'PENDING', 'Pending'
        VERIFIED = 'VERIFIED', 'Verified'
        REJECTED = 'REJECTED', 'Rejected'

    mlm_member = models.ForeignKey('MLMMember', on_delete=models.CASCADE, related_name='kyc_documents')
    document_type = models.CharField(max_length=20, choices=DocumentType.choices)
    document_number = models.CharField(max_length=50)  # Aadhar number, PAN number etc.
    document_file = models.FileField(upload_to='kyc_documents/%Y/%m/')
    status = models.CharField(
        max_length=20, 
        choices=VerificationStatus.choices,
        default=VerificationStatus.PENDING
    )
    verified_by = models.ForeignKey(
        'User', 
        on_delete=models.SET_NULL, 
        null=True, 
        blank=True,
        related_name='verified_documents'
    )
    verification_date = models.DateTimeField(null=True, blank=True)
    rejection_reason = models.TextField(blank=True)
    created_at = models.DateTimeField(auto_now_add=True)
    
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        db_table = 'kyc_documents'
        unique_together = ['mlm_member', 'document_type']

    def __str__(self):
        return f"{self.mlm_member.user.username} - {self.get_document_type_display()}"

class BankDetails(models.Model):
    mlm_member = models.OneToOneField('MLMMember', on_delete=models.CASCADE, related_name='bank_details')
    account_holder_name = models.CharField(max_length=100)
    account_number = models.CharField(max_length=50)
    ifsc_code = models.CharField(max_length=20)
    bank_name = models.CharField(max_length=100)
    branch_name = models.CharField(max_length=100)
    is_verified = models.BooleanField(default=False)
    verification_date = models.DateTimeField(null=True, blank=True)
    verified_by = models.ForeignKey(
        'User',
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name='verified_bank_accounts'
    )
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        db_table = 'bank_details'

    def __str__(self):
        return f"{self.mlm_member.user.username}'s Bank Details"
    


class Commission(models.Model): 
    member = models.ForeignKey(MLMMember, on_delete=models.CASCADE, related_name='earned_commissions') 
    from_member = models.ForeignKey(MLMMember, on_delete=models.CASCADE, related_name='generated_commissions') 
    order = models.ForeignKey(Order, on_delete=models.CASCADE) 
    amount = models.DecimalField(max_digits=10, decimal_places=2) 
    date = models.DateTimeField(auto_now_add=True) 
    is_paid = models.BooleanField(default=False) 
    payment_date = models.DateTimeField(null=True, blank=True) 
    level = models.PositiveIntegerField()  # Level in the MLM hierarchy 
    # Add this to your existing Commission model 
    is_first_purchase_bonus = models.BooleanField( 
        default=False,  
        help_text="Flag to indicate if this is a first purchase bonus commission" 
    ) 
    is_reversed = models.BooleanField(default=False) 
    reversed_at = models.DateTimeField(null=True, blank=True) 

    # Type of commission
    COMMISSION_TYPES = (
        ('ORDER', 'Order Commission'),
        ('MONTHLY', 'Monthly Calculation'),
        ('BONUS', 'First Purchase Bonus'),
        ('SPECIAL', 'Special Promotion')
    )
    commission_type = models.CharField(max_length=10, choices=COMMISSION_TYPES, default='MONTHLY')
    
    # Details about the commission (JSON)
    details = models.JSONField(default=dict, blank=True)
    
    # For monthly calculations, track the month this represents
    calculation_month = models.DateField(null=True, blank=True, 
        help_text="For monthly calculations, the first day of the month this calculation represents")
    
    class Meta:
        db_table = 'commissions'
        ordering = ['-date']
        indexes = [
            models.Index(fields=['member', 'date']),
            models.Index(fields=['from_member', 'date']),
            models.Index(fields=['calculation_month']),
        ]
    def __str__(self):
        return f"Commission {self.id}: {self.amount} to {self.member.member_id} from {self.from_member.member_id}"
    
    # def save(self, *args, **kwargs):
    #     # If this is a monthly calculation, set the calculation_month
    #     if self.commission_type == 'MONTHLY' and not self.calculation_month:
    #         # Set to the first day of the current month
    #         today = timezone.now()
    #         self.calculation_month = today.replace(day=1).date()
            
    #     # Add details if they don't exist
    #     if not self.details:
    #         self.details = {
    #             'member_position': self.member.position.name,
    #             'member_percentage': float(self.member.position.discount_percentage),
    #             'from_member_position': self.from_member.position.name,
    #             'from_member_percentage': float(self.from_member.position.discount_percentage),
    #             'difference_percentage': float(self.member.position.discount_percentage - self.from_member.position.discount_percentage)
    #         }
            
    #     super().save(*args, **kwargs)
        
    #     # If this is being marked as paid, update member's total earnings
    #     if self.is_paid and self.payment_date is None:
    #         self.payment_date = timezone.now()
    #         self.member.total_earnings += self.amount
    #         self.member.save(update_fields=['total_earnings'])
    def save(self, *args, **kwargs):
        # Check if this is a new commission or an existing one being modified
        is_new = self.pk is None
        
        # If this is an existing commission, get the old version to check for changes
        if not is_new:
            old_commission = Commission.objects.get(pk=self.pk)
            is_newly_paid = not old_commission.is_paid and self.is_paid
        else:
            is_newly_paid = self.is_paid
        
        # Set calculation_month for monthly commissions
        if self.commission_type == 'MONTHLY' and not self.calculation_month:
            today = timezone.now()
            self.calculation_month = today.replace(day=1).date()
        
        # Add details if they don't exist
        if not self.details:
            self.details = {
                'member_position': self.member.position.name,
                'member_percentage': float(self.member.position.discount_percentage),
                'from_member_position': self.from_member.position.name,
                'from_member_percentage': float(self.from_member.position.discount_percentage),
                'difference_percentage': float(self.member.position.discount_percentage - self.from_member.position.discount_percentage)
            }
        
        # Save the commission
        super().save(*args, **kwargs)
        
        # If this commission is being marked as paid for the first time
        if is_newly_paid:
            self.payment_date = timezone.now()
            
            # Use a transaction to ensure all or nothing updates
            with transaction.atomic():
                # 1. Update member's total earnings
                self.member.total_earnings += self.amount
                self.member.save(update_fields=['total_earnings'])
                
                # 2. Add to wallet balance
                wallet, created = Wallet.objects.get_or_create(user=self.member.user)
                
                # 3. Create wallet transaction record
                WalletTransaction.objects.create(
                    wallet=wallet,
                    amount=self.amount,
                    transaction_type='COMMISSION',
                    description=f'Commission from {self.from_member.user.get_full_name() or self.from_member.member_id}',
                    reference_id=str(self.id)
                )
                
                # 4. Update wallet balance
                wallet.balance += self.amount
                wallet.save()
                
                # 5. Save the payment date on the commission
                if not self.payment_date:
                    self.payment_date = timezone.now()
                    super().save(update_fields=['payment_date'])

    @classmethod
    def get_monthly_earnings(cls, member, year=None, month=None):
        """
        Get monthly earnings for a specific member
        If year and month are not provided, returns data for all months
        """
        from django.db.models.functions import TruncMonth
        
        # Base queryset
        queryset = cls.objects.filter(member=member)
        
        # Filter by year and month if provided
        if year and month:
            start_date = timezone.datetime(year, month, 1)
            if month == 12:
                end_date = timezone.datetime(year+1, 1, 1)
            else:
                end_date = timezone.datetime(year, month+1, 1)
                
            queryset = queryset.filter(date__gte=start_date, date__lt=end_date)
        
        # Aggregate by month
        monthly_data = queryset.annotate(
            month=TruncMonth('date')
        ).values('month').annotate(
            total=Sum('amount'),
            paid=Sum('amount', filter=Q(is_paid=True)),
            pending=Sum('amount', filter=Q(is_paid=False))
        ).order_by('month')
        
        return monthly_data
    
    # @classmethod
    @classmethod
    def calculate_commissions(cls, order):
        """
        Calculate commissions for an order based on pure differential model
        """
        try:
            # Get the member who made the purchase
            member = order.user.mlm_profile
            
            # List to store calculated commissions
            commissions = []
            
            # Track current sponsor
            current_sponsor = member.sponsor
            
            # Traverse up the network
            level = 1
            while current_sponsor and level <= 5:  # Limit to 5 levels
                try:
                    # Check if sponsor can earn commission
                    if not current_sponsor.position.can_earn_commission:
                        current_sponsor = current_sponsor.sponsor
                        level += 1
                        continue
                    
                    # Check monthly quota maintenance
                    if not current_sponsor.check_monthly_quota_maintenance():
                        current_sponsor = current_sponsor.sponsor
                        level += 1
                        continue
                    
                    # Get position percentages
                    sponsor_percentage = current_sponsor.position.discount_percentage
                    member_percentage = member.position.discount_percentage
                    
                    # Only calculate commission if sponsor has higher percentage
                    if sponsor_percentage <= member_percentage:
                        # No commission if sponsor's percentage is not higher
                        current_sponsor = current_sponsor.sponsor
                        level += 1
                        continue
                    
                    # Calculate differential percentage
                    differential_percentage = sponsor_percentage - member_percentage
                    
                    # Calculate commission amount based on differential percentage
                    commission_amount = (
                        order.final_amount * 
                        Decimal(str(differential_percentage)) / 
                        Decimal('100')
                    )
                    
                    # Create regular commission record
                    if commission_amount > 0:
                        regular_commission = cls(
                            member=current_sponsor,
                            from_member=member,
                            order=order,
                            amount=commission_amount,
                            level=level,
                            is_paid=True,
                            is_first_purchase_bonus=False,
                            commission_type='ORDER'
                        )
                        commissions.append(regular_commission)
                    
                    # Handle first purchase bonus (only for direct sponsor)
                    # IMPORTANT: We'll skip this if there's already a first purchase bonus
                    if not member.first_purchase_bonus_received and level == 1:
                        # Check if a bonus already exists
                        existing_bonus = cls.objects.filter(
                            from_member=member,
                            is_first_purchase_bonus=True
                        ).exists()
                        
                        if not existing_bonus:
                            # Create separate bonus commission
                            first_bonus = Decimal('1000.00')  # First purchase bonus amount
                            bonus_commission = cls(
                                member=current_sponsor,
                                from_member=member,
                                order=order,
                                amount=first_bonus,
                                level=level,
                                is_paid=True,
                                is_first_purchase_bonus=True,
                                commission_type='BONUS'
                            )
                            commissions.append(bonus_commission)
                            
                            # Mark first purchase bonus as received
                            member.first_purchase_bonus_received = True
                            member.save()
                    
                    # Move to next sponsor
                    current_sponsor = current_sponsor.sponsor
                    level += 1
                
                except Exception as sponsor_error:
                    logger.error(f"Error processing sponsor {current_sponsor.id}: {str(sponsor_error)}")
                    break
            
            return commissions
        
        except Exception as e:
            logger.error(f"Error calculating commissions: {str(e)}")
            return []
    # def calculate_commissions(cls, order):
    #     """
    #     Calculate commissions for an order based on pure differential model
    #     Commission is based on the difference between position percentages
        
    #     Args:
    #         order (Order): The order to calculate commissions for
        
    #     Returns:
    #         list: Commission objects to be created
    #     """
    #     try:
    #         # Get the member who made the purchase
    #         member = order.user.mlm_profile
            
    #         # List to store calculated commissions
    #         commissions = []
            
    #         # Track current sponsor
    #         current_sponsor = member.sponsor
            
    #         # Traverse up the network
    #         level = 1
    #         while current_sponsor and level <= 5:  # Limit to 5 levels
    #             try:
    #                 # Check if sponsor can earn commission
    #                 if not current_sponsor.position.can_earn_commission:
    #                     current_sponsor = current_sponsor.sponsor
    #                     level += 1
    #                     continue
                    
    #                 # Check monthly quota maintenance
    #                 if not current_sponsor.check_monthly_quota_maintenance():
    #                     current_sponsor = current_sponsor.sponsor
    #                     level += 1
    #                     continue
                    
    #                 # Get position percentages
    #                 sponsor_percentage = current_sponsor.position.discount_percentage
    #                 member_percentage = member.position.discount_percentage
                    
    #                 # Only calculate commission if sponsor has higher percentage
    #                 if sponsor_percentage <= member_percentage:
    #                     # No commission if sponsor's percentage is not higher
    #                     current_sponsor = current_sponsor.sponsor
    #                     level += 1
    #                     continue
                    
    #                 # Calculate differential percentage
    #                 differential_percentage = sponsor_percentage - member_percentage
                    
    #                 # Calculate commission amount based on differential percentage
    #                 commission_amount = (
    #                     order.final_amount * 
    #                     Decimal(str(differential_percentage)) / 
    #                     Decimal('100')
    #                 )
                    
    #                 # First purchase bonus should be a separate commission record
    #                 is_first_purchase_bonus = False
                    
    #                 # Create regular commission
    #                 regular_commission = cls(
    #                     member=current_sponsor,
    #                     from_member=member,
    #                     order=order,
    #                     amount=commission_amount,
    #                     level=level,
    #                     is_paid=True,
    #                     is_first_purchase_bonus=False,
    #                     commission_type='ORDER'
    #                 )
    #                 commissions.append(regular_commission)
                    
    #                 # Handle first purchase bonus (only for direct sponsor)
    #                 if (not member.first_purchase_bonus_received and level == 1):
    #                     # Create separate bonus commission
    #                     first_bonus = Decimal('1000.00')  # First purchase bonus amount
    #                     bonus_commission = cls(
    #                         member=current_sponsor,
    #                         from_member=member,
    #                         order=order,
    #                         amount=first_bonus,
    #                         level=level,
    #                         is_paid=True,
    #                         is_first_purchase_bonus=True,
    #                         commission_type='BONUS'
    #                     )
    #                     commissions.append(bonus_commission)
                        
    #                     # Mark first purchase bonus as received
    #                     member.first_purchase_bonus_received = True
    #                     member.save()
                    
    #                 # Move to next sponsor
    #                 current_sponsor = current_sponsor.sponsor
    #                 level += 1
                
    #             except Exception as sponsor_error:
    #                 logger.error(f"Error processing sponsor {current_sponsor.id}: {str(sponsor_error)}")
    #                 break
            
    #         return commissions
        
    #     except Exception as e:
    #         logger.error(f"Error calculating commissions: {str(e)}")
    #         return []
    # @classmethod
    # def calculate_commissions(cls, order):
    #     """
    #     Calculate commissions for an order, considering first purchase and monthly quota
        
    #     Args:
    #         order (Order): The order to calculate commissions for
        
    #     Returns:
    #         list: Commission objects to be created
    #     """
    #     try:
    #         # Get the member who made the purchase
    #         member = order.user.mlm_profile
            
    #         # List to store calculated commissions
    #         commissions = []
            
    #         # Track current sponsor
    #         current_sponsor = member.sponsor
            
    #         # Traverse up the network
    #         level = 1
    #         while current_sponsor and level <= 5:  # Limit to 5 levels
    #             try:
    #                 # Check if sponsor can earn commission
    #                 if not current_sponsor.position.can_earn_commission:
    #                     current_sponsor = current_sponsor.sponsor
    #                     level += 1
    #                     continue
                    
    #                 # Check monthly quota maintenance
    #                 if not current_sponsor.check_monthly_quota_maintenance():
    #                     current_sponsor = current_sponsor.sponsor
    #                     level += 1
    #                     continue
                    
    #                 # Calculate commission rate for this level
    #                 # You might want to adjust this logic based on your specific requirements
    #                 level_rates = {
    #                     1: 1.0,    # 100% of base rate
    #                     2: 0.5,    # 50% of base rate
    #                     3: 0.25,   # 25% of base rate
    #                     4: 0.125,  # 12.5% of base rate
    #                     5: 0.0625  # 6.25% of base rate
    #                 }
                    
    #                 # Get base commission rate from position
    #                 base_rate = current_sponsor.position.commission_percentage
                    
    #                 # Apply level-based reduction
    #                 commission_rate = base_rate * level_rates.get(level, 0.03125)
                    
    #                 # Calculate commission amount
    #                 commission_amount = (
    #                     order.final_amount * 
    #                     Decimal(str(commission_rate)) / 
    #                     Decimal('100')
    #                 )
                    
    #                 # Special handling for first purchase bonus
    #                 is_first_purchase_bonus = False
    #                 if (not member.first_purchase_bonus_received and 
    #                     level == 1):  # Only for direct sponsor
    #                     # Add first purchase bonus (e.g., 1000 rupees)
    #                     first_bonus = Decimal('1000.00')
    #                     commission_amount += first_bonus
    #                     is_first_purchase_bonus = True
                        
    #                     # Mark first purchase bonus as received
    #                     member.first_purchase_bonus_received = True
    #                     member.save()
                    
    #                 # Create commission
    #                 commission_obj = cls(
    #                     member=current_sponsor,
    #                     from_member=member,
    #                     order=order,
    #                     amount=commission_amount,
    #                     level=level,
    #                     is_paid=True,
    #                     is_first_purchase_bonus=is_first_purchase_bonus
    #                 )
    #                 commissions.append(commission_obj)
                    
    #                 # Move to next sponsor
    #                 current_sponsor = current_sponsor.sponsor
    #                 level += 1
                
    #             except Exception as sponsor_error:
    #                 logger.error(f"Error processing sponsor {current_sponsor.id}: {str(sponsor_error)}")
    #                 break
            
    #         return commissions
        
    #     except Exception as e:
    #         logger.error(f"Error calculating commissions: {str(e)}")
    #         return []
        
    @receiver(post_save, sender=Order)
    def process_order_commissions(sender, instance, created, **kwargs):
        """
        Process commissions when an order is created and confirmed
        """
        if created and instance.status in ['CONFIRMED', 'SHIPPED', 'DELIVERED']:
            try:
                # Calculate commissions
                commissions = Commission.calculate_commissions(instance)
                
                # Bulk create commissions
                if commissions:
                    Commission.objects.bulk_create(commissions)
            
            except Exception as e:
                logger.error(f"Error processing order commissions: {str(e)}")
class Wallet(models.Model):
    user = models.OneToOneField(User, on_delete=models.CASCADE, related_name='wallet')
    balance = models.DecimalField(max_digits=10, decimal_places=2, default=0)
    last_updated = models.DateTimeField(auto_now=True)

    class Meta:
        db_table = 'wallets'

class WalletTransaction(models.Model):
    class TransactionType(models.TextChoices):
        COMMISSION = 'COMMISSION', 'Commission'
        WITHDRAWAL = 'WITHDRAWAL', 'Withdrawal'
        REFUND = 'REFUND', 'Refund'

    wallet = models.ForeignKey(Wallet, on_delete=models.CASCADE, related_name='transactions')
    amount = models.DecimalField(max_digits=10, decimal_places=2)
    transaction_type = models.CharField(max_length=20, choices=TransactionType.choices)
    description = models.TextField()
    created_at = models.DateTimeField(auto_now_add=True)
    reference_id = models.CharField(max_length=100, null=True, blank=True)

    class Meta:
        db_table = 'wallet_transactions'
        ordering = ['-created_at']

class WithdrawalRequest(models.Model):
    class Status(models.TextChoices):
        PENDING = 'PENDING', 'Pending'
        APPROVED = 'APPROVED', 'Approved'
        REJECTED = 'REJECTED', 'Rejected'

    wallet = models.ForeignKey(Wallet, on_delete=models.CASCADE, related_name='withdrawal_requests')
    amount = models.DecimalField(max_digits=10, decimal_places=2)
    status = models.CharField(max_length=20, choices=Status.choices, default=Status.PENDING)
    created_at = models.DateTimeField(auto_now_add=True)
    processed_at = models.DateTimeField(null=True, blank=True)
    rejection_reason = models.TextField(blank=True)

    class Meta:
        db_table = 'withdrawal_requests'
        ordering = ['-created_at']

    def __str__(self):
        return f"{self.wallet.user.username} - {self.amount} ({self.status})"







 # -------------------------------- Basic Webstie Functionality  -------------------------------------------------------------
class HomeSlider(models.Model):
    title = models.CharField(max_length=200)  # Added missing field
    desktop_image = models.ImageField(upload_to='slider/desktop/')
    mobile_image = models.ImageField(upload_to='slider/mobile/', null=True, blank=True)
    link = models.URLField(max_length=500)
    order = models.PositiveIntegerField(unique=True, null=True, blank=True)
    is_active = models.BooleanField(default=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    
    class Meta:
        ordering = ['order']
        verbose_name = 'Home Slider'
        verbose_name_plural = 'Home Sliders'
        db_table = 'home_sliders'

    def clean(self):
        if not self.mobile_image and not self.desktop_image:
            raise ValidationError("At least one image (desktop or mobile) is required.")

    def save(self, *args, **kwargs):
        if not self.order:
            max_order = HomeSlider.objects.aggregate(Max('order'))['order__max']
            self.order = 1 if max_order is None else max_order + 1
        
        if HomeSlider.objects.filter(order=self.order).exclude(pk=self.pk).exists():
            HomeSlider.objects.filter(order__gte=self.order).exclude(pk=self.pk).update(
                order=F('order') + 1
            )
        
        super().save(*args, **kwargs)

    def delete(self, *args, **kwargs):
        # Store paths before deletion
        desktop_path = self.desktop_image.path if self.desktop_image else None
        mobile_path = self.mobile_image.path if self.mobile_image else None
        
        # Call the parent delete method first
        super().delete(*args, **kwargs)
        
        # Delete files after model deletion
        if desktop_path and os.path.isfile(desktop_path):
            os.remove(desktop_path)
        if mobile_path and os.path.isfile(mobile_path):
            os.remove(mobile_path)

# Custom page 
class CustomPage(models.Model):
    title = models.CharField(max_length=200)
    slug = models.SlugField(max_length=200, unique=True)
    content = models.TextField()
    is_active = models.BooleanField(default=True)
    show_in_footer = models.BooleanField(default=False)
    show_in_header = models.BooleanField(default=False)
    order = models.PositiveIntegerField(default=0)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        db_table = 'custom_pages'
        ordering = ['order', 'title']

    def __str__(self):
        return self.title

    def get_absolute_url(self):
        return f"/page/{self.slug}/"

# Blog page 
class Blog(models.Model):
    title = models.CharField(max_length=200)
    slug = models.SlugField(max_length=200, unique=True)
    content = models.TextField()
    feature_image = models.ImageField(upload_to='blogs/', blank=True, null=True)
    is_active = models.BooleanField(default=True)
    show_in_slider = models.BooleanField(default=False)
    order = models.PositiveIntegerField(default=0)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        db_table = 'blog'
        ordering = ['order', '-created_at']

    def __str__(self):
        return self.title

  

class PageType(models.TextChoices):
    HOME = 'HOME', 'Home Page'
    ABOUT = 'ABOUT', 'About Page'
    CONTACT = 'CONTACT', 'Contact Page'
    PRODUCT = 'PRODUCT', 'Product Page'
    CATEGORY = 'CATEGORY', 'Category Page'
    CUSTOM = 'CUSTOM', 'Custom Page'
    BLOG = 'BLOG', 'Blog Page'




#--------------------------- Home Sections --------------------------------------------------------------------------------
class HomeSectionType(models.TextChoices):
    TRENDING = 'TRENDING', 'Trending Products'
    FEATURED = 'FEATURED', 'Featured Products'
    NEW_ARRIVAL = 'NEW_ARRIVAL', 'New Arrivals'
    BESTSELLER = 'BESTSELLER', 'Best Sellers'

class HomeSection(models.Model):
    section_type = models.CharField(max_length=20, choices=HomeSectionType.choices, unique=True)
    title = models.CharField(max_length=200)
    subtitle = models.CharField(max_length=200, blank=True)
    description = models.TextField(blank=True)
    image = models.ImageField(upload_to='home_sections/')
    is_active = models.BooleanField(default=True)
    display_order = models.PositiveIntegerField(default=0)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        db_table = 'home_sections'
        ordering = ['display_order']

    def __str__(self):
        return f"{self.get_section_type_display()} - {self.title}"

    def get_products(self):
        """Get products based on section type"""
        try:
            if self.section_type == HomeSectionType.TRENDING:
                return Product.objects.filter(is_trending=True, is_active=True)
            elif self.section_type == HomeSectionType.FEATURED:
                return Product.objects.filter(is_featured=True, is_active=True)
            elif self.section_type == HomeSectionType.NEW_ARRIVAL:
                return Product.objects.filter(is_new_arrival=True, is_active=True)
            elif self.section_type == HomeSectionType.BESTSELLER:
                return Product.objects.filter(is_bestseller=True, is_active=True)
            return Product.objects.none()
        except Exception as e:
            logger.error(f"Error getting products for section {self.section_type}: {str(e)}")
            return Product.objects.none()

#  -------------------------------- Company Info Model ----------------------------------------

class CompanyInfo(models.Model):
    # Basic Info
    company_name = models.CharField(max_length=200)
    logo = models.ImageField(upload_to='company/')
    gst_number = models.CharField(max_length=15, blank=True)
    
    # Contact Details
    email = models.EmailField()
    mobile_1 = models.CharField(max_length=15)
    mobile_2 = models.CharField(max_length=15, blank=True)
    
    # Address
    address_line1 = models.CharField(max_length=255)
    address_line2 = models.CharField(max_length=255, blank=True)
    city = models.CharField(max_length=100)
    state = models.CharField(max_length=100)
    pincode = models.CharField(max_length=10)
    country = models.CharField(max_length=100, default='India')
    
    # Social Media Links
    facebook_link = models.URLField(blank=True)
    instagram_link = models.URLField(blank=True)
    twitter_link = models.URLField(blank=True)
    youtube_link = models.URLField(blank=True)
    
    # Website Images
    footer_bg_image = models.ImageField(
        upload_to='company/backgrounds/', 
        blank=True,
        help_text="Background image for website footer"
    )
    testimonial_bg_image = models.ImageField(
        upload_to='company/backgrounds/',
        blank=True,
        help_text="Background image for testimonials section"
    )
    
    # Meta Information
    is_active = models.BooleanField(default=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        db_table = 'company_info'
        verbose_name = 'Company Information'
        verbose_name_plural = 'Company Information'

    def __str__(self):
        return self.company_name

    def save(self, *args, **kwargs):
        # Ensure only one company info record exists
        if not self.pk and CompanyInfo.objects.exists():
            raise ValidationError('Only one company information record can exist.')
        return super().save(*args, **kwargs)

    @classmethod
    def get_info(cls):
        """Get company information - creates default if doesn't exist"""
        info, created = cls.objects.get_or_create(
            defaults={
                'company_name': 'Your Company Name',
                'email': 'info@yourcompany.com',
                'mobile_1': '+91 0000000000',
                'address_line1': 'Your Address',
                'city': 'Your City',
                'state': 'Your State',
                'pincode': '000000',
            }
        )
        return info

    @property
    def full_address(self):
        """Return formatted full address"""
        address_parts = [
            self.address_line1,
            self.address_line2,
            f"{self.city}, {self.state}",
            f"{self.pincode}",
            self.country
        ]
        return ', '.join(filter(None, address_parts))

    GST_STATE_CODES = {
        '01': 'Jammu & Kashmir', '02': 'Himachal Pradesh', '03': 'Punjab',
        '04': 'Chandigarh', '05': 'Uttarakhand', '06': 'Haryana',
        '07': 'Delhi', '08': 'Rajasthan', '09': 'Uttar Pradesh',
        '10': 'Bihar', '11': 'Sikkim', '12': 'Arunachal Pradesh',
        '13': 'Nagaland', '14': 'Manipur', '15': 'Mizoram',
        '16': 'Tripura', '17': 'Meghalaya', '18': 'Assam',
        '19': 'West Bengal', '20': 'Jharkhand', '21': 'Odisha',
        '22': 'Chattisgarh', '23': 'Madhya Pradesh', '24': 'Gujarat',
        '26': 'Daman & Diu', '27': 'Maharashtra', '28': 'Andhra Pradesh',
        '29': 'Karnataka', '30': 'Goa', '31': 'Lakshadweep',
        '32': 'Kerala', '33': 'Tamil Nadu', '34': 'Puducherry',
        '35': 'Andaman & Nicobar Islands', '36': 'Telangana',
        '37': 'Andhra Pradesh (New)', '38': 'Ladakh'
    }

    def clean(self):
        if self.gst_number:
            # Basic format check
            gst_pattern = r'^\d{2}[A-Z]{5}\d{4}[A-Z]{1}\d[Z]{1}[A-Z\d]{1}$'
            if not re.match(gst_pattern, self.gst_number):
                raise ValidationError({
                    'gst_number': 'Invalid GST format. Must be 15 characters long with pattern: 22AAAAA0000A1Z5'
                })

            # State code validation
            state_code = self.gst_number[:2]
            if state_code not in self.GST_STATE_CODES:
                raise ValidationError({
                    'gst_number': f'Invalid state code {state_code}. Must be a valid Indian state code.'
                })

            # PAN validation (characters 3-12)
            pan_part = self.gst_number[2:12]
            pan_pattern = r'^[A-Z]{5}\d{4}[A-Z]{1}$'
            if not re.match(pan_pattern, pan_part):
                raise ValidationError({
                    'gst_number': 'Invalid PAN number format in GST.'
                })

    def get_gst_state(self):
        """Returns the state name based on GST number"""
        if self.gst_number:
            state_code = self.gst_number[:2]
            return self.GST_STATE_CODES.get(state_code, 'Unknown State')



#--------------------------------- testimonials Model ----------------------------------------------------
class Testimonial(models.Model):
    name = models.CharField(
        max_length=100,
        validators=[MinLengthValidator(2, "Name must be at least 2 characters long")]
    )
    designation = models.CharField(
        max_length=100,
        help_text="Job title or role of the person"
    )
    content = models.TextField(
        validators=[MinLengthValidator(10, "Testimonial must be at least 10 characters long")]
    )
    image = models.ImageField(
        upload_to='testimonials/',
        help_text="Profile picture of the person",
        null=True,
        blank=True
    )
    rating = models.PositiveSmallIntegerField(
        default=5,
        choices=[(i, f"{i} Stars") for i in range(1, 6)]
    )
    is_active = models.BooleanField(default=True)
    display_order = models.PositiveIntegerField(
        default=0,
        help_text="Order in which testimonials are displayed"
    )
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        db_table = 'testimonials'
        ordering = ['display_order', '-created_at']
        verbose_name = 'Testimonial'
        verbose_name_plural = 'Testimonials'

    def __str__(self):
        return f"{self.name} - {self.designation}"

    def save(self, *args, **kwargs):
        if not self.display_order:
            # If no display order is set, put it at the end
            last_order = Testimonial.objects.aggregate(
                models.Max('display_order'))['display_order__max']
            self.display_order = (last_order or 0) + 1
        super().save(*args, **kwargs)

# ------------------------------ ads model -------------------------------------------------

class AdvertisementPositionType(models.TextChoices):
        SIDEBAR = 'SIDEBAR', 'Sidebar'
        FULL_WIDTH = 'FULL_WIDTH', 'Full Width'
        PRODUCT_PAGE = 'PRODUCT_PAGE', 'Product Page'
        CUSTOMER_PANEL = 'CUSTOMER_PANEL', 'Customer Panel'
        MLM_PANEL = 'MLM_PANEL', 'MLM Panel'

class Advertisement(models.Model):
    title = models.CharField(max_length=200, blank=True, null=True)
    image = models.ImageField(upload_to='advertisements/')
    link = models.URLField(blank=True, null=True)
    position = models.CharField(max_length=100, blank=True, null=True , choices=AdvertisementPositionType.choices, default=AdvertisementPositionType.SIDEBAR)
    is_active = models.BooleanField(default=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        db_table = 'advertisements'
        ordering = ['-created_at']

    def __str__(self):
        return self.title or "Untitled Advertisement"

    
# --------------------------------- success Stories & Customer Picks models --------------------------------------

class SuccessStory(models.Model):
    title = models.CharField(max_length=200)
    description = models.TextField(blank=True, null=True)
    youtube_link = models.URLField(help_text="YouTube video link")
    thumbnail = models.ImageField(
        upload_to='success_stories/',
        null=True,
        blank=True,
        help_text="Thumbnail image for the video"
    )
    position = models.PositiveIntegerField(default=0)
    is_active = models.BooleanField(default=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        db_table = 'success_stories'
        ordering = ['position', '-created_at']
        verbose_name = 'Success Story'
        verbose_name_plural = 'Success Stories'

    def __str__(self):
        return self.title

    def save(self, *args, **kwargs):
        if not self.position:
            max_position = SuccessStory.objects.aggregate(models.Max('position'))
            self.position = (max_position['position__max'] or 0) + 1
        super().save(*args, **kwargs)

class CustomerPickReview(models.Model):
    title = models.CharField(max_length=200)
    description = models.TextField(blank=True, null=True)
    youtube_link = models.URLField(help_text="YouTube video link")
    thumbnail = models.ImageField(
        upload_to='customer_picks/',
        null=True,
        blank=True,
        help_text="Thumbnail image for the video"
    )
    position = models.PositiveIntegerField(default=0)
    is_active = models.BooleanField(default=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        db_table = 'customer_pick_reviews'
        ordering = ['position', '-created_at']
        verbose_name = 'Customer Pick Review'
        verbose_name_plural = 'Customer Pick Reviews'

    def __str__(self):
        return self.title

    def save(self, *args, **kwargs):
        if not self.position:
            max_position = CustomerPickReview.objects.aggregate(models.Max('position'))
            self.position = (max_position['position__max'] or 0) + 1
        super().save(*args, **kwargs)



# ------------------------------------------- About model ---------------------------------------------------

class About(models.Model):
    TYPE_CHOICES = (
        ('HOME', 'Homepage About'),
        ('MAIN', 'Main About Page')
    )
    
    type = models.CharField(max_length=4, choices=TYPE_CHOICES, default='MAIN')
    title = models.CharField(max_length=200)
    content = models.TextField()
    feature_content = models.TextField(blank=True, null=True)
    left_image = models.ImageField(upload_to='about/')
    vision_description = models.TextField(blank=True, null=True)
    mission_description = models.TextField(blank=True, null=True)
    objective_content = models.TextField(blank=True, null=True)
    is_active = models.BooleanField(default=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        db_table = 'about'
        verbose_name = 'About'
        verbose_name_plural = 'About'

    def __str__(self):
        return f"{self.get_type_display()} - {self.title}"

    def clean(self):
        # Check if another instance of the same type exists
        if not self.pk:
            if About.objects.filter(type=self.type).exists():
                raise ValidationError(f'An {self.get_type_display()} already exists.')
    

# -------------------------- Menu Model --------------------------------------------------------------------------------
class Menu(models.Model):
    category = models.ForeignKey(
        'Category',
        on_delete=models.CASCADE,
        related_name='menu_items'
    )
    position = models.PositiveIntegerField(default=0)
    is_active = models.BooleanField(default=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        db_table = 'menus'
        ordering = ['position']
        verbose_name = 'Menu'
        verbose_name_plural = 'Menu'

    def __str__(self):
        return self.category.name
# -------------------------------------------------------   MetaTags ---------------------------------------------------

class MetaTag(models.Model):
    title = models.CharField(max_length=200)
    description = models.TextField()
    keywords = models.TextField(blank=True, help_text="Comma separated keywords")
    og_title = models.CharField(max_length=200, blank=True, verbose_name="Open Graph Title")
    og_description = models.TextField(blank=True, verbose_name="Open Graph Description")
    og_image = models.ImageField(upload_to='meta/og/', blank=True, verbose_name="Open Graph Image")
    twitter_title = models.CharField(max_length=200, blank=True)
    twitter_description = models.TextField(blank=True)
    twitter_image = models.ImageField(upload_to='meta/twitter/', blank=True)
    canonical_url = models.URLField(blank=True)
    
    # References to different page types
    page_type = models.CharField(max_length=20, choices=PageType.choices)
    product = models.OneToOneField('Product', on_delete=models.CASCADE, null=True, blank=True)
    category = models.OneToOneField('Category', on_delete=models.CASCADE, null=True, blank=True)
    custom_page = models.OneToOneField(CustomPage, on_delete=models.CASCADE, null=True, blank=True)
    blog = models.OneToOneField(Blog, on_delete=models.CASCADE, null=True, blank=True)
    is_default = models.BooleanField(default=False, help_text="Use as default meta for this page type")
    
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        db_table = 'meta_tags'
        constraints = [
            # Ensure only one default meta per page type
            models.UniqueConstraint(
                fields=['page_type', 'is_default'],
                condition=models.Q(is_default=True),
                name='unique_default_meta_per_page_type'
            ),
            # Ensure only one reference is set
            models.CheckConstraint(
                check=(
                    models.Q(product__isnull=True, category__isnull=True, custom_page__isnull=True) |
                    models.Q(product__isnull=False, category__isnull=True, custom_page__isnull=True) |
                    models.Q(product__isnull=True, category__isnull=False, custom_page__isnull=True) |
                    models.Q(product__isnull=True, category__isnull=True, custom_page__isnull=False)
                ),
                name='only_one_reference_set'
            )
        ]

    def clean(self):
        # Validate that only one reference is set
        references = [
            bool(self.product),
            bool(self.category),
            bool(self.custom_page),
            bool(self.blog),
        ]
        if sum(references) > 1:
            raise ValidationError("Only one reference (product, category, or custom page) can be set.")
        
        # Validate default meta tags
        if self.is_default and (self.product or self.category or self.custom_page):
            raise ValidationError("Default meta tags cannot be linked to specific pages.")

    def __str__(self):
        if self.product:
            return f"Meta for Product: {self.product.name}"
        elif self.category:
            return f"Meta for Category: {self.category.name}"
        elif self.custom_page:
            return f"Meta for Page: {self.custom_page.title}"
        elif self.blog:
            return f"Meta for Page: {self.blog.title}"
        else:
            return f"Default Meta for {self.get_page_type_display()}"
        
class Notification(models.Model):
    NOTIFICATION_TYPES = (
        ('GENERAL', 'General'),
        ('INDIVIDUAL', 'Individual'),
        ('COMMISSION', 'Commission'),
        ('WITHDRAWAL', 'Withdrawal'),
        ('KYC', 'KYC'),
        ('SYSTEM', 'System')
    )

    title = models.CharField(max_length=255)
    message = models.TextField()
    notification_type = models.CharField(max_length=20, choices=NOTIFICATION_TYPES)
    recipient = models.ForeignKey(
        MLMMember, 
        on_delete=models.CASCADE, 
        related_name='notifications',
        null=True, 
        blank=True
    )
    is_read = models.BooleanField(default=False)
    created_at = models.DateTimeField(auto_now_add=True)
    read_at = models.DateTimeField(null=True, blank=True)

    class Meta:
        ordering = ['-created_at']

    def mark_as_read(self):
        if not self.is_read:
            self.is_read = True
            self.read_at = timezone.now()
            self.save()

    @property
    def short_message(self):
        """Returns truncated message for preview"""
        return self.message[:100] + '...' if len(self.message) > 100 else self.message
    



class Contact(models.Model):
    name = models.CharField(max_length=100)
    email = models.EmailField()
    phone = models.CharField(max_length=15)
    subject = models.CharField(max_length=200)
    message = models.TextField()
    is_read = models.BooleanField(default=False)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        db_table = 'contacts'
        ordering = ['-created_at']
        verbose_name = 'Contact Query'
        verbose_name_plural = 'Contact Queries'

    def __str__(self):
        return f"{self.name} - {self.subject} ({self.created_at.strftime('%Y-%m-%d')})"
    

class Newsletter(models.Model):
    email = models.EmailField(unique=True)
    is_active = models.BooleanField(default=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        db_table = 'newsletters'
        ordering = ['-created_at']
        verbose_name = 'Newsletter Subscription'
        verbose_name_plural = 'Newsletter Subscriptions'

    def __str__(self):
        return self.email


class PasswordResetRequest(models.Model):
    user = models.ForeignKey('User', on_delete=models.CASCADE)
    status = models.CharField(
        max_length=20,
        choices=[
            ('PENDING', 'Pending'),
            ('APPROVED', 'Approved'),
            ('REJECTED', 'Rejected')
        ],
        default='PENDING'
    )
    requested_at = models.DateTimeField(auto_now_add=True)
    processed_at = models.DateTimeField(null=True, blank=True)
    processed_by = models.ForeignKey(
        'User',
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name='processed_reset_requests'
    )

    class Meta:
        db_table = 'password_reset_requests'
        ordering = ['-requested_at']

    def __str__(self):
        return f"Password reset request for {self.user.username}"

    def clean(self):
        # Check for existing pending requests
        if not self.pk:  # Only check on creation
            existing_request = PasswordResetRequest.objects.filter(
                user=self.user,
                status='PENDING'
            ).exists()
            if existing_request:
                raise ValidationError('A password reset request is already pending for this user')

    def save(self, *args, **kwargs):
        self.full_clean()
        super().save(*args, **kwargs)



class CommissionActivationRequest(models.Model):
    class Status(models.TextChoices):
        PENDING = 'PENDING', 'Pending'
        APPROVED = 'APPROVED', 'Approved'
        REJECTED = 'REJECTED', 'Rejected'

    requester = models.ForeignKey(
        'MLMMember', 
        on_delete=models.CASCADE, 
        related_name='commission_activation_requests'
    )
    sponsor = models.ForeignKey(
        'MLMMember', 
        on_delete=models.SET_NULL, 
        null=True, 
        blank=True, 
        related_name='downline_commission_requests'
    )
    current_position = models.ForeignKey(
        'Position', 
        on_delete=models.CASCADE,
        related_name='current_commission_requests'
    )
    target_position = models.ForeignKey(
        'Position', 
        on_delete=models.CASCADE,
        related_name='target_commission_requests'
    )
    status = models.CharField(
        max_length=20, 
        choices=Status.choices, 
        default=Status.PENDING
    )
    created_at = models.DateTimeField(auto_now_add=True)
    processed_at = models.DateTimeField(null=True, blank=True)
    processed_by = models.ForeignKey(
        User, 
        on_delete=models.SET_NULL, 
        null=True, 
        blank=True,
        related_name='processed_commission_requests'
    )
    reason = models.TextField(blank=True)



# class ShippingCredential(models.Model):
#     """Store API credentials for shipping providers"""
#     provider_name = models.CharField(max_length=100)  # E.g., 'QuixGo'
#     api_key = models.CharField(max_length=255)
#     api_secret = models.CharField(max_length=255, blank=True, null=True)
#     base_url = models.URLField()
#     is_active = models.BooleanField(default=True)
#     created_at = models.DateTimeField(auto_now_add=True)
#     updated_at = models.DateTimeField(auto_now=True)

#     def __str__(self):
#         return f"{self.provider_name} API"

class PickupAddress(models.Model):
    """
    Store pickup addresses for shipping
    Each address is registered with QuixGo and stored locally
    """
    # Basic Info
    name = models.CharField(
        max_length=100,
        help_text="Name for this pickup point"
    )
    address_id = models.CharField(
        max_length=50,
        blank=True,
        null=True,
        help_text="QuixGo address ID"
    )
    customer_id = models.CharField(
        max_length=50,
        blank=True,
        null=True,
        help_text="QuixGo customer ID"
    )
    
    # Contact Details
    contact_person = models.CharField(
        max_length=100,
        help_text="Contact person name"
    )
    address_line1 = models.CharField(
        max_length=255,
        help_text="Address line 1"
    )
    address_line2 = models.CharField(
        max_length=255,
        blank=True,
        help_text="Address line 2 (optional)"
    )
    city = models.CharField(
        max_length=100,
        help_text="City"
    )
    state = models.CharField(
        max_length=100,
        help_text="State"
    )
    country = models.CharField(
        max_length=100,
        default='India',
        help_text="Country"
    )
    pincode = models.CharField(
        max_length=10,
        help_text="PIN code"
    )
    phone = models.CharField(
        max_length=15,
        help_text="Contact phone"
    )
    alternate_phone = models.CharField(
        max_length=15,
        blank=True,
        help_text="Alternate phone (optional)"
    )
    email = models.EmailField(
        blank=True,
        help_text="Email (optional)"
    )
    landmark = models.CharField(
        max_length=255,
        blank=True,
        help_text="Landmark (optional)"
    )
    
    # Additional Info
    address_type = models.CharField(
        max_length=20,
        default='Office',
        help_text="Address type (Home, Office, Warehouse)"
    )
    is_default = models.BooleanField(
        default=False,
        help_text="Use as default pickup address"
    )
    is_active = models.BooleanField(
        default=True,
        help_text="Address is active and available for use"
    )
    
    # Tracking
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        verbose_name = "Pickup Address"
        verbose_name_plural = "Pickup Addresses"
        ordering = ['-is_default', 'name']

    def __str__(self):
        return f"{self.name} - {self.city}, {self.pincode}"
    
    def save(self, *args, **kwargs):
        # Set as default if it's the first pickup address
        if not self.pk and not PickupAddress.objects.filter(is_default=True).exists():
            self.is_default = True
        
        # If setting this as default, unset any other defaults
        if self.is_default:
            PickupAddress.objects.filter(is_default=True).update(is_default=False)
            
        super().save(*args, **kwargs)


class Shipment(models.Model):
    """Track shipments for orders"""
    
    # Shipment status choices
    STATUS_CHOICES = [
        ('PENDING', 'Pending'),
        ('BOOKED', 'Booked'),
        ('PICKED_UP', 'Picked Up'),
        ('IN_TRANSIT', 'In Transit'),
        ('OUT_FOR_DELIVERY', 'Out for Delivery'),
        ('DELIVERED', 'Delivered'),
        ('FAILED_DELIVERY', 'Failed Delivery'),
        ('RETURNED', 'Returned'),
        ('CANCELLED', 'Cancelled'),
    ]
    
    # Relationships
    order = models.ForeignKey(
        'Order',
        on_delete=models.CASCADE,
        related_name='shipments',
        help_text="Order being shipped"
    )
    pickup_address = models.ForeignKey(
        'PickupAddress',
        on_delete=models.PROTECT,
        help_text="Pickup address for this shipment"
    )
    
    # Shipment identifiers
    awb_number = models.CharField(
        max_length=50,
        blank=True,
        null=True,
        help_text="AWB tracking number"
    )
    shipment_id = models.CharField(
        max_length=50,
        blank=True,
        null=True,
        help_text="QuixGo shipment ID"
    )
    
    # Shipment details
    courier_name = models.CharField(
        max_length=50,
        blank=True,
        null=True,
        help_text="Courier service provider (DLV, DTC, SFX)"
    )
    service_type = models.CharField(
        max_length=10,
        default='SF',
        help_text="Service type (Express=EXP or Surface=SF)"
    )
    status = models.CharField(
        max_length=20,
        choices=STATUS_CHOICES,
        default='PENDING',
        help_text="Current status of the shipment"
    )
    status_details = models.JSONField(
        default=dict,
        blank=True,
        help_text="Additional status details as JSON"
    )
    tracking_url = models.URLField(
        blank=True,
        null=True,
        help_text="URL for tracking this shipment"
    )
    
    # Shipment specifications
    weight = models.DecimalField(
        max_digits=5,
        decimal_places=2,
        default=1.0,
        help_text="Weight in kg"
    )
    length = models.DecimalField(
        max_digits=5,
        decimal_places=2,
        default=10.0,
        help_text="Length in cm"
    )
    width = models.DecimalField(
        max_digits=5,
        decimal_places=2,
        default=10.0,
        help_text="Width in cm"
    )
    height = models.DecimalField(
        max_digits=5,
        decimal_places=2,
        default=10.0,
        help_text="Height in cm"
    )
    
    # Payment details
    is_cod = models.BooleanField(
        default=False,
        help_text="Whether this is a Cash on Delivery shipment"
    )
    cod_amount = models.DecimalField(
        max_digits=10,
        decimal_places=2,
        default=0.0,
        help_text="COD amount to be collected"
    )
    shipping_charge = models.DecimalField(
        max_digits=10,
        decimal_places=2,
        default=0.0,
        help_text="Shipping charge for this shipment"
    )
    
    # Status flags
    is_cancelled = models.BooleanField(
        default=False,
        help_text="Whether this shipment has been cancelled"
    )
    
    # Tracking
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        verbose_name = "Shipment"
        verbose_name_plural = "Shipments"
        ordering = ['-created_at']
        indexes = [
            models.Index(fields=['order', 'status']),
            models.Index(fields=['awb_number']),
        ]

    def __str__(self):
        return f"Shipment {self.awb_number or 'pending'} for Order {self.order.order_number}"
    
    def get_status_display_custom(self):
        """Get a custom status display name"""
        for code, display in self.STATUS_CHOICES:
            if code == self.status:
                return display
        return self.status


class ShipmentStatusUpdate(models.Model):
    """Track shipment status updates"""
    
    shipment = models.ForeignKey(
        'Shipment',
        on_delete=models.CASCADE,
        related_name='status_updates',
        help_text="Related shipment"
    )
    status = models.CharField(
        max_length=50,
        help_text="Status name"
    )
    status_details = models.TextField(
        blank=True,
        help_text="Status details or comments"
    )
    location = models.CharField(
        max_length=100,
        blank=True,
        help_text="Location of the status update"
    )
    timestamp = models.DateTimeField(
        help_text="When this status was updated"
    )
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        verbose_name = "Shipment Status Update"
        verbose_name_plural = "Shipment Status Updates"
        ordering = ['-timestamp']
        indexes = [
            models.Index(fields=['shipment', 'timestamp']),
        ]

    def __str__(self):
        return f"{self.status} at {self.timestamp.strftime('%Y-%m-%d %H:%M')}"


class ShippingConfig(models.Model):
    email = models.EmailField(null=True, blank=True)
    password = models.CharField(max_length=255 , blank=True, null=True)
    customer_id = models.CharField(max_length=50, blank=True, null=True)
    access_token = models.TextField(blank=True, null=True)
    token_expiry = models.DateTimeField(blank=True, null=True)
    
    # Optional additional fields
    first_name = models.CharField(max_length=100, blank=True, null=True)
    last_name = models.CharField(max_length=100, blank=True, null=True)
    mobile = models.CharField(max_length=15, blank=True, null=True)
    
    # Default shipping preferences
    default_courier = models.CharField(max_length=10, default='DTC')
    default_service_type = models.CharField(max_length=10, default='SF')
    
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    def __str__(self):
        return f"{self.email} API"



class ShippingAddress(models.Model):
    order = models.OneToOneField('Order', on_delete=models.CASCADE, related_name='shipping_details')
    name = models.CharField(max_length=100, help_text="Name for this address (e.g. Home, Office)")
    street_address = models.CharField(max_length=255)
    city = models.CharField(max_length=100)
    state = models.CharField(max_length=100)
    postal_code = models.CharField(max_length=10)

    created_at = models.DateTimeField(auto_now_add=True)
    
    class Meta:
        db_table = 'shipping_addresses'
        verbose_name_plural = 'Shipping Addresses'
    
    def __str__(self):
        return f"Shipping for {self.order.order_number}"




class ShippingRate(models.Model):
    is_free_shipping = models.BooleanField(default=False)
    base_rate = models.DecimalField(max_digits=10, decimal_places=2, default=100.00)
    tax_percentage = models.DecimalField(max_digits=5, decimal_places=2, default=18.00)
    is_active = models.BooleanField(default=True)
    updated_at = models.DateTimeField(auto_now=True)
    
    class Meta:
        db_table = 'shipping_rate'
        
    @classmethod
    def get_active_config(cls):
        """Get active shipping configuration"""
        config = cls.objects.filter(is_active=True).first()
        if not config:
            config = cls.objects.create()
        return config


class StaffPermission(models.Model):
    """Model to represent individual permissions for staff users"""
    name = models.CharField(max_length=100, unique=True)
    description = models.TextField(blank=True)
    module = models.CharField(max_length=50, help_text="Module this permission belongs to")
    is_active = models.BooleanField(default=True)
    
    class Meta:
        ordering = ['module', 'name']
        
    def __str__(self):
        return f"{self.module} - {self.name}"


class StaffRole(models.Model):
    """Model for staff roles with predefined permissions"""
    name = models.CharField(max_length=100, unique=True)
    description = models.TextField(blank=True)
    permissions = models.ManyToManyField(StaffPermission, related_name='roles')
    is_active = models.BooleanField(default=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    
    class Meta:
        ordering = ['name']
        
    def __str__(self):
        return self.name


class StaffMember(models.Model):
    """Model for internal staff users with specific permissions"""
    user = models.OneToOneField(User, on_delete=models.CASCADE, related_name='staff_profile')
    role = models.ForeignKey(StaffRole, on_delete=models.PROTECT, related_name='staff_members')
    custom_permissions = models.ManyToManyField(
        StaffPermission, 
        related_name='staff_members',
        blank=True,
        help_text="Additional permissions beyond the role"
    )
    supervisor = models.ForeignKey(
        'self', 
        on_delete=models.SET_NULL, 
        null=True, 
        blank=True,
        related_name='subordinates'
    )
    department = models.CharField(max_length=100, blank=True)
    phone_regex = RegexValidator(
        regex=r'^\+?1?\d{9,15}$',
        message="Phone number must be entered in the format: '+999999999'. Up to 15 digits allowed."
    )
    phone_number = models.CharField(validators=[phone_regex], max_length=17, blank=True)
    employee_id = models.CharField(max_length=20, blank=True)
    is_active = models.BooleanField(default=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    
    def __str__(self):
        return f"{self.user.get_full_name()} ({self.role.name})"
    
    def has_permission(self, permission_name):
        """Check if staff member has a specific permission"""
        # Check if user has this permission directly
        if self.custom_permissions.filter(name=permission_name, is_active=True).exists():
            return True
            
        # Check if user's role has this permission
        if self.role.permissions.filter(name=permission_name, is_active=True).exists():
            return True
            
        return False