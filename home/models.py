from django.db import models

# Create your models here.
from django.contrib.auth.models import AbstractUser, BaseUserManager
from django.core.validators import EmailValidator, MinValueValidator, MaxValueValidator
from django.utils import timezone
from decimal import Decimal
from django.core.validators import RegexValidator

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
                raise ValueError('Password required for members and associates')
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
        MEMBER = 'MEMBER', 'Member'
        ASSOCIATE = 'ASSOCIATE', 'Associate'

    username = models.CharField(max_length=50, unique=True)
    role = models.CharField(max_length=20, choices=Role.choices, default=Role.CUSTOMER)
    phone_number = models.CharField(max_length=10, unique=True, null=True, blank=True)
    email = models.EmailField(unique=True, blank=True, null=True)
    
    objects = CustomUserManager()

    class Meta:
        db_table = 'users'

class PhoneOTP(models.Model):
    phone_number = models.CharField(max_length=17)
    otp = models.CharField(max_length=6)
    created_at = models.DateTimeField(auto_now_add=True)
    is_verified = models.BooleanField(default=False)
    count = models.IntegerField(default=0)  # Number of OTP sent
    
    class Meta:
        db_table = 'phone_otps'

# Products 
class Product(models.Model):
    name = models.CharField(max_length=200)
    description = models.TextField()
    price = models.DecimalField(max_digits=10, decimal_places=2)
    regular_discount = models.DecimalField(
        max_digits=5, 
        decimal_places=2, 
        default=0,
        validators=[MinValueValidator(0), MaxValueValidator(100)]
    )
    associate_discount = models.DecimalField(
        max_digits=5, 
        decimal_places=2, 
        default=10,  # 10% discount for associates
        validators=[MinValueValidator(0), MaxValueValidator(100)]
    )
    stock = models.PositiveIntegerField(default=0)
    is_active = models.BooleanField(default=True)

    class Meta:
        db_table = 'products'


# customers 
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


# members 
class Member(models.Model):
    user = models.OneToOneField(
        User,
        on_delete=models.CASCADE,
        related_name='member'
    )
    member_id = models.CharField(max_length=50, unique=True)
    commission_rate = models.DecimalField(
        max_digits=5,
        decimal_places=2,
        default=5.00,  # 5% commission on associate purchases
        validators=[MinValueValidator(0), MaxValueValidator(100)]
    )
    total_earnings = models.DecimalField(max_digits=10, decimal_places=2, default=0)
    join_date = models.DateTimeField(default=timezone.now)

    class Meta:
        db_table = 'members'

# Associates 
class Associate(models.Model):
    user = models.OneToOneField(
        User,
        on_delete=models.CASCADE,
        related_name='associate'
    )
    sponsor = models.ForeignKey(
        Member,
        on_delete=models.SET_NULL,
        null=True,
        related_name='sponsored_associates'
    )
    associate_id = models.CharField(max_length=50, unique=True)
    join_date = models.DateTimeField(default=timezone.now)
    total_purchases = models.DecimalField(max_digits=10, decimal_places=2, default=0)

    class Meta:
        db_table = 'associates'

# Orders 
class Order(models.Model):
    class OrderStatus(models.TextChoices):
        PENDING = 'PENDING', 'Pending'
        CONFIRMED = 'CONFIRMED', 'Confirmed'
        SHIPPED = 'SHIPPED', 'Shipped'
        DELIVERED = 'DELIVERED', 'Delivered'
        CANCELLED = 'CANCELLED', 'Cancelled'

    user = models.ForeignKey(User, on_delete=models.CASCADE, related_name='orders')
    order_number = models.CharField(max_length=50, unique=True)
    order_date = models.DateTimeField(auto_now_add=True)
    status = models.CharField(max_length=20, choices=OrderStatus.choices, default=OrderStatus.PENDING)
    total_amount = models.DecimalField(max_digits=10, decimal_places=2)
    discount_amount = models.DecimalField(max_digits=10, decimal_places=2, default=0)
    final_amount = models.DecimalField(max_digits=10, decimal_places=2)
    shipping_address = models.TextField()
    billing_address = models.TextField()

    class Meta:
        db_table = 'orders'

# OrderItems 
class OrderItem(models.Model):
    order = models.ForeignKey(Order, on_delete=models.CASCADE, related_name='items')
    product = models.ForeignKey(Product, on_delete=models.CASCADE)
    quantity = models.PositiveIntegerField()
    price = models.DecimalField(max_digits=10, decimal_places=2)  # Price at time of purchase
    discount_percentage = models.DecimalField(max_digits=5, decimal_places=2, default=0)
    final_price = models.DecimalField(max_digits=10, decimal_places=2)  # After discount

    class Meta:
        db_table = 'order_items'

# Commisions 
class Commission(models.Model):
    member = models.ForeignKey(Member, on_delete=models.CASCADE, related_name='commissions')
    associate = models.ForeignKey(Associate, on_delete=models.CASCADE)
    order = models.ForeignKey(Order, on_delete=models.CASCADE)
    amount = models.DecimalField(max_digits=10, decimal_places=2)
    date = models.DateTimeField(auto_now_add=True)
    is_paid = models.BooleanField(default=False)
    payment_date = models.DateTimeField(null=True, blank=True)

    class Meta:
        db_table = 'commissions'

#wallets 
class Wallet(models.Model):
    user = models.OneToOneField(User, on_delete=models.CASCADE, related_name='wallet')
    balance = models.DecimalField(max_digits=10, decimal_places=2, default=0)
    last_updated = models.DateTimeField(auto_now=True)

    class Meta:
        db_table = 'wallets'

# WalletTransaction
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