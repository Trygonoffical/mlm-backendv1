from django.contrib import admin

# Register your models here.
from .models import (
    User, PhoneOTP, Product, Customer, Member,
    Associate, Order, OrderItem, Commission,
    Wallet, WalletTransaction
)

# Register your models here.
admin.site.register(User)
admin.site.register(PhoneOTP)
admin.site.register(Product)
admin.site.register(Customer)
admin.site.register(Member)
admin.site.register(Associate)
admin.site.register(Order)
admin.site.register(OrderItem)
admin.site.register(Commission)
admin.site.register(Wallet)
admin.site.register(WalletTransaction)