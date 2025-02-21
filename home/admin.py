from django.contrib import admin
from django.utils.html import format_html
from utils.email_utils import send_welcome_email
# Register your models here.
from .models import (
    User, PhoneOTP, Product, Customer, MLMMember, Order, OrderItem, Commission,
    Wallet, WalletTransaction, Testimonial , Advertisement , SuccessStory , CustomerPickReview , About ,Menu ,CompanyInfo , Contact , Newsletter
)

# Register your models here.
admin.site.register(User)
admin.site.register(PhoneOTP)
admin.site.register(Product)
admin.site.register(Customer)
admin.site.register(MLMMember)
admin.site.register(Order)
admin.site.register(OrderItem)
admin.site.register(Commission)
admin.site.register(Wallet)
admin.site.register(WalletTransaction)
admin.site.register(CompanyInfo)

from django.utils.html import format_html

@admin.register(Testimonial)
class TestimonialAdmin(admin.ModelAdmin):
    list_display = ['name', 'designation', 'rating', 'image_preview', 'is_active', 'display_order']
    list_editable = ['is_active', 'display_order']
    list_filter = ['is_active', 'rating']
    search_fields = ['name', 'designation', 'content']
    readonly_fields = ['image_preview']
    ordering = ['display_order']

    def image_preview(self, obj):
        if obj.image:
            return format_html(
                '<img src="{}" style="max-width: 50px; max-height: 50px;" />',
                obj.image.url
            )
        return "No image"
    image_preview.short_description = 'Image Preview'


@admin.register(Advertisement)
class AdvertisementAdmin(admin.ModelAdmin):
    list_display = ['title', 'image_preview', 'position', 'is_active']
    list_editable = ['is_active']
    search_fields = ['title', 'position']

    def image_preview(self, obj):
        if obj.image:
            return format_html(
                '<img src="{}" style="max-width: 100px; max-height: 100px;" />',
                obj.image.url
            )
        return "No image"
    image_preview.short_description = 'Image Preview'


@admin.register(SuccessStory)
class SuccessStoryAdmin(admin.ModelAdmin):
    list_display = ['title', 'thumbnail_preview', 'position', 'is_active']
    list_editable = ['position', 'is_active']
    search_fields = ['title', 'description']
    list_filter = ['is_active']

    def thumbnail_preview(self, obj):
        if obj.thumbnail:
            return format_html(
                '<img src="{}" style="max-width: 50px; max-height: 50px;" />',
                obj.thumbnail.url
            )
        return "No thumbnail"
    thumbnail_preview.short_description = 'Thumbnail'

@admin.register(CustomerPickReview)
class CustomerPickReviewAdmin(admin.ModelAdmin):
    list_display = ['title', 'thumbnail_preview', 'position', 'is_active']
    list_editable = ['position', 'is_active']
    search_fields = ['title', 'description']
    list_filter = ['is_active']

    def thumbnail_preview(self, obj):
        if obj.thumbnail:
            return format_html(
                '<img src="{}" style="max-width: 50px; max-height: 50px;" />',
                obj.thumbnail.url
            )
        return "No thumbnail"
    thumbnail_preview.short_description = 'Thumbnail'


@admin.register(About)
class AboutAdmin(admin.ModelAdmin):
    list_display = ['title', 'type', 'image_preview', 'is_active']
    list_editable = ['is_active']
    readonly_fields = ['image_preview']
    
    # Show/hide fields based on type
    def get_fieldsets(self, request, obj=None):
        if obj and obj.type == 'HOME' or request.GET.get('type') == 'HOME':
            return (
                (None, {
                    'fields': ('type', 'title', 'content', 'feature_content', 
                             'left_image', 'image_preview', 'is_active')
                }),
            )
        return (
            (None, {
                'fields': ('type', 'title', 'content', 'left_image', 
                         'image_preview', 'vision_description', 
                         'mission_description', 'objective_content', 'is_active')
            }),
        )

    def image_preview(self, obj):
        if obj.left_image:
            return format_html(
                '<img src="{}" style="max-width: 200px; max-height: 200px;" />',
                obj.left_image.url
            )
        return "No image"
    image_preview.short_description = 'Image Preview'

    def get_form(self, request, obj=None, **kwargs):
        # Pre-set the type for new instances based on URL parameter
        form = super().get_form(request, obj, **kwargs)
        if not obj and 'type' in request.GET:
            form.base_fields['type'].initial = request.GET['type']
        return form
    
@admin.register(Menu)
class MenuAdmin(admin.ModelAdmin):
    list_display = ['category', 'position', 'is_active']
    list_editable = ['position', 'is_active']





@admin.register(Contact)
class ContactAdmin(admin.ModelAdmin):
    list_display = ('name', 'email', 'subject', 'is_read', 'created_at')
    list_filter = ('is_read', 'created_at')
    search_fields = ('name', 'email', 'subject', 'message', 'phone')
    readonly_fields = ('created_at', 'updated_at')
    list_per_page = 25
    ordering = ('-created_at',)

    fieldsets = (
        ('Contact Information', {
            'fields': ('name', 'email', 'phone')
        }),
        ('Query Details', {
            'fields': ('subject', 'message')
        }),
        ('Status', {
            'fields': ('is_read',)
        }),
        ('Timestamps', {
            'fields': ('created_at', 'updated_at'),
            'classes': ('collapse',)
        }),
    )

    actions = ['mark_as_read', 'mark_as_unread']

    def mark_as_read(self, request, queryset):
        queryset.update(is_read=True)
    mark_as_read.short_description = "Mark selected queries as read"

    def mark_as_unread(self, request, queryset):
        queryset.update(is_read=False)
    mark_as_unread.short_description = "Mark selected queries as unread"

    def save_model(self, request, obj, form, change):
        if change and 'is_read' in form.changed_data:
            # You can add notification logic here when admin marks a query as read
            pass
        super().save_model(request, obj, form, change)



@admin.register(Newsletter)
class NewsletterAdmin(admin.ModelAdmin):
    list_display = ('email', 'is_active', 'created_at')
    list_filter = ('is_active', 'created_at')
    search_fields = ('email',)
    readonly_fields = ('created_at', 'updated_at')
    list_per_page = 25
    ordering = ('-created_at',)

    actions = ['activate_subscriptions', 'deactivate_subscriptions']

    def activate_subscriptions(self, request, queryset):
        updated = queryset.update(is_active=True)
        self.message_user(request, f'{updated} subscriptions were successfully activated.')
    activate_subscriptions.short_description = "Activate selected subscriptions"

    def deactivate_subscriptions(self, request, queryset):
        updated = queryset.update(is_active=False)
        self.message_user(request, f'{updated} subscriptions were successfully deactivated.')
    deactivate_subscriptions.short_description = "Deactivate selected subscriptions"

    def save_model(self, request, obj, form, change):
        if not change:  # Only for new subscriptions
            # You can add email notification logic here
            pass
        super().save_model(request, obj, form, change)



