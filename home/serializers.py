
from rest_framework import serializers
from django.contrib.auth import get_user_model
from .models import Testimonial , HomeSlider , Category , ProductImage , ProductFeature , Product , Position , MLMMember , Commission , WalletTransaction , Advertisement , SuccessStory , CustomerPickReview , CompanyInfo , About , HomeSection , HomeSectionType , Menu , CustomPage , KYCDocument , Blog , Address , Order , OrderItem , Wallet, WalletTransaction, WithdrawalRequest, BankDetails , Notification , Contact , Newsletter , ProductFAQ  , MetaTag , CommissionActivationRequest , PickupAddress, Shipment, ShipmentStatusUpdate , ShippingConfig , ShippingAddress , StaffMember , StaffPermission , StaffRole
from appAuth.serializers import UserSerializer
from django.db import IntegrityError
from django.db.models import Sum, Avg, Count, Min, Max
from django.db.models.functions import TruncMonth, TruncDay, TruncYear, Extract
from django.db.models import F, Q , Count
import re
from django.utils.text import slugify
from django.core.validators import RegexValidator
import logging
from django.db import transaction
from django.db import models
from decimal import Decimal


logger = logging.getLogger(__name__)


User = get_user_model()

class TestimonialSerializer(serializers.ModelSerializer):
    image_url = serializers.SerializerMethodField()

    class Meta:
        model = Testimonial
        fields = [
            'id', 'name', 'designation', 'content',
            'image_url', 'rating', 'display_order'
        ]

    def get_image_url(self, obj):
        if obj.image:
            request = self.context.get('request')
            if request:
                return request.build_absolute_uri(obj.image.url)
        return None



class HomeSliderSerializer(serializers.ModelSerializer):
    desktop_image = serializers.ImageField(required=True)
    mobile_image = serializers.ImageField(required=False, allow_null=True)
    class Meta:
        model = HomeSlider
        fields = '__all__'
        read_only_fields = ['created_at', 'updated_at' ]




class ProductImageSerializer(serializers.ModelSerializer):
    class Meta:
        model = ProductImage
        fields = ['id', 'image', 'alt_text', 'is_feature', 'order']

class ProductFeatureSerializer(serializers.ModelSerializer):
    class Meta:
        model = ProductFeature
        fields = ['id', 'title', 'content', 'order']

class CategoryDetailSerializer(serializers.ModelSerializer):
    class Meta:
        model = Category
        fields = ['id', 'name']

# class ProductSerializer(serializers.ModelSerializer):
#     images = ProductImageSerializer(many=True, read_only=True)
#     features = ProductFeatureSerializer(many=True, read_only=True)
#     uploaded_images = serializers.ListField(
#         child=serializers.ImageField(max_length=1000000),
#         write_only=True,
#         required=False
#     )
#     # feature_list = serializers.ListField(
#     #     child=serializers.DictField(),
#     #     write_only=True,
#     #     required=False
#     # )
#     feature_list = serializers.JSONField(required=False)
#     slug = serializers.SlugField(read_only=True)
#     categories = serializers.PrimaryKeyRelatedField(
#         many=True,
#         queryset=Category.objects.all(),
#         required=False
#     )
#     category_details = CategoryDetailSerializer(source='categories', many=True, read_only=True)

#     class Meta:
#         model = Product
#         fields = ['id', 'name', 'slug', 'description', 'regular_price', 
#                  'selling_price', 'bp_value', 'gst_percentage', 'stock',
#                  'is_featured', 'is_bestseller', 'is_new_arrival', 
#                  'is_trending', 'is_active', 'images', 'features',
#                  'uploaded_images', 'feature_list', 'categories', 'category_details']
#         # read_only_fields = ['slug']  # Make sure slug is read-only
        

#     def validate(self, data):
#         # Add proper validation messages
#         if not data.get('name'):
#             raise serializers.ValidationError({'name': 'Name is required'})
        
#         # Generate slug from name
#         from django.utils.text import slugify
        
#         # Get the base slug from the name
#         base_slug = slugify(data['name'])

#         # Check if this slug already exists
#         if Product.objects.filter(slug=base_slug).exists():
#             # If it exists, append a number to make it unique
#             count = 1
#             while Product.objects.filter(slug=f"{base_slug}-{count}").exists():
#                 count += 1
#             data['slug'] = f"{base_slug}-{count}"
#         else:
#             data['slug'] = base_slug
#         return data
    
#     def validate_feature_list(self, value):
#         """
#         Validate the feature list data
#         """
#         # If value is a string, try to parse it as JSON
#         if isinstance(value, str):
#             try:
#                 import json
#                 value = json.loads(value)
#             except json.JSONDecodeError:
#                 raise serializers.ValidationError("Invalid JSON format for feature_list")

#         if not isinstance(value, list):
#             raise serializers.ValidationError("Feature list must be an array")
        
#         for feature in value:
#             if not isinstance(feature, dict):
#                 raise serializers.ValidationError("Each feature must be an object")
#             if 'title' not in feature or 'content' not in feature:
#                 raise serializers.ValidationError("Each feature must have title and content")
#         return value
    

#     def create(self, validated_data):
#         uploaded_images = validated_data.pop('uploaded_images', [])
#         feature_list = validated_data.pop('feature_list', [])
#         categories = validated_data.pop('categories', [])

#         # If feature_list is a string, parse it
#         # if isinstance(feature_list, str):
#         #     import json
#         #     feature_list = json.loads(feature_list)


#         product = Product.objects.create(**validated_data)
        
#         # Add categories
#         if categories:
#             product.categories.set(categories)


#         # Create product features
#         for idx, feature_data in enumerate(feature_list, 1):
#             ProductFeature.objects.create(
#                 product=product,
#                 order=idx,
#                 # **feature_data
#                 title=feature_data.get('title', ''),
#                 content=feature_data.get('content', '')
#             )
        
#         # Create product images
#         for idx, image in enumerate(uploaded_images):
#             ProductImage.objects.create(
#                 product=product,
#                 image=image,
#                 order=idx + 1,
#                 is_feature=idx == 0  # First image is feature image
#             )
            
        
#         return product

#     def update(self, instance, validated_data):
#         uploaded_images = validated_data.pop('uploaded_images', [])
#         feature_list = validated_data.pop('feature_list', [])
#         categories = validated_data.pop('categories', None)


#         # Update categories if provided
#         if categories is not None:
#             instance.categories.set(categories)


#         # Update product fields
#         for attr, value in validated_data.items():
#             setattr(instance, attr, value)
#         instance.save()
        
#         # Update features
#         if feature_list:
#             instance.features.all().delete()
#             for idx, feature_data in enumerate(feature_list):
#                 ProductFeature.objects.create(
#                     product=instance,
#                     order=idx + 1,
#                     **feature_data
#                 )
        
#         # Add new images
#         for idx, image in enumerate(uploaded_images):
#             ProductImage.objects.create(
#                 product=instance,
#                 image=image,
#                 order=instance.images.count() + idx + 1
#             )
        
#         return instance
class ProductFAQSerializer(serializers.ModelSerializer):
    class Meta:
        model = ProductFAQ
        fields = ['id', 'title', 'content', 'order']

class ProductSerializer(serializers.ModelSerializer):
    images = ProductImageSerializer(many=True, read_only=True)
    features = ProductFeatureSerializer(many=True, read_only=True)
    faq = ProductFAQSerializer(many=True, read_only=True)
    uploaded_images = serializers.ListField(
        child=serializers.ImageField(max_length=1000000),
        write_only=True,
        required=False
    )
    feature_list = serializers.JSONField(required=False)
    faq_list = serializers.JSONField(required=False)
    slug = serializers.SlugField(read_only=True)
    categories = serializers.PrimaryKeyRelatedField(
        many=True,
        queryset=Category.objects.all(),
        required=False
    )
    category_details = CategoryDetailSerializer(source='categories', many=True, read_only=True)
    
    # Meta tag fields
    meta_title = serializers.CharField(write_only=True, required=False)
    meta_description = serializers.CharField(write_only=True, required=False)
    meta_keywords = serializers.CharField(write_only=True, required=False)
    meta_og_title = serializers.CharField(write_only=True, required=False)
    meta_og_description = serializers.CharField(write_only=True, required=False)
    meta_canonical_url = serializers.URLField(write_only=True, required=False)

    class Meta:
        model = Product
        fields = ['id', 'name', 'slug', 'HSN_Code', 'description', 'regular_price', 
                 'selling_price', 'bp_value', 'gst_percentage', 'stock',
                 'is_featured', 'is_bestseller', 'is_new_arrival', 
                 'is_trending', 'is_active', 'images', 'features', 'faq',
                 'uploaded_images', 'feature_list', 'faq_list', 'categories', 
                 'category_details', 'meta_title', 'meta_description', 'meta_keywords',
                 'meta_og_title', 'meta_og_description', 'meta_canonical_url']
        

    def validate(self, data):
        # Add proper validation messages
        if not data.get('name'):
            raise serializers.ValidationError({'name': 'Name is required'})
        
        # Generate slug from name
        from django.utils.text import slugify
        
        # Get the base slug from the name
        base_slug = slugify(data['name'])

        # Check if this slug already exists
        if Product.objects.filter(slug=base_slug).exists():
            # If it exists, append a number to make it unique
            count = 1
            while Product.objects.filter(slug=f"{base_slug}-{count}").exists():
                count += 1
            data['slug'] = f"{base_slug}-{count}"
        else:
            data['slug'] = base_slug
        return data
    
    def validate_feature_list(self, value):
        """
        Validate the feature list data
        """
        # If value is a string, try to parse it as JSON
        if isinstance(value, str):
            try:
                import json
                value = json.loads(value)
            except json.JSONDecodeError:
                raise serializers.ValidationError("Invalid JSON format for feature_list")

        if not isinstance(value, list):
            raise serializers.ValidationError("Feature list must be an array")
        
        for feature in value:
            if not isinstance(feature, dict):
                raise serializers.ValidationError("Each feature must be an object")
            if 'title' not in feature or 'content' not in feature:
                raise serializers.ValidationError("Each feature must have title and content")
        return value
    
    def validate_faq_list(self, value):
        """
        Validate the FAQ list data
        """
        # If value is a string, try to parse it as JSON
        if isinstance(value, str):
            try:
                import json
                value = json.loads(value)
            except json.JSONDecodeError:
                raise serializers.ValidationError("Invalid JSON format for faq_list")

        if not isinstance(value, list):
            raise serializers.ValidationError("FAQ list must be an array")
        
        for faq in value:
            if not isinstance(faq, dict):
                raise serializers.ValidationError("Each FAQ must be an object")
            if 'title' not in faq or 'content' not in faq:
                raise serializers.ValidationError("Each FAQ must have title and content")
        return value

    def create(self, validated_data):
        uploaded_images = validated_data.pop('uploaded_images', [])
        feature_list = validated_data.pop('feature_list', [])
        faq_list = validated_data.pop('faq_list', [])
        categories = validated_data.pop('categories', [])
        
        # Extract meta fields
        meta_fields = {}
        for field in ['meta_title', 'meta_description', 'meta_keywords', 
                     'meta_og_title', 'meta_og_description', 'meta_canonical_url']:
            if field in validated_data:
                meta_fields[field.replace('meta_', '')] = validated_data.pop(field)

        # Create product
        product = Product.objects.create(**validated_data)
        
        # Add categories
        if categories:
            product.categories.set(categories)

        # Create product features
        for idx, feature_data in enumerate(feature_list, 1):
            ProductFeature.objects.create(
                product=product,
                order=idx,
                title=feature_data.get('title', ''),
                content=feature_data.get('content', '')
            )
        
        # Create product FAQs
        for idx, faq_data in enumerate(faq_list, 1):
            ProductFAQ.objects.create(
                product=product,
                order=idx,
                title=faq_data.get('title', ''),
                content=faq_data.get('content', '')
            )
        
        # Create product images
        for idx, image in enumerate(uploaded_images):
            ProductImage.objects.create(
                product=product,
                image=image,
                order=idx + 1,
                is_feature=idx == 0  # First image is feature image
            )
            
        # Create meta tags if provided
        if meta_fields:
            MetaTag.objects.create(
                title=meta_fields.get('title', product.name),
                description=meta_fields.get('description', ''),
                keywords=meta_fields.get('keywords', ''),
                og_title=meta_fields.get('og_title', ''),
                og_description=meta_fields.get('og_description', ''),
                canonical_url=meta_fields.get('canonical_url', ''),
                page_type='PRODUCT',
                product=product
            )
        
        return product

    def update(self, instance, validated_data):
        uploaded_images = validated_data.pop('uploaded_images', [])
        feature_list = validated_data.pop('feature_list', [])
        faq_list = validated_data.pop('faq_list', [])
        categories = validated_data.pop('categories', None)

        # Extract meta fields
        meta_fields = {}
        for field in ['meta_title', 'meta_description', 'meta_keywords', 
                     'meta_og_title', 'meta_og_description', 'meta_canonical_url']:
            if field in validated_data:
                meta_fields[field.replace('meta_', '')] = validated_data.pop(field)

        # Update categories if provided
        if categories is not None:
            instance.categories.set(categories)

        # Update product fields
        for attr, value in validated_data.items():
            setattr(instance, attr, value)
        instance.save()
        
        # Update features
        if feature_list:
            instance.features.all().delete()
            for idx, feature_data in enumerate(feature_list, 1):
                ProductFeature.objects.create(
                    product=instance,
                    order=idx + 1,
                    title=feature_data.get('title', ''),
                    content=feature_data.get('content', '')
                )
                
        # Update FAQs
        if faq_list:
            instance.faq.all().delete()
            for idx, faq_data in enumerate(faq_list, 1):
                ProductFAQ.objects.create(
                    product=instance,
                    order=idx + 1,
                    title=faq_data.get('title', ''),
                    content=faq_data.get('content', '')
                )
        
        # Add new images
        for idx, image in enumerate(uploaded_images):
            ProductImage.objects.create(
                product=instance,
                image=image,
                order=instance.images.count() + idx + 1
            )
            
        # Update meta tags if provided
        if meta_fields:
            meta_tag = MetaTag.objects.filter(product=instance).first()
            if meta_tag:
                for key, value in meta_fields.items():
                    if value:  # Only update if a value was provided
                        setattr(meta_tag, key, value)
                meta_tag.save()
            else:
                # Create new meta tag if it doesn't exist
                MetaTag.objects.create(
                    title=meta_fields.get('title', instance.name),
                    description=meta_fields.get('description', ''),
                    keywords=meta_fields.get('keywords', ''),
                    og_title=meta_fields.get('og_title', ''),
                    og_description=meta_fields.get('og_description', ''),
                    canonical_url=meta_fields.get('canonical_url', ''),
                    page_type='PRODUCT',
                    product=instance
                )
        
        return instance

class CategorySerializer(serializers.ModelSerializer):
    products = ProductSerializer(many=True, read_only=True)
    class Meta:
        model = Category
        fields = '__all__'
        read_only_fields = ['created_at', 'updated_at',  'slug']
        depth = 1
        


    def validate(self, data):
        # Add proper validation messages
        if not data.get('name'):
            raise serializers.ValidationError({'name': 'Name is required'})
        
        # Generate slug from name
        from django.utils.text import slugify
        
        # Get the base slug from the name
        base_slug = slugify(data['name'])

        # Check if this slug already exists
        if Category.objects.filter(slug=base_slug).exists():
            # If it exists, append a number to make it unique
            count = 1
            while Category.objects.filter(slug=f"{base_slug}-{count}").exists():
                count += 1
            data['slug'] = f"{base_slug}-{count}"
        else:
            data['slug'] = base_slug
        return data

    def create(self, validated_data):
        try:
            return super().create(validated_data)
        except Exception as e:
            print(f"Error in create: {str(e)}")
            raise




class PositionSerializer(serializers.ModelSerializer):
    class Meta:
        model = Position
        fields = [
            'id', 
            'name', 
            'bp_required_min', 
            'bp_required_max',
            'discount_percentage', 
            'commission_percentage',
            'can_earn_commission', 
            'monthly_quota', 
            'level_order',
            'is_active'
        ]

    def validate(self, data):
        # Validate BP range
        if data.get('bp_required_min') > data.get('bp_required_max'):
            raise serializers.ValidationError({
                'bp_required_min': 'Minimum BP cannot be greater than maximum BP'
            })
        
        # Check level_order uniqueness on update
        if self.instance:  # If updating
            existing = Position.objects.filter(level_order=data.get('level_order')).exclude(id=self.instance.id)
            if existing.exists():
                raise serializers.ValidationError({
                    'level_order': 'This level order already exists'
                })
        
        return data
    

# Main Serializer for Create/Update Operations
class MLMMemberSerializer(serializers.ModelSerializer):
    # Write-only fields for user creation
    username = serializers.CharField(write_only=True)
    password = serializers.CharField(write_only=True)
    email = serializers.EmailField(write_only=True)
    phone_number = serializers.CharField(write_only=True)
    first_name = serializers.CharField(write_only=True)
    last_name = serializers.CharField(write_only=True)
    
    # Read-only fields for user data display
    user_email = serializers.EmailField(source='user.email', read_only=True)
    user_phone = serializers.CharField(source='user.phone_number', read_only=True)
    user_first_name = serializers.CharField(source='user.first_name', read_only=True)
    user_last_name = serializers.CharField(source='user.last_name', read_only=True)
    member_id = serializers.CharField(read_only=True)

    position_id = serializers.PrimaryKeyRelatedField(
        queryset=Position.objects.all(),
        write_only=True
    )
    sponsor_id = serializers.CharField(required=False, allow_null=True, allow_blank=True)
    
    position_name = serializers.CharField(source='position.name', read_only=True)
    sponsor_name = serializers.CharField(source='sponsor.user.get_full_name', read_only=True)

    monthly_earnings = serializers.SerializerMethodField()
    recent_commissions = serializers.SerializerMethodField()
    withdrawals = serializers.SerializerMethodField()
    pending_payouts = serializers.SerializerMethodField()

    class Meta:
        model = MLMMember
        fields = [
            'id', 'member_id', 
            # Write-only fields
            'username', 'password', 'email', 'phone_number', 'first_name', 'last_name',
            'position_id', 'sponsor_id',
            # Read-only fields
            'user_email', 'user_phone', 'user_first_name', 'user_last_name',
            'position_name', 'sponsor_name', 'is_active' , 'monthly_earnings',
            'recent_commissions',
            'withdrawals',
            'pending_payouts'
        ]
        read_only_fields = ['member_id', 'user_email', 'user_phone', 
                           'user_first_name', 'user_last_name',
                           'position_name', 'sponsor_name']

    def validate_email(self, value):
        if User.objects.filter(email=value).exists():
            raise serializers.ValidationError("This email is already in use.")
        return value

    def validate_phone_number(self, value):
        if not value.isdigit() or len(value) != 10:
            raise serializers.ValidationError("Phone number must be 10 digits.")
        
        # Check if phone number is already in use
        if User.objects.filter(phone_number=value).exists():
            raise serializers.ValidationError("This phone number is already registered.")
        return value

    def validate_username(self, value):
        if User.objects.filter(username=value).exists():
            raise serializers.ValidationError("This username is already taken.")
        return value

    def validate_sponsor_id(self, value):
        if value:
            try:
                MLMMember.objects.get(member_id=value)
            except MLMMember.DoesNotExist:
                raise serializers.ValidationError("Invalid sponsor ID")
        return value

    def create(self, validated_data):
        # First check for unique constraints
        email = validated_data.get('email')
        phone_number = validated_data.get('phone_number')
        username = validated_data.get('username')

        # Double-check uniqueness before creating (to handle race conditions)
        if User.objects.filter(email=email).exists():
            raise serializers.ValidationError({'email': 'This email is already in use.'})
        
        if User.objects.filter(phone_number=phone_number).exists():
            raise serializers.ValidationError({'phone_number': 'This phone number is already registered.'})
        
        if User.objects.filter(username=username).exists():
            raise serializers.ValidationError({'username': 'This username is already taken.'})

        # Extract user data
        user_data = {
            'username': validated_data.pop('username'),
            'password': validated_data.pop('password'),
            'email': validated_data.pop('email'),
            'phone_number': validated_data.pop('phone_number'),
            'first_name': validated_data.pop('first_name'),
            'last_name': validated_data.pop('last_name'),
            'role': 'MLM_MEMBER'
        }

        try:
            # Get position and sponsor
            position = validated_data.pop('position_id')
            sponsor_id = validated_data.pop('sponsor_id', None)
            sponsor = None
            if sponsor_id:
                sponsor = MLMMember.objects.get(member_id=sponsor_id)

            # Create user
            user = User.objects.create_user(**user_data)

            # Create MLM Member
            member = MLMMember.objects.create(
                user=user,
                position=position,
                sponsor=sponsor,
                **validated_data
            )

            return member
            
        except IntegrityError:
            # If there's any database integrity error, make sure to clean up
            if 'user' in locals():
                user.delete()
            raise serializers.ValidationError({
                'error': 'An error occurred while creating the member. Please try again.'
            })
    
    def to_representation(self, instance):
        """
        Customize the output data
        """
        data = super().to_representation(instance)
        # Ensure member_id is included in response
        data['member_id'] = instance.member_id
        return data
    def get_monthly_earnings(self, obj):
        earnings = Commission.objects.filter(
            member=obj
        ).annotate(
            month=TruncMonth('date')
        ).values('month').annotate(
            amount=Sum('amount')
        ).order_by('month')

        return [
            {
                'month': entry['month'].strftime('%b %Y'),
                'amount': float(entry['amount'])
            }
            for entry in earnings
        ]

    def get_recent_commissions(self, obj):
        commissions = Commission.objects.filter(
            member=obj
        ).order_by('-date')[:10]

        return [
            {
                'date': commission.date,
                'amount': float(commission.amount),
                'from_member_name': commission.from_member.user.get_full_name(),
                'is_paid': commission.is_paid
            }
            for commission in commissions
        ]

    def get_withdrawals(self, obj):
        withdrawals = WalletTransaction.objects.filter(
            wallet__user=obj.user,
            transaction_type='WITHDRAWAL'
        ).order_by('-created_at')[:10]

        return [
            {
                'date': withdrawal.created_at,
                'amount': float(withdrawal.amount),
                # 'status': withdrawal.status
                'transaction_type': withdrawal.transaction_type
            }
            for withdrawal in withdrawals
        ]

    def get_pending_payouts(self, obj):
        return float(
            Commission.objects.filter(
                member=obj,
                is_paid=False
            ).aggregate(
                total=Sum('amount')
            )['total'] or 0
        )
    

class MLMMemberBasicSerializer(serializers.ModelSerializer):
    user = UserSerializer(read_only=True)
    position_name = serializers.CharField(source='position.name', read_only=True)
    # Add a method to get full name
    full_name = serializers.SerializerMethodField()

    class Meta:
        model = MLMMember
        fields = ['id', 'member_id', 'user', 'position_name', 'full_name']

    def get_full_name(self, obj):
        return f"{obj.user.first_name} {obj.user.last_name}".strip()



class BankDetailsSerializerNew(serializers.ModelSerializer):
    class Meta:
        model = BankDetails
        fields = [
            'id',
            'account_holder_name',
            'account_number',
            'ifsc_code',
            'bank_name',
            'branch_name',
            'is_verified',
            'verification_date',
            'created_at',
            'updated_at'
        ]
        read_only_fields = ['is_verified', 'verification_date', 'created_at', 'updated_at']

    # def validate_ifsc_code(self, value):
    #     # IFSC code validation
    #     if not value.strip():
    #         raise serializers.ValidationError("IFSC code is required")
        
    #     # IFSC format: AAAA0999999
    #     # First 4 characters: Letters representing bank name
    #     # 5th character: 0
    #     # Last 6 characters: Alphanumeric representing branch code
    #     if not (len(value) == 11 and 
    #             value[:4].isalpha() and 
    #             value[4] == '0' and 
    #             value[5:].isalnum()):
    #         raise serializers.ValidationError("Invalid IFSC code format")
        
    #     return value.upper()

    def validate_account_number(self, value):
        # Basic account number validation
        if not value.strip():
            raise serializers.ValidationError("Account number is required")
        
        # Remove any spaces and check if it's numeric
        cleaned_value = value.replace(" ", "")
        if not cleaned_value.isdigit():
            raise serializers.ValidationError("Account number should contain only digits")
        
        # Check length (most Indian bank account numbers are between 9 and 18 digits)
        if len(cleaned_value) < 9 or len(cleaned_value) > 18:
            raise serializers.ValidationError("Account number should be between 9 and 18 digits")
        
        return cleaned_value

    def validate_account_holder_name(self, value):
        if not value.strip():
            raise serializers.ValidationError("Account holder name is required")
        
        # Remove extra spaces and ensure proper capitalization
        cleaned_value = " ".join(value.split())
        return cleaned_value.title()

    def validate_bank_name(self, value):
        if not value.strip():
            raise serializers.ValidationError("Bank name is required")
        return value.strip()

    def validate_branch_name(self, value):
        if not value.strip():
            raise serializers.ValidationError("Branch name is required")
        return value.strip()
    


    



class TestimonialSerializer(serializers.ModelSerializer):
    image_url = serializers.SerializerMethodField()

    class Meta:
        model = Testimonial
        fields = [
            'id', 'name', 'designation', 'content', 
            'image', 'image_url', 'rating', 'is_active', 
            'display_order', 'created_at'
        ]
        read_only_fields = ['created_at']

    def get_image_url(self, obj):
        if obj.image:
            return self.context['request'].build_absolute_uri(obj.image.url)
        return None

    def validate_rating(self, value):
        if value < 1 or value > 5:
            raise serializers.ValidationError("Rating must be between 1 and 5")
        return value

class AdvertisementSerializer(serializers.ModelSerializer):
    image_url = serializers.SerializerMethodField()
    position_display = serializers.CharField(source='get_position_display', read_only=True)

    class Meta:
        model = Advertisement
        fields = [
            'id', 'title', 'image', 'image_url', 'link', 
            'position', 'position_display', 'is_active', 'created_at'
        ]
        read_only_fields = ['created_at']

    def get_image_url(self, obj):
        if obj.image:
            request = self.context.get('request')
            if request:
                return request.build_absolute_uri(obj.image.url)
        return None
        
    def validate(self, data):
        # Add any additional validation if needed
        print(f"Advertisement serializer validating data: {data}")
        return data
    

class SuccessStorySerializer(serializers.ModelSerializer):
    thumbnail_url = serializers.SerializerMethodField()
    
    class Meta:
        model = SuccessStory
        fields = [
            'id', 'title', 'description', 'youtube_link', 'thumbnail', 
            'thumbnail_url', 'position', 'is_active', 'created_at', 'updated_at'
        ]
        read_only_fields = ['created_at', 'updated_at']
    
    def get_thumbnail_url(self, obj):
        if obj.thumbnail:
            request = self.context.get('request')
            if request:
                return request.build_absolute_uri(obj.thumbnail.url)
        return None

class CustomerPickSerializer(serializers.ModelSerializer):
    thumbnail_url = serializers.SerializerMethodField()
    
    class Meta:
        model = CustomerPickReview
        fields = [
            'id', 'title', 'description', 'youtube_link', 'thumbnail',
            'thumbnail_url', 'position', 'is_active', 'created_at', 'updated_at'
        ]
        read_only_fields = ['created_at', 'updated_at']
    
    def get_thumbnail_url(self, obj):
        if obj.thumbnail:
            request = self.context.get('request')
            if request:
                return request.build_absolute_uri(obj.thumbnail.url)
        return None
    

class CompanyInfoSerializer(serializers.ModelSerializer):
    logo_url = serializers.SerializerMethodField()
    footer_bg_image_url = serializers.SerializerMethodField()
    testimonial_bg_image_url = serializers.SerializerMethodField()
    gst_state = serializers.SerializerMethodField()
    full_address = serializers.CharField(read_only=True)

    class Meta:
        model = CompanyInfo
        fields = [
            'id', 'company_name', 'logo', 'logo_url', 'gst_number', 'gst_state',
            'email', 'mobile_1', 'mobile_2', 'address_line1', 'address_line2',
            'city', 'state', 'pincode', 'country', 'facebook_link',
            'instagram_link', 'twitter_link', 'youtube_link', 'footer_bg_image',
            'footer_bg_image_url', 'testimonial_bg_image', 'testimonial_bg_image_url',
            'is_active', 'created_at', 'updated_at', 'full_address'
        ]
        read_only_fields = ['created_at', 'updated_at']

    def get_logo_url(self, obj):
        if obj.logo:
            request = self.context.get('request')
            if request:
                return request.build_absolute_uri(obj.logo.url)
        return None

    def get_footer_bg_image_url(self, obj):
        if obj.footer_bg_image:
            request = self.context.get('request')
            if request:
                return request.build_absolute_uri(obj.footer_bg_image.url)
        return None

    def get_testimonial_bg_image_url(self, obj):
        if obj.testimonial_bg_image:
            request = self.context.get('request')
            if request:
                return request.build_absolute_uri(obj.testimonial_bg_image.url)
        return None

    def get_gst_state(self, obj):
        return obj.get_gst_state()

    def validate_gst_number(self, value):
        if value:
            # Basic format check
            gst_pattern = r'^\d{2}[A-Z]{5}\d{4}[A-Z]{1}\d[Z]{1}[A-Z\d]{1}$'
            if not re.match(gst_pattern, value):
                raise serializers.ValidationError(
                    'Invalid GST format. Must be 15 characters long with pattern: 22AAAAA0000A1Z5'
                )
        return value



class AboutSerializer(serializers.ModelSerializer):
    type_display = serializers.CharField(source='get_type_display', read_only=True)
    left_image_url = serializers.SerializerMethodField()

    class Meta:
        model = About
        fields = [
            'id', 'type', 'type_display', 'title', 'content', 'feature_content',
            'left_image', 'left_image_url', 'vision_description', 
            'mission_description', 'objective_content', 'is_active',
            'created_at', 'updated_at'
        ]
        read_only_fields = ['created_at', 'updated_at']

    def get_left_image_url(self, obj):
        if obj.left_image:
            request = self.context.get('request')
            if request:
                return request.build_absolute_uri(obj.left_image.url)
        return None

    def validate_type(self, value):
        instance = self.instance
        if instance is None:  # Creating new instance
            if About.objects.filter(type=value).exists():
                raise serializers.ValidationError(
                    f'An About page of type {value} already exists.'
                )
        elif instance.type != value:  # Updating existing instance
            if About.objects.filter(type=value).exists():
                raise serializers.ValidationError(
                    f'An About page of type {value} already exists.'
                )
        return value
    
class ProductListSerializer(serializers.ModelSerializer):
    image_url = serializers.SerializerMethodField()
    images = ProductImageSerializer(many=True, read_only=True)
    feature_image = serializers.SerializerMethodField()
    discount_percentage = serializers.SerializerMethodField()
    class Meta:
        model = Product
        fields = [
            'id', 'name', 'slug', 'regular_price', 'selling_price', 'images',
            'feature_image', 'image_url', 'discount_percentage',
            'is_active', 'is_trending', 'is_featured', 
            'is_new_arrival', 'is_bestseller', 'description',
            'bp_value', 'stock', 'gst_percentage'
        ]

    def get_image_url(self, obj):
        try:
            feature_image = obj.images.filter(is_feature=True).first()
            if feature_image and feature_image.image:
                request = self.context.get('request')
                if request:
                    return request.build_absolute_uri(feature_image.image.url)
            return None
        except Exception as e:
            logger.error(f"Error getting image URL for product {obj.id}: {str(e)}")
            return None

    def get_feature_image(self, obj):
        try:
            feature_image = obj.images.filter(is_feature=True).first()
            if feature_image:
                request = self.context.get('request')
                if request:
                    return request.build_absolute_uri(feature_image.image.url)
            return None
        except Exception as e:
            logger.error(f"Error getting feature image for product {obj.id}: {str(e)}")
            return None

    def get_discount_percentage(self, obj):
        try:
            if obj.regular_price > 0:
                discount = ((obj.regular_price - obj.selling_price) / obj.regular_price) * 100
                return round(discount, 2)
            return 0
        except Exception as e:
            logger.error(f"Error calculating discount for product {obj.id}: {str(e)}")
            return 0
    def to_representation(self, instance):
        try:
            data = super().to_representation(instance)
            # Sort images by order
            if data.get('images'):
                data['images'] = sorted(data['images'], key=lambda x: x.get('order', 0))
            return data
        except Exception as e:
            logger.error(f"Error in to_representation for product {instance.id}: {str(e)}")
            return {}

# class HomeSectionSerializer(serializers.ModelSerializer):
#     section_type_display = serializers.CharField(source='get_section_type_display', read_only=True)
#     image_url = serializers.SerializerMethodField()
#     products = serializers.SerializerMethodField()

#     class Meta:
#         model = HomeSection
#         fields = [
#             'id', 'section_type', 'section_type_display', 'title', 'subtitle',
#             'description', 'image', 'image_url', 'is_active', 'display_order',
#             'created_at', 'updated_at', 'products'
#         ]
#         read_only_fields = ['created_at', 'updated_at']

#     def get_image_url(self, obj):
#         if obj.image:
#             request = self.context.get('request')
#             if request:
#                 return request.build_absolute_uri(obj.image.url)
#         return None

#     def get_products(self, obj):
#         products = obj.get_products()
#         return ProductListSerializer(products, many=True, context=self.context).data

#     def validate_section_type(self, value):
#         if value not in HomeSectionType.values:
#             raise serializers.ValidationError(f"Invalid section type. Must be one of: {HomeSectionType.values}")
#         instance = self.instance
#         if instance is None:  # Creating new instance
#             if HomeSection.objects.filter(section_type=value).exists():
#                 raise serializers.ValidationError(f'A section with type {value} already exists.')
#         elif instance.section_type != value:  # Updating instance
#             if HomeSection.objects.filter(section_type=value).exists():
#                 raise serializers.ValidationError(f'A section with type {value} already exists.')
#         return value

class HomeSectionSerializer(serializers.ModelSerializer):
    section_type_display = serializers.CharField(source='get_section_type_display', read_only=True)
    image_url = serializers.SerializerMethodField()
    products = serializers.SerializerMethodField()

    class Meta:
        model = HomeSection
        fields = [
            'id', 'section_type', 'section_type_display', 'title', 'subtitle',
            'description', 'image', 'image_url', 'is_active', 'display_order',
            'created_at', 'updated_at', 'products'
        ]
        read_only_fields = ['created_at', 'updated_at']


    def get_image_url(self, obj):
        try:
            if obj.image:
                request = self.context.get('request')
                if request:
                    return request.build_absolute_uri(obj.image.url)
            return None
        except Exception as e:
            logger.error(f"Error getting image URL: {str(e)}")
            return None

    def get_products(self, obj):
        try:
            if not hasattr(obj, 'get_products'):
                logger.error(f"Section {obj.id} does not have get_products method")
                return []
            products = obj.get_products()

            logger.info(f"Found {products.count()} products for section {obj.section_type}")

            # Make sure we have request in context
            if 'request' not in self.context:
                logger.error("Request missing from serializer context")
                self.context['request'] = self.context.get('request')

            return ProductListSerializer(
                products, 
                many=True, 
                context=self.context
            ).data
        except Exception as e:
            logger.error(f"Error getting products: {str(e)}")
            logger.exception(e)
            return []

    def to_representation(self, instance):
        try:
            data = super().to_representation(instance)
            
            # Log the data being returned for debugging
            logger.info(f"Section {instance.id} data: {data}")
            
            # Ensure proper image URL
            if data.get('image'):
                if not data.get('image_url'):
                    request = self.context.get('request')
                    if request and hasattr(instance.image, 'url'):
                        data['image_url'] = request.build_absolute_uri(instance.image.url)
            
            return data
        except Exception as e:
            logger.error(f"Error in to_representation for section {instance.id}: {str(e)}")
            return {}

    def validate_section_type(self, value):
        if value not in HomeSectionType.values:
            raise serializers.ValidationError(f"Invalid section type. Must be one of: {HomeSectionType.values}")
        
        instance = self.instance
        if instance is None:  # Creating new instance
            if HomeSection.objects.filter(section_type=value).exists():
                raise serializers.ValidationError(f'A section with type {value} already exists.')
        elif instance.section_type != value:  # Updating instance
            if HomeSection.objects.filter(section_type=value).exists():
                raise serializers.ValidationError(f'A section with type {value} already exists.')
                
        return value
        
class MenuSerializer(serializers.ModelSerializer):
    category_details = CategorySerializer(source='category', read_only=True)
    category_name = serializers.CharField(source='category.name', read_only=True)

    class Meta:
        model = Menu
        fields = [
            'id', 'category', 'category_details', 'category_name',
            'position', 'is_active', 'created_at', 'updated_at'
        ]
        read_only_fields = ['created_at', 'updated_at']

    def validate_position(self, value):
        if value < 0:
            raise serializers.ValidationError("Position cannot be negative")
        return value


class CustomPageSerializer(serializers.ModelSerializer):
    class Meta:
        model = CustomPage
        fields = ['id', 'title', 'slug', 'content', 'is_active', 
                 'show_in_footer', 'show_in_header', 'order', 
                 'created_at', 'updated_at']
            
class KYCDocumentSerializer(serializers.ModelSerializer):
    mlm_member_name = serializers.CharField(source='mlm_member.user.username', read_only=True)
    member_id = serializers.CharField(source='mlm_member.member_id', read_only=True)
    verified_by_name = serializers.CharField(source='verified_by.username', read_only=True)
    document_type_display = serializers.CharField(source='get_document_type_display', read_only=True)
    status_display = serializers.CharField(source='get_status_display', read_only=True)
    mlm_member = serializers.PrimaryKeyRelatedField(read_only=True)  # Make this read-only

    class Meta:
        model = KYCDocument
        fields = [
            'id', 'mlm_member', 'mlm_member_name', 'member_id', 'document_type',
            'document_type_display', 'document_number', 'document_file', 'status',
            'status_display', 'verified_by', 'verified_by_name', 'verification_date',
            'rejection_reason', 'created_at', 'updated_at'
        ]
        read_only_fields = ['verified_by', 'verification_date', 'status', 'mlm_member']

    def validate_document_file(self, value):
        # Validate file size (5MB)
        if value.size > 5 * 1024 * 1024:
            raise serializers.ValidationError("File size should not exceed 5MB")
        
        # Validate file type
        allowed_types = ['image/jpeg', 'image/png', 'application/pdf']
        if hasattr(value, 'content_type') and value.content_type not in allowed_types:
            raise serializers.ValidationError("Only JPG, PNG and PDF files are allowed")
        
        return value

    def validate_document_number(self, value):
        if not value or not value.strip():
            raise serializers.ValidationError("Document number is required")
        return value.strip()

    def create(self, validated_data):
        request = self.context.get('request')
        if not request or not request.user:
            raise serializers.ValidationError("Authentication required")

        if not hasattr(request.user, 'mlm_profile'):
            raise serializers.ValidationError("User does not have an MLM profile")

        # Set the MLM member before creating
        validated_data['mlm_member'] = request.user.mlm_profile
        validated_data['status'] = 'PENDING'  # Set initial status

        # Check if document already exists for this member and type
        existing_doc = KYCDocument.objects.filter(
            mlm_member=request.user.mlm_profile,
            document_type=validated_data['document_type']
        ).first()

        if existing_doc:
            # Update existing document
            for key, value in validated_data.items():
                setattr(existing_doc, key, value)
            existing_doc.save()
            return existing_doc

        return super().create(validated_data)
    


class MLMMemberListSerializer(serializers.ModelSerializer):
    user = UserSerializer(read_only=True)
    position = PositionSerializer(read_only=True)
    sponsor = MLMMemberBasicSerializer(read_only=True)
    monthly_earnings = serializers.SerializerMethodField()
    recent_commissions = serializers.SerializerMethodField()
    withdrawals = serializers.SerializerMethodField()
    pending_payouts = serializers.SerializerMethodField()
    bank_details = BankDetailsSerializerNew(read_only=True)
    kyc_documents = KYCDocumentSerializer(many=True, read_only=True, source='kyc_documents.all')
    class Meta:
        model = MLMMember
        fields = [
            'id', 'member_id', 'user', 'position', 'sponsor',
            'total_bp', 'current_month_purchase', 'is_active',
            'join_date', 'total_earnings', 'monthly_earnings',
            'recent_commissions', 'withdrawals', 'pending_payouts' ,'bank_details' , 'kyc_documents'
        ]

    def get_monthly_earnings(self, obj):
        monthly = Commission.objects.filter(
            member=obj
        ).annotate(
            month=TruncMonth('date')
        ).values('month').annotate(
            amount=Sum('amount')
        ).order_by('month')

        return [
            {
                'month': entry['month'].strftime('%b %Y'),
                'amount': float(entry['amount'])
            }
            for entry in monthly
        ]

    def get_recent_commissions(self, obj):
        commissions = Commission.objects.filter(
            member=obj
        ).select_related('from_member__user').order_by('-date')[:10]

        return [
            {
                'date': commission.date,
                'amount': float(commission.amount),
                'from_member_name': commission.from_member.user.get_full_name(),
                'is_paid': commission.is_paid
            }
            for commission in commissions
        ]

    def get_withdrawals(self, obj):
        withdrawals = WithdrawalRequest.objects.filter(
            wallet__user=obj.user
        ).order_by('-created_at')

        return [
            {
                'date': withdrawal.created_at,
                'amount': float(withdrawal.amount),
                'status': withdrawal.status
            }
            for withdrawal in withdrawals
        ]

    def get_pending_payouts(self, obj):
        return float(
            Commission.objects.filter(
                member=obj,
                is_paid=False
            ).aggregate(
                total=Sum('amount')
            )['total'] or 0
        )
    

class BlogSerializer(serializers.ModelSerializer):
    feature_image_url = serializers.SerializerMethodField()

    class Meta:
        model = Blog
        fields = [
            'id', 'title', 'slug', 'content', 'feature_image', 
            'feature_image_url', 'is_active', 'show_in_slider', 
            'order', 'created_at', 'updated_at'
        ]
        read_only_fields = ['slug', 'created_at', 'updated_at']

    def get_feature_image_url(self, obj):
        if obj.feature_image:
            request = self.context.get('request')
            if request:
                return request.build_absolute_uri(obj.feature_image.url)
        return None

    def create(self, validated_data):
        # Generate slug from title
        validated_data['slug'] = slugify(validated_data['title'])
        return super().create(validated_data)

    def update(self, instance, validated_data):
        # Update slug if title changes
        if 'title' in validated_data and validated_data['title'] != instance.title:
            validated_data['slug'] = slugify(validated_data['title'])
        return super().update(instance, validated_data)



class AddressSerializer(serializers.ModelSerializer):
    class Meta:
        model = Address
        fields = ['id', 'name', 'street_address', 'city', 'state', 
                 'postal_code', 'is_active', 'created_at', 'updated_at']
        read_only_fields = ['created_at', 'updated_at']

    def validate(self, data):
        # If this is the first address, make it default
        user = self.context['request'].user
        if not Address.objects.filter(user=user).exists():
            data['is_active'] = True
        return data



class CustomerProfileSerializer(serializers.ModelSerializer):
    # first_name = serializers.CharField(source='first_name', required=False, allow_blank=True)
    # last_name = serializers.CharField(source='last_name', required=False, allow_blank=True)

    
    class Meta:
        model = User
        fields = ['id', 'first_name', 'last_name', 'email', 'phone_number', 'role']
        read_only_fields = ['id', 'phone_number']

    def validate_email(self, value):
        if not value:
            return value
            
        # Check if email exists for other users
        if User.objects.exclude(id=self.instance.id).filter(email=value).exists():
            raise serializers.ValidationError("This email is already in use.")
        return value

    def update(self, instance, validated_data):
        # Update fields while preserving phone number
        instance.first_name = validated_data.get('first_name', instance.first_name)
        instance.last_name = validated_data.get('last_name', instance.last_name)
        instance.email = validated_data.get('email', instance.email)
        
        instance.save()
        return instance
    
class MLMProfileSerializer(serializers.ModelSerializer):
    class Meta:
        model = User
        fields = ['first_name', 'last_name', 'email' ,'phone_number']
        
    def validate_email(self, value):
        # Check if email is already in use by another user
        if User.objects.exclude(pk=self.instance.pk).filter(email=value).exists():
            raise serializers.ValidationError("This email is already in use.")
        return value

    def update(self, instance, validated_data):
        # Update only allowed fields
        instance.first_name = validated_data.get('first_name', instance.first_name)
        instance.last_name = validated_data.get('last_name', instance.last_name)
        instance.email = validated_data.get('email', instance.email)
        instance.phone_number = validated_data.get('phone_number', instance.phone_number)
        instance.save()
        return instance

class OrderItemSerializer(serializers.ModelSerializer):
    product = ProductSerializer()

    class Meta:
        model = OrderItem
        fields = [
            'id', 'product', 'quantity', 'price', 
            'discount_percentage', 'discount_amount',
            'gst_amount', 'final_price', 'bp_points'
        ]
class ShippingAddressSerializer(serializers.ModelSerializer):
    class Meta:
        model = ShippingAddress
        fields = ['name', 'street_address', 'city', 'state', 'postal_code']

# class OrderSerializer(serializers.ModelSerializer):
#     items = OrderItemSerializer(many=True, read_only=True)
#     user = serializers.SerializerMethodField()
#     shipping_details = ShippingAddressSerializer(read_only=True)
#     # Or use SerializerMethodField
#     final_amount_display = serializers.SerializerMethodField()

#     def get_final_amount_display(self, obj):
#         return float(obj.final_amount)
#     class Meta:
#         model = Order
#         fields = [
#             'id', 'order_number', 'order_date', 'status',
#             'total_amount', 'discount_amount', 'final_amount',
#             'final_amount_display', 'shipping_address', 'billing_address', 'total_bp',
#             'items' ,'user' , 'shipping_details'
#         ]
#     def get_user(self, obj):
#         # Return a dictionary with user details
#         return {
#             'first_name': obj.user.first_name,
#             'last_name': obj.user.last_name,
#             'email': obj.user.email,
#             'phone_number': obj.user.phone_number
#         }
class OrderSerializer(serializers.ModelSerializer):
    items = OrderItemSerializer(many=True, read_only=True)
    user = serializers.SerializerMethodField()
    shipping_details = ShippingAddressSerializer(read_only=True)
    final_amount_display = serializers.SerializerMethodField()
    payment_type = serializers.CharField(source='get_orderType_display', read_only=True)
    shipments = serializers.SerializerMethodField()
    shipping_charges = serializers.SerializerMethodField()

    def get_final_amount_display(self, obj):
        return float(obj.final_amount)
        
    def get_shipments(self, obj):
        """Get shipment information for the order"""
        try:
            shipments = Shipment.objects.filter(order=obj)
            return [
                {
                    'id': shipment.id,
                    'awb_number': shipment.awb_number,
                    'courier_name': shipment.courier_name,
                    'status': shipment.status,
                    'tracking_url': shipment.tracking_url,
                    'created_at': shipment.created_at,
                    'shipping_charge': float(shipment.shipping_charge) if shipment.shipping_charge else 0,
                    'service_type': shipment.service_type,
                    'status_updates': [
                        {
                            'status': update.status,
                            'status_details': update.status_details,
                            'location': update.location,
                            'timestamp': update.timestamp
                        } for update in ShipmentStatusUpdate.objects.filter(shipment=shipment).order_by('-timestamp')
                    ]
                } for shipment in shipments
            ]
        except Exception as e:
            logger.error(f"Error retrieving shipment data: {str(e)}")
            return []
            
    def get_shipping_charges(self, obj):
        """Calculate total shipping charges from all shipments"""
        try:
            shipments = Shipment.objects.filter(order=obj)
            total_shipping = sum(float(s.shipping_charge or 0) for s in shipments)
            return total_shipping
        except Exception as e:
            logger.error(f"Error calculating shipping charges: {str(e)}")
            return 0

    class Meta:
        model = Order
        fields = [
            'id', 'order_number', 'order_date', 'status',
            'total_amount', 'discount_amount', 'final_amount',
            'final_amount_display', 'shipping_address', 'billing_address', 'total_bp',
            'items', 'user', 'shipping_details', 'payment_type', 'orderType', 
            'shipments', 'shipping_charges'
        ]
        
    def get_user(self, obj):
        # Return a dictionary with user details
        return {
            'first_name': obj.user.first_name,
            'last_name': obj.user.last_name,
            'email': obj.user.email,
            'phone_number': obj.user.phone_number
        }

class BankDetailsSerializer(serializers.ModelSerializer):
    class Meta:
        model = BankDetails
        fields = ['account_holder_name', 'account_number', 'ifsc_code', 
                 'bank_name', 'branch_name']

class WalletSerializer(serializers.ModelSerializer):
    total_earnings = serializers.SerializerMethodField()
    pending_withdrawals = serializers.SerializerMethodField()
    
    class Meta:
        model = Wallet
        fields = ['id', 'balance', 'total_earnings', 'pending_withdrawals', 'last_updated']

    def get_total_earnings(self, obj):
        # Sum all commission transactions
        total = WalletTransaction.objects.filter(
            wallet=obj,
            transaction_type='COMMISSION',
        ).aggregate(total=models.Sum('amount'))['total'] or Decimal('0.00')
        return float(total)

    def get_pending_withdrawals(self, obj):
        # Sum all pending withdrawal requests
        pending = WithdrawalRequest.objects.filter(
            wallet=obj,
            status='PENDING'
        ).aggregate(total=models.Sum('amount'))['total'] or Decimal('0.00')
        return float(pending)
    # pending_withdrawals = serializers.DecimalField(
    #     max_digits=10, decimal_places=2, read_only=True
    # )
    # total_earnings = serializers.DecimalField(
    #     max_digits=10, decimal_places=2, read_only=True
    # )

    # class Meta:
    #     model = Wallet
    #     fields = ['id', 'balance', 'pending_withdrawals', 
    #              'total_earnings', 'last_updated']

class WalletTransactionSerializer(serializers.ModelSerializer):
    class Meta:
        model = WalletTransaction
        fields = ['id', 'amount', 'transaction_type', 'description', 
                 'created_at', 'reference_id']
        read_only_fields = ['created_at']

class WithdrawalRequestSerializer(serializers.ModelSerializer):
    member_name = serializers.CharField(source='wallet.user.get_full_name', read_only=True)
    member_id = serializers.CharField(source='wallet.user.mlm_profile.member_id', read_only=True)
    bank_details = BankDetailsSerializer(source='wallet.user.mlm_profile.bank_details', read_only=True)
    status = serializers.CharField(read_only=True)

    class Meta:
        model = WithdrawalRequest
        fields = ['id', 'wallet', 'amount', 'status', 'created_at', 
                 'processed_at', 'rejection_reason', 'member_name', 
                 'member_id', 'bank_details']
        read_only_fields = ['processed_at', 'rejection_reason']


    
class NotificationSerializer(serializers.ModelSerializer):
    recipient_name = serializers.CharField(source='recipient.user.get_full_name', read_only=True)
    notification_type_display = serializers.CharField(source='get_notification_type_display', read_only=True)
    recipient = serializers.PrimaryKeyRelatedField(
        queryset=MLMMember.objects.all(),
        required=False,
        allow_null=True
    )
    time_ago = serializers.SerializerMethodField()

    class Meta:
        model = Notification
        fields = [
            'id', 'title', 'message', 'notification_type', 
            'notification_type_display', 'recipient', 'recipient_name',
            'is_read', 'created_at', 'read_at', 'time_ago'
        ]
        read_only_fields = ['is_read', 'created_at', 'read_at']

    def validate(self, data):
        notification_type = data.get('notification_type')
        recipient = data.get('recipient')

        if notification_type == 'INDIVIDUAL' and not recipient:
            raise serializers.ValidationError({
                'recipient': 'Recipient is required for individual notifications'
            })

        if notification_type == 'GENERAL' and recipient:
            data['recipient'] = None

        # Verify recipient is active if provided
        if recipient and not recipient.is_active:
            raise serializers.ValidationError({
                'recipient': 'Selected recipient is not active'
            })

        return data

    def get_time_ago(self, obj):
        from django.utils import timezone
        now = timezone.now()
        diff = now - obj.created_at

        if diff.days > 30:
            return obj.created_at.strftime("%b %d, %Y")
        elif diff.days > 0:
            return f"{diff.days} days ago"
        elif diff.seconds > 3600:
            hours = diff.seconds // 3600
            return f"{hours} hours ago"
        elif diff.seconds > 60:
            minutes = diff.seconds // 60
            return f"{minutes} minutes ago"
        else:
            return "Just now"
        
class MLMMemberRegistrationSerializer(serializers.Serializer):
    first_name = serializers.CharField(max_length=100, required=True)
    last_name = serializers.CharField(max_length=100, required=False, allow_blank=True)
    phone_number = serializers.CharField(max_length=15, required=True)
    email = serializers.EmailField(required=False, allow_blank=True)
    password = serializers.CharField(required=True, write_only=True)
    document_types = serializers.ListField(
        child=serializers.CharField(),
        required=False,
        allow_empty=True
    )
    document_numbers = serializers.DictField(
        child=serializers.CharField(),
        required=False
    )

    def validate_phone_number(self, value):
        if not value.isdigit():
            raise serializers.ValidationError("Phone number must contain only digits")
        if len(value) != 10:
            raise serializers.ValidationError("Phone number must be 10 digits long")
        if User.objects.filter(phone_number=value).exists():
            raise serializers.ValidationError("Phone number is already registered")
        return value

    def validate_email(self, value):
        if value:
            value = value.strip().lower()
            if User.objects.filter(email=value).exists():
                raise serializers.ValidationError("Email is already registered")
        return value

    def validate(self, data):
        # Validate documents
        document_types = self.context.get('document_types', [])
        if not document_types or len(document_types) < 2:
            raise serializers.ValidationError({
                "document_types": "At least two documents (Aadhar and PAN) are required"
            })

        # Validate document numbers
        document_numbers = self.context.get('document_numbers', {})
        required_docs = ['AADHAR', 'PAN']
        for doc_type in required_docs:
            if doc_type not in document_numbers or not document_numbers[doc_type]:
                raise serializers.ValidationError({
                    "document_numbers": f"{doc_type} number is required"
                })

        return data
    



class ContactSerializer(serializers.ModelSerializer):
    class Meta:
        model = Contact
        fields = [
            'id', 'name', 'email', 'phone', 
            'subject', 'message', 'created_at'
        ]
        read_only_fields = ['created_at']

    def validate_phone(self, value):
        # Basic phone number validation
        value = value.strip()
        if not value.isdigit() or len(value) < 10:
            raise serializers.ValidationError("Please enter a valid phone number")
        return value

    def validate_email(self, value):
        value = value.strip().lower()
        if not value:
            raise serializers.ValidationError("Email is required")
        return value
    



class NewsletterSerializer(serializers.ModelSerializer):
    class Meta:
        model = Newsletter
        fields = ['id', 'email', 'is_active', 'created_at']
        read_only_fields = ['is_active', 'created_at']

    def validate_email(self, value):
        value = value.strip().lower()
        if not value:
            raise serializers.ValidationError("Email is required")
        if Newsletter.objects.filter(email=value).exists():
            raise serializers.ValidationError("This email is already subscribed")
        return value
    


class CustomerListSerializer(serializers.ModelSerializer):
    order_count = serializers.IntegerField(read_only=True)
    
    class Meta:
        model = User
        fields = [
            'id', 'username', 'first_name', 'last_name', 'email', 
            'phone_number', 'date_joined', 'order_count'
        ]

class CustomerDetailSerializer(serializers.ModelSerializer):
    addresses = AddressSerializer(many=True)
    order_count = serializers.IntegerField(read_only=True)
    
    class Meta:
        model = User
        fields = [
            'id', 'username', 'first_name', 'last_name', 'email', 
            'phone_number', 'date_joined', 'order_count', 'addresses'
        ]



class CommissionActivationRequestSerializer(serializers.ModelSerializer):
    requester_name = serializers.CharField(
        source='requester.user.get_full_name', 
        read_only=True
    )
    requester_member_id = serializers.CharField(
        source='requester.member_id', 
        read_only=True
    )
    sponsor_name = serializers.CharField(
        source='sponsor.user.get_full_name', 
        read_only=True,
        allow_null=True
    )
    sponsor_member_id = serializers.CharField(
        source='sponsor.member_id', 
        read_only=True,
        allow_null=True
    )
    processed_by_name = serializers.CharField(
        source='processed_by.username', 
        read_only=True,
        allow_null=True
    )
    current_position_name = serializers.CharField(
        source='current_position.name', 
        read_only=True
    )
    target_position_name = serializers.CharField(
        source='target_position.name', 
        read_only=True
    )

    class Meta:
        model = CommissionActivationRequest
        fields = [
            'id', 
            'requester', 
            'requester_name',
            'requester_member_id',
            'sponsor',
            'sponsor_name',
            'sponsor_member_id',
            'current_position',
            'current_position_name',
            'target_position',
            'target_position_name',
            'status', 
            'created_at', 
            'processed_at', 
            'processed_by',
            'processed_by_name',
            'reason'
        ]
        extra_kwargs = {
            'requester': {'required': True},
            'current_position': {'required': True},
            'target_position': {'required': True},
            'sponsor': {'required': False, 'allow_null': True},
            'status': {'read_only': True},
            'created_at': {'read_only': True},
            'processed_at': {'read_only': True},
            'processed_by': {'read_only': True}
        }

    def validate(self, data):
        """
        Additional validation to ensure data consistency
        """
        # Ensure required fields are present
        if not data.get('requester'):
            raise serializers.ValidationError("Requester is required")
        
        if not data.get('current_position'):
            raise serializers.ValidationError("Current position is required")
        
        if not data.get('target_position'):
            raise serializers.ValidationError("Target position is required")
        
        return data


class ShippingConfigSerializer(serializers.ModelSerializer):
    """Serializer for ShippingConfig model"""
    class Meta:
        model = ShippingConfig
        fields = [
            'id', 'email', 'first_name', 'last_name',
            'mobile', 'customer_id',
            'default_courier', 'default_service_type', 'created_at', 'updated_at'
        ]
        read_only_fields = ['customer_id', 'created_at', 'updated_at']
        
    def validate_email(self, value):
        """Validate email"""
        if not value:
            raise serializers.ValidationError("Email is required")
        return value


class PickupAddressSerializer(serializers.ModelSerializer):
    """Serializer for PickupAddress model"""
    class Meta:
        model = PickupAddress
        fields = [
            'id', 'name', 'address_id', 'customer_id', 'contact_person',
            'address_line1', 'address_line2', 'city', 'state', 'country',
            'pincode', 'phone', 'alternate_phone', 'email', 'landmark',
            'address_type', 'is_default', 'is_active', 'created_at', 'updated_at'
        ]
        read_only_fields = ['address_id', 'customer_id', 'created_at', 'updated_at']
        
    def validate(self, data):
        """Validate address data"""
        required_fields = ['name', 'contact_person', 'address_line1', 'city', 
                           'state', 'pincode', 'phone']
        
        for field in required_fields:
            if not data.get(field):
                raise serializers.ValidationError(f"{field} is required")
                
        # Validate pincode format
        pincode = data.get('pincode', '')
        if not pincode.isdigit() or len(pincode) not in [5, 6]:
            raise serializers.ValidationError("Pincode must be 5 or 6 digits")
            
        # Validate phone format
        phone = data.get('phone', '')
        if not phone.isdigit() or len(phone) < 10 or len(phone) > 12:
            raise serializers.ValidationError("Phone number must be 10-12 digits")
            
        return data


class ShipmentStatusUpdateSerializer(serializers.ModelSerializer):
    """Serializer for ShipmentStatusUpdate model"""
    class Meta:
        model = ShipmentStatusUpdate
        fields = [
            'id', 'shipment', 'status', 'status_details', 
            'location', 'timestamp', 'created_at'
        ]
        read_only_fields = ['created_at']

class OrderMinimalSerializer(serializers.ModelSerializer):
    class Meta:
        model = Order
        fields = ['id', 'order_number', 'order_date', 'status']

class ShipmentSerializer(serializers.ModelSerializer):
    """Serializer for Shipment model"""
    status_display = serializers.CharField(source='get_status_display', read_only=True)
    status_updates = ShipmentStatusUpdateSerializer(many=True, read_only=True)
    tracking_link = serializers.SerializerMethodField()
    # order = OrderMinimalSerializer(read_only=True)
    # order = serializers.PrimaryKeyRelatedField(queryset=Order.objects.all(), required=True)

    # Accept order_id as input
    order_id = serializers.PrimaryKeyRelatedField(queryset=Order.objects.all(), source="order", write_only=True)
    
    # Show full order details in response
    order = OrderMinimalSerializer(read_only=True)
    
    class Meta:
        model = Shipment
        fields = [
            'id', 'order_id', 'order', 'pickup_address', 'awb_number', 'shipment_id',
            'courier_name', 'service_type', 'status', 'status_display', 
            'status_details', 'tracking_url', 'tracking_link', 'weight', 
            'length', 'width', 'height', 'is_cod', 'cod_amount', 
            'shipping_charge', 'is_cancelled', 'created_at', 'updated_at',
            'status_updates'
        ]
        read_only_fields = [
            'awb_number', 'shipment_id', 'status_details', 'tracking_url',
            'shipping_charge', 'created_at', 'updated_at', 'status_updates', 
        ]
        
    def get_tracking_link(self, obj):
        """Generate a tracking link based on the courier"""
        if not obj.awb_number:
            return None
            
        # Different tracking URLs for different couriers
        if obj.courier_name == 'DTDC':
            return f"https://tracking.dtdc.com/tracking/tracking_results.asp?ttrk={obj.awb_number}"
        elif obj.courier_name == 'DELHIVERY':
            return f"https://www.delhivery.com/track/?tracking_id={obj.awb_number}"
        elif obj.courier_name == 'SHADOWFAX':
            return f"https://shadowfax.in/track-order/{obj.awb_number}"
        
        # Return the tracking URL from the object if available
        return obj.tracking_url
    
    def validate(self, data):
        """Custom validation for shipment data"""
        # Ensure order status is appropriate for shipping
        order = data.get('order')
        if order and order.status not in ['PENDING', 'CONFIRMED']:
            raise serializers.ValidationError(
                f"Cannot create shipment for order with status {order.status}"
            )
            
        # Validate dimensions
        for field in ['weight', 'length', 'width', 'height']:
            value = data.get(field)
            if value and value <= 0:
                raise serializers.ValidationError(f"{field} must be positive")
                
        # Validate COD amount
        is_cod = data.get('is_cod', False)
        cod_amount = data.get('cod_amount', 0)
        
        if is_cod and cod_amount <= 0:
            raise serializers.ValidationError("COD amount must be positive for COD shipments")
            
        if not is_cod and cod_amount > 0:
            raise serializers.ValidationError("COD amount must be zero for non-COD shipments")
            
        return data

class StaffPermissionSerializer(serializers.ModelSerializer):
    class Meta:
        model = StaffPermission
        fields = ['id', 'name', 'description', 'module', 'is_active']


class StaffRoleSerializer(serializers.ModelSerializer):
    permissions = StaffPermissionSerializer(many=True, read_only=True)
    permission_ids = serializers.PrimaryKeyRelatedField(
        queryset=StaffPermission.objects.all(), 
        many=True, 
        write_only=True,
        required=False
    )

    class Meta:
        model = StaffRole
        fields = ['id', 'name', 'description', 'permissions', 'permission_ids', 'is_active']

    def create(self, validated_data):
        permission_ids = validated_data.pop('permission_ids', [])
        role = StaffRole.objects.create(**validated_data)
        if permission_ids:
            role.permissions.set(permission_ids)
        return role

    def update(self, instance, validated_data):
        permission_ids = validated_data.pop('permission_ids', None)
        
        # Update role fields
        for attr, value in validated_data.items():
            setattr(instance, attr, value)
        instance.save()
        
        # Update permissions if provided
        if permission_ids is not None:
            instance.permissions.set(permission_ids)
            
        return instance


class StaffMemberCreateSerializer(serializers.ModelSerializer):
    """Serializer for creating staff members with associated user"""
    # User fields
    username = serializers.CharField(write_only=True)
    password = serializers.CharField(write_only=True, style={'input_type': 'password'})
    email = serializers.EmailField(write_only=True)
    first_name = serializers.CharField(write_only=True)
    last_name = serializers.CharField(write_only=True, required=False, allow_blank=True)
    
    # Permission fields
    role_id = serializers.PrimaryKeyRelatedField(
        queryset=StaffRole.objects.all(),
        source='role'
    )
    supervisor_id = serializers.PrimaryKeyRelatedField(
        queryset=StaffMember.objects.all(),
        source='supervisor',
        required=False,
        allow_null=True
    )
    custom_permission_ids = serializers.PrimaryKeyRelatedField(
        queryset=StaffPermission.objects.all(),
        many=True,
        write_only=True,
        required=False
    )
    
    # Module permission checkboxes (write-only)
    # Add fields for each permission module
    user_management_permissions = serializers.MultipleChoiceField(
        choices=[], 
        required=False, 
        write_only=True
    )
    order_management_permissions = serializers.MultipleChoiceField(
        choices=[], 
        required=False, 
        write_only=True
    )
    product_management_permissions = serializers.MultipleChoiceField(
        choices=[], 
        required=False, 
        write_only=True
    )
    kyc_management_permissions = serializers.MultipleChoiceField(
        choices=[], 
        required=False, 
        write_only=True
    )
    report_management_permissions = serializers.MultipleChoiceField(
        choices=[], 
        required=False, 
        write_only=True
    )
    wallet_management_permissions = serializers.MultipleChoiceField(
        choices=[], 
        required=False, 
        write_only=True
    )
    settings_management_permissions = serializers.MultipleChoiceField(
        choices=[], 
        required=False, 
        write_only=True
    )

    class Meta:
        model = StaffMember
        fields = [
            'id', 'username', 'password', 'email', 'first_name', 'last_name',
            'role_id', 'supervisor_id', 'department', 'phone_number', 'employee_id',
            'is_active', 'custom_permission_ids',
            'user_management_permissions', 'order_management_permissions',
            'product_management_permissions', 'kyc_management_permissions',
            'report_management_permissions', 'wallet_management_permissions',
            'settings_management_permissions'
        ]
        read_only_fields = ['id']

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        
        # Dynamically load permission choices for each module
        modules = ['user_management', 'order_management', 'product_management', 
                 'kyc_management', 'report_management', 'wallet_management',
                 'settings_management']
                 
        for module in modules:
            field_name = f"{module}_permissions"
            if field_name in self.fields:
                permissions = StaffPermission.objects.filter(
                    module=module, 
                    is_active=True
                )
                self.fields[field_name].choices = [
                    (perm.id, perm.name) for perm in permissions
                ]

    @transaction.atomic
    def create(self, validated_data):
        # Extract user data
        user_data = {
            'username': validated_data.pop('username'),
            'password': validated_data.pop('password'),
            'email': validated_data.pop('email'),
            'first_name': validated_data.pop('first_name'),
            'last_name': validated_data.pop('last_name', ''),
            'role': 'ADMIN'  # Set role to ADMIN for staff
        }
        
        # Extract permission data
        custom_permission_ids = validated_data.pop('custom_permission_ids', [])
        
        # Extract module permissions
        module_permission_ids = []
        modules = ['user_management', 'order_management', 'product_management', 
                 'kyc_management', 'report_management', 'wallet_management',
                 'settings_management']
                 
        for module in modules:
            field_name = f"{module}_permissions"
            if field_name in validated_data:
                module_permission_ids.extend(validated_data.pop(field_name, []))
        
        # Combine all permission IDs
        all_permission_ids = set(custom_permission_ids + module_permission_ids)
        
        # Create user
        user = User.objects.create_user(**user_data)
        
        # Create staff member
        staff_member = StaffMember.objects.create(user=user, **validated_data)
        
        # Set custom permissions
        if all_permission_ids:
            staff_member.custom_permissions.set(all_permission_ids)
            
        return staff_member


class StaffMemberListSerializer(serializers.ModelSerializer):
    """Serializer for listing staff members"""
    username = serializers.CharField(source='user.username')
    email = serializers.EmailField(source='user.email')
    first_name = serializers.CharField(source='user.first_name')
    last_name = serializers.CharField(source='user.last_name')
    full_name = serializers.SerializerMethodField()
    role_name = serializers.CharField(source='role.name')
    supervisor_name = serializers.SerializerMethodField()
    permission_count = serializers.SerializerMethodField()

    class Meta:
        model = StaffMember
        fields = [
            'id', 'username', 'email', 'first_name', 'last_name', 'full_name',
            'role_name', 'supervisor_name', 'department', 'employee_id',
            'is_active', 'permission_count', 'created_at'
        ]
        
    def get_full_name(self, obj):
        return obj.user.get_full_name() or obj.user.username
        
    def get_supervisor_name(self, obj):
        if obj.supervisor:
            return obj.supervisor.user.get_full_name() or obj.supervisor.user.username
        return None
        
    def get_permission_count(self, obj):
        """Count total permissions (role + custom)"""
        role_permissions = obj.role.permissions.count()
        custom_permissions = obj.custom_permissions.count()
        # We need to account for duplicates (permissions in both role and custom)
        role_perm_ids = set(obj.role.permissions.values_list('id', flat=True))
        custom_perm_ids = set(obj.custom_permissions.values_list('id', flat=True))
        unique_perms = len(role_perm_ids.union(custom_perm_ids))
        return unique_perms


class StaffMemberDetailSerializer(serializers.ModelSerializer):
    """Serializer for detailed staff member view"""
    username = serializers.CharField(source='user.username')
    email = serializers.EmailField(source='user.email')
    first_name = serializers.CharField(source='user.first_name')
    last_name = serializers.CharField(source='user.last_name')
    role = StaffRoleSerializer(read_only=True)
    supervisor = StaffMemberListSerializer(read_only=True)
    permissions = serializers.SerializerMethodField()

    class Meta:
        model = StaffMember
        fields = [
            'id', 'username', 'email', 'first_name', 'last_name',
            'role', 'supervisor', 'department', 'phone_number', 
            'employee_id', 'is_active', 'permissions',
            'created_at', 'updated_at'
        ]
        
    def get_permissions(self, obj):
        """Get all effective permissions grouped by module"""
        # Get role permissions
        role_permissions = obj.role.permissions.filter(is_active=True)
        # Get custom permissions
        custom_permissions = obj.custom_permissions.filter(is_active=True)
        
        # Combine and deduplicate
        all_permissions = {}
        
        for perm in list(role_permissions) + list(custom_permissions):
            if perm.module not in all_permissions:
                all_permissions[perm.module] = []
                
            # Add permission if not already in the list
            perm_data = {
                'id': perm.id,
                'name': perm.name,
                'description': perm.description,
                'source': 'role' if perm in role_permissions else 'custom'
            }
            
            # Check if permission already exists in results
            existing = next((p for p in all_permissions[perm.module] 
                          if p['id'] == perm.id), None)
                          
            if not existing:
                all_permissions[perm.module].append(perm_data)
                
        return all_permissions