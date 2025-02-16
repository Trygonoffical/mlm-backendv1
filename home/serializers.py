
from rest_framework import serializers
from django.contrib.auth import get_user_model
from .models import Testimonial , HomeSlider , Category , ProductImage , ProductFeature , Product , Position , MLMMember , Commission , WalletTransaction , Advertisement , SuccessStory , CustomerPickReview , CompanyInfo , About , HomeSection , HomeSectionType , Menu , CustomPage , KYCDocument , Blog , Address , Order , OrderItem , Wallet, WalletTransaction, WithdrawalRequest, BankDetails , Notification
from appAuth.serializers import UserSerializer
from django.db import IntegrityError
from django.db.models import Sum, Avg, Count, Min, Max
from django.db.models.functions import TruncMonth, TruncDay, TruncYear, Extract
from django.db.models import F, Q , Count
import re
from django.utils.text import slugify
from django.core.validators import RegexValidator


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

class ProductSerializer(serializers.ModelSerializer):
    images = ProductImageSerializer(many=True, read_only=True)
    features = ProductFeatureSerializer(many=True, read_only=True)
    uploaded_images = serializers.ListField(
        child=serializers.ImageField(max_length=1000000),
        write_only=True,
        required=False
    )
    # feature_list = serializers.ListField(
    #     child=serializers.DictField(),
    #     write_only=True,
    #     required=False
    # )
    feature_list = serializers.JSONField(required=False)
    slug = serializers.SlugField(read_only=True)
    categories = serializers.PrimaryKeyRelatedField(
        many=True,
        queryset=Category.objects.all(),
        required=False
    )
    category_details = CategoryDetailSerializer(source='categories', many=True, read_only=True)

    class Meta:
        model = Product
        fields = ['id', 'name', 'slug', 'description', 'regular_price', 
                 'selling_price', 'bp_value', 'gst_percentage', 'stock',
                 'is_featured', 'is_bestseller', 'is_new_arrival', 
                 'is_trending', 'is_active', 'images', 'features',
                 'uploaded_images', 'feature_list', 'categories', 'category_details']
        # read_only_fields = ['slug']  # Make sure slug is read-only
        

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
    

    def create(self, validated_data):
        uploaded_images = validated_data.pop('uploaded_images', [])
        feature_list = validated_data.pop('feature_list', [])
        categories = validated_data.pop('categories', [])

        # If feature_list is a string, parse it
        # if isinstance(feature_list, str):
        #     import json
        #     feature_list = json.loads(feature_list)


        product = Product.objects.create(**validated_data)
        
        # Add categories
        if categories:
            product.categories.set(categories)


        # Create product features
        for idx, feature_data in enumerate(feature_list, 1):
            ProductFeature.objects.create(
                product=product,
                order=idx,
                # **feature_data
                title=feature_data.get('title', ''),
                content=feature_data.get('content', '')
            )
        
        # Create product images
        for idx, image in enumerate(uploaded_images):
            ProductImage.objects.create(
                product=product,
                image=image,
                order=idx + 1,
                is_feature=idx == 0  # First image is feature image
            )
        
        return product

    def update(self, instance, validated_data):
        uploaded_images = validated_data.pop('uploaded_images', [])
        feature_list = validated_data.pop('feature_list', [])
        categories = validated_data.pop('categories', None)


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
            for idx, feature_data in enumerate(feature_list):
                ProductFeature.objects.create(
                    product=instance,
                    order=idx + 1,
                    **feature_data
                )
        
        # Add new images
        for idx, image in enumerate(uploaded_images):
            ProductImage.objects.create(
                product=instance,
                image=image,
                order=instance.images.count() + idx + 1
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
            'id', 'name', 'bp_required_min', 'bp_required_max',
            'discount_percentage', 'commission_percentage',
            'can_earn_commission', 'monthly_quota', 'level_order',
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

    class Meta:
        model = MLMMember
        fields = [
            'id', 'member_id', 
            # Write-only fields
            'username', 'password', 'email', 'phone_number', 'first_name', 'last_name',
            'position_id', 'sponsor_id',
            # Read-only fields
            'user_email', 'user_phone', 'user_first_name', 'user_last_name',
            'position_name', 'sponsor_name', 'is_active'
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
    

class MLMMemberListSerializer(serializers.ModelSerializer):
    user = UserSerializer(read_only=True)
    position = PositionSerializer(read_only=True)
    sponsor = MLMMemberBasicSerializer(read_only=True)
    monthly_earnings = serializers.SerializerMethodField()
    recent_commissions = serializers.SerializerMethodField()
    withdrawals = serializers.SerializerMethodField()
    pending_payouts = serializers.SerializerMethodField()
    bank_details = BankDetailsSerializerNew(read_only=True)
    class Meta:
        model = MLMMember
        fields = [
            'id', 'member_id', 'user', 'position', 'sponsor',
            'total_bp', 'current_month_purchase', 'is_active',
            'join_date', 'total_earnings', 'monthly_earnings',
            'recent_commissions', 'withdrawals', 'pending_payouts' ,'bank_details'
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
        withdrawals = WalletTransaction.objects.filter(
            wallet__user=obj.user,
            transaction_type='WITHDRAWAL'
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

    class Meta:
        model = Advertisement
        fields = [
            'id', 'title', 'image', 'image_url', 'link', 
            'position', 'is_active', 'created_at'
        ]
        read_only_fields = ['created_at']

    def get_image_url(self, obj):
        if obj.image:
            request = self.context.get('request')
            if request:
                return request.build_absolute_uri(obj.image.url)
        return None
    

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

    class Meta:
        model = Product
        fields = [
            'id', 'title', 'slug', 'price', 'sale_price',
            'image', 'image_url', 'is_active',
            'is_trending', 'is_featured', 'is_new_arrival', 'is_bestseller'
        ]

    def get_image_url(self, obj):
        if obj.image:
            request = self.context.get('request')
            if request:
                return request.build_absolute_uri(obj.image.url)
        return None

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
        if obj.image:
            request = self.context.get('request')
            if request:
                return request.build_absolute_uri(obj.image.url)
        return None

    def get_products(self, obj):
        products = obj.get_products()
        return ProductListSerializer(products, many=True, context=self.context).data

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
    first_name = serializers.CharField(source='first_name', required=False, allow_blank=True)
    last_name = serializers.CharField(source='last_name', required=False, allow_blank=True)

    
    class Meta:
        model = User
        fields = ['id', 'first_name', 'last_name', 'email', ]
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
    


class OrderItemSerializer(serializers.ModelSerializer):
    product = ProductSerializer()

    class Meta:
        model = OrderItem
        fields = [
            'id', 'product', 'quantity', 'price', 
            'discount_percentage', 'discount_amount',
            'gst_amount', 'final_price', 'bp_points'
        ]

class OrderSerializer(serializers.ModelSerializer):
    items = OrderItemSerializer(many=True, read_only=True)
    user = serializers.SerializerMethodField()
    class Meta:
        model = Order
        fields = [
            'id', 'order_number', 'order_date', 'status',
            'total_amount', 'discount_amount', 'final_amount',
            'shipping_address', 'billing_address', 'total_bp',
            'items' ,'user'
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
    pending_withdrawals = serializers.DecimalField(
        max_digits=10, decimal_places=2, read_only=True
    )
    total_earnings = serializers.DecimalField(
        max_digits=10, decimal_places=2, read_only=True
    )

    class Meta:
        model = Wallet
        fields = ['id', 'balance', 'pending_withdrawals', 
                 'total_earnings', 'last_updated']

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
    recipient_name = serializers.CharField(source='recipient.get_full_name', read_only=True)
    notification_type_display = serializers.CharField(source='get_notification_type_display', read_only=True)
    recipient = serializers.PrimaryKeyRelatedField(
        queryset=User.objects.filter(role='MLM_MEMBER'),
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

    def validate(self, data):
        # Validate notification type and recipient
        notification_type = data.get('notification_type')
        recipient = data.get('recipient')

        if notification_type == 'INDIVIDUAL' and not recipient:
            raise serializers.ValidationError({
                'recipient': 'Recipient is required for individual notifications'
            })
        elif notification_type == 'GENERAL' and recipient:
            data['recipient'] = None  # Clear recipient for general notifications

        return data
    

class MLMMemberRegistrationSerializer(serializers.Serializer):
    first_name = serializers.CharField(max_length=100, required=True)
    last_name = serializers.CharField(max_length=100, required=False, allow_blank=True)
    phone_number = serializers.CharField(max_length=15, required=True)
    email = serializers.EmailField(required=False, allow_blank=True)
    password = serializers.CharField(required=True, write_only=True)
    document_types = serializers.ListField(child=serializers.CharField(), required=True)
    document_number = serializers.ListField(child=serializers.CharField(), required=True)
    
    def validate_phone_number(self, value):
        if not value.isdigit():
            raise serializers.ValidationError("Phone number must contain only digits")
        if len(value) != 10:
            raise serializers.ValidationError("Phone number must be 10 digits long")
        if User.objects.filter(phone_number=value).exists():
            raise serializers.ValidationError("Phone number is already registered")
        return value

    def validate_email(self, value):
        if value and User.objects.filter(email=value).exists():
            raise serializers.ValidationError("Email is already registered")
        return value