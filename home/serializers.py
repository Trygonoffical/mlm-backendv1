
from rest_framework import serializers
from django.contrib.auth import get_user_model
from .models import Testimonial , HomeSlider , Category , ProductImage , ProductFeature , Product , Position , MLMMember , Commission , WalletTransaction , Advertisement , SuccessStory , CustomerPickReview , CompanyInfo , About , HomeSection , HomeSectionType , Menu , CustomPage
from appAuth.serializers import UserSerializer
from django.db import IntegrityError
from django.db.models import Sum, Avg, Count, Min, Max
from django.db.models.functions import TruncMonth, TruncDay, TruncYear, Extract
from django.db.models import F, Q , Count
import re
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

class MLMMemberListSerializer(serializers.ModelSerializer):
    user = UserSerializer(read_only=True)
    position = PositionSerializer(read_only=True)
    sponsor = MLMMemberBasicSerializer(read_only=True)
    monthly_earnings = serializers.SerializerMethodField()
    recent_commissions = serializers.SerializerMethodField()
    withdrawals = serializers.SerializerMethodField()
    pending_payouts = serializers.SerializerMethodField()

    class Meta:
        model = MLMMember
        fields = [
            'id', 'member_id', 'user', 'position', 'sponsor',
            'total_bp', 'current_month_purchase', 'is_active',
            'join_date', 'total_earnings', 'monthly_earnings',
            'recent_commissions', 'withdrawals', 'pending_payouts'
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