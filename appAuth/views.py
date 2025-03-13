import requests
import logging
import re
import uuid
import datetime
from rest_framework import serializers
from rest_framework import status
from rest_framework.views import APIView
from rest_framework.response import Response
from django.conf import settings
from home.models import PhoneOTP, User , HomeSlider , Category , Product , ProductImage , Position , MLMMember , Commission , WalletTransaction , Testimonial , Advertisement , SuccessStory , CustomerPickReview , CompanyInfo , About , HomeSection , HomeSectionType , Menu , CustomPage , KYCDocument , Blog , Address , Order , OrderItem ,  Wallet, WalletTransaction, WithdrawalRequest, BankDetails , Notification , Contact , Newsletter , PasswordResetRequest , CommissionActivationRequest , Shipment , PickupAddress , ShippingConfig , ShipmentStatusUpdate , ShippingAddress
from django.shortcuts import get_object_or_404
import random
from django.views.decorators.csrf import csrf_exempt
from django.utils.decorators import method_decorator
from rest_framework.permissions import AllowAny , IsAdminUser
from django.utils import timezone
from datetime import timedelta
from .serializers import UserSerializer 
from home.serializers import CategorySerializer , ProductSerializer , PositionSerializer  , MLMMemberSerializer , MLMMemberListSerializer , TestimonialSerializer , AdvertisementSerializer , SuccessStorySerializer , CustomerPickSerializer , CompanyInfoSerializer , AboutSerializer , HomeSectionSerializer , MenuSerializer , CustomPageSerializer , KYCDocumentSerializer , BlogSerializer , AddressSerializer , CustomerProfileSerializer , OrderSerializer , WithdrawalRequestSerializer , WalletTransactionSerializer , WalletSerializer , BankDetailsSerializer , BankDetailsSerializerNew , NotificationSerializer , MLMMemberRegistrationSerializer , ContactSerializer , NewsletterSerializer , CustomerDetailSerializer , CustomerListSerializer , ProductListSerializer , MLMProfileSerializer , CommissionActivationRequestSerializer ,ShipmentSerializer , PickupAddressSerializer , ShippingConfigSerializer
from rest_framework_simplejwt.tokens import RefreshToken
from django.contrib.auth import authenticate
from rest_framework.permissions import IsAuthenticated
from rest_framework_simplejwt.views import TokenRefreshView
from rest_framework_simplejwt.authentication import JWTAuthentication
from rest_framework.exceptions import AuthenticationFailed
from django.db.models import F, Q , Count
from django.db.models import Sum, Avg, Count, Min, Max
from django.db.models.functions import TruncMonth, TruncDay, TruncYear, Extract , TruncWeek
from rest_framework import viewsets , permissions
from rest_framework.parsers import MultiPartParser, FormParser
from home.serializers import HomeSliderSerializer
from rest_framework.decorators import action
from rest_framework.filters import SearchFilter, OrderingFilter
import time 
import razorpay
from django.shortcuts import get_object_or_404
from django.http import FileResponse
from utils.invoice_generator import generate_invoice_pdf
from rest_framework.decorators import api_view, permission_classes
from decimal import Decimal
from django.db import transaction
from django.core.mail import send_mail
from django.template.loader import render_to_string
from django.utils.html import strip_tags
from utils.email_utils import send_welcome_email
from utils.msg91_utils import MSG91Service 
import string
from django.core.exceptions import ValidationError
from .services import QuixGoShippingService
from home.utils import calculate_monthly_commissions
from utils.msg91_email_utils import MSG91EmailService


logger = logging.getLogger(__name__)

def send_otp_sms(phone_number, otp):
    """
    Send OTP via SMS using Trygon SMS API
    """
    try:
        base_url = "https://sms.webtextsolution.com/sms-panel/api/http/index.php"
        
        # Prepare the message with OTP
        message = f"Dear User {otp} is the OTP for your login at Trygon. In case you have not requested this, please contact us at info@trygon.in"
        
        params = {
            'username': 'TRYGON',
            'apikey': 'E705A-DFEDC',
            'apirequest': 'Text',
            'sender': 'TRYGON', 
            'mobile': phone_number,
            'message': message,
            'route': 'TRANS',
            'TemplateID': '1707162192151162124',
            'format': 'JSON'
        }
        
        # Send the request with timeout
        response = requests.get(base_url, params=params, timeout=10)
        
        # Log the response
        logger.info(f"SMS API Response for {phone_number}: {response.text}")
        # Check if request was successful
        if response.status_code == 200:
            return True, "OTP sent successfully"
        else:
            logger.error(f"SMS API Error: {response.text}")
            return False, "Failed to send OTP"
            
    except requests.Timeout:
        logger.error(f"Timeout while sending OTP to {phone_number}")
        return False, "SMS service timeout"
    except Exception as e:
        logger.error(f"Error sending OTP to {phone_number}: {str(e)}")
        return False, str(e)

@method_decorator(csrf_exempt, name='dispatch')
class GenerateOTP(APIView):
    permission_classes = [AllowAny]

    def validate_phone_number(self, phone_number):
        """Validate phone number format"""
        if not phone_number:
            return False, "Phone number is required"
        if not phone_number.isdigit():
            return False, "Phone number should contain only digits"
        if not (10 <= len(phone_number) <= 12):
            return False, "Phone number should be 10-12 digits long"
        return True, "Valid phone number"
    
    def post(self, request):
        try:
            phone_number = request.data.get('phone_number')

            # Validate phone number
            is_valid, message = self.validate_phone_number(phone_number)
            if not is_valid:
                return Response({
                    'status': False,
                    'message': message
                }, status=status.HTTP_400_BAD_REQUEST)

            try:
                # Check if user exists and is not a customer
                user = User.objects.filter(phone_number=phone_number).first()
                if user and user.role != 'CUSTOMER':
                    return Response({
                        'status': False,
                        'message': 'This number is registered as a non-customer user'
                    }, status=status.HTTP_400_BAD_REQUEST)

                # Get or create PhoneOTP object
                phone_otp, created = PhoneOTP.objects.get_or_create(
                    phone_number=phone_number,
                    defaults={'otp': '', 'count': 0}
                )

                # Check if the OTP is blocked and reset if time has passed
                if not created:
                    # Check if blocking period has expired
                    time_elapsed = timezone.now() - phone_otp.last_attempt
                    
                    # Add debug logging
                    logger.info(f"Time elapsed since last attempt: {time_elapsed}")
                    logger.info(f"Current count: {phone_otp.count}")
                    
                    # Reset if 30 minutes have passed since last attempt and count >= 5
                    if phone_otp.count >= 5 and time_elapsed >= timedelta(minutes=30):
                        logger.info("Resetting OTP attempt count")
                        phone_otp.count = 0
                        phone_otp.save()
                
                # After potential reset, check if still blocked
                if phone_otp.count >= 5:
                    minutes_left = max(0, 30 - (timezone.now() - phone_otp.last_attempt).seconds // 60)
                    return Response({
                        'status': False,
                        'message': f'Maximum OTP attempts reached. Please try again after {minutes_left} minutes.'
                    }, status=status.HTTP_400_BAD_REQUEST)

                # Generate 6-digit OTP
                otp = str(random.randint(100000, 999999))

                # Initialize MSG91 service
                msg91_service = MSG91Service(settings.MSG91_AUTH_KEY)

                # Send OTP via MSG91
                send_result = msg91_service.send_otp(phone_number, otp)

                # Check if OTP sending was successful
                if not send_result['success']:
                    return Response({
                        'status': False,
                        'message': f'Failed to send OTP: {send_result["message"]}'
                    }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

                # Update OTP in database
                phone_otp.otp = otp
                phone_otp.is_verified = False
                phone_otp.count += 1
                phone_otp.last_attempt = timezone.now()
                phone_otp.save()

                return Response({
                    'status': True,
                    'message': 'OTP sent successfully',
                    'attempts_left': max(0, 5 - phone_otp.count),
                    'otp': otp  # Remove in production
                })

            except Exception as e:
                logger.error(f"Error in GenerateOTP: {str(e)}")
                return Response({
                    'status': False,
                    'message': 'Internal server error'
                }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

        except Exception as e:
            logger.error(f"Unexpected error in GenerateOTP: {str(e)}")
            return Response({
                'status': False,
                'message': 'Unexpected error occurred'
            }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
    

@method_decorator(csrf_exempt, name='dispatch')
class VerifyOTP(APIView):
    permission_classes = [AllowAny]
    
    def post(self, request):
        phone_number = request.data.get('phone_number')
        otp = request.data.get('otp')
        
        if not phone_number or not otp:
            return Response({
                'status': False,
                'message': 'Phone number and OTP are required'
            }, status=status.HTTP_400_BAD_REQUEST)
            
        try:
            phone_otp = PhoneOTP.objects.get(
                phone_number=phone_number,
                otp=otp,
                is_verified=False
            )
            
            phone_otp.is_verified = True
            phone_otp.save()
            
            # Get or create user
            user, created = User.objects.get_or_create(
                phone_number=phone_number,
                defaults={
                    'username': f"C{phone_number}",
                    'role': 'CUSTOMER'
                }
            )
            
            
            # refresh = RefreshToken.for_user(user)
            # Serialize user data
            user_data = UserSerializer(user).data
            from rest_framework_simplejwt.tokens import RefreshToken
            # Generate tokens
            refresh = RefreshToken.for_user(user)
            
            return Response({
                'status': True,
                'message': 'OTP verified successfully',
                'token': str(refresh.access_token),
                'refresh': str(refresh),
                'user_id': user.id,
                'role': user.role,
                'userinfo': user_data
            })
            
        except PhoneOTP.DoesNotExist:
            return Response({
                'status': False,
                'message': 'Invalid OTP'
            }, status=status.HTTP_400_BAD_REQUEST)
        except Exception as e:
            logger.error(f"Error in VerifyOTP: {str(e)}")
            return Response({
                'status': False,
                'message': 'Internal server error'
            }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
        



# ---------------------- user login logics ----------------

@method_decorator(csrf_exempt, name='dispatch')
class UserLogin(APIView):
    permission_classes = [AllowAny]
    
    def post(self, request):
        username = request.data.get('username')
        password = request.data.get('password')
        print( 'data' , username)
        print( 'data password' , password)
        if not username or not password:
            return Response({
                'status': False,
                'message': 'Username and password are required'
            }, status=status.HTTP_400_BAD_REQUEST)
            
        try: 
            # Authenticate user
            user = authenticate(username=username, password=password)
            print( 'user' , user)
            if not user:
                return Response({
                    'status': False,
                    'message': 'Invalid credentials'
                }, status=status.HTTP_401_UNAUTHORIZED)
            
            # Check if user is customer (customers should use OTP login)
            if user.role == 'CUSTOMER':
                return Response({
                    'status': False,
                    'message': 'Please use phone number and OTP to login'
                }, status=status.HTTP_400_BAD_REQUEST)
            
            # Check if user is active
            if not user.is_active:
                return Response({
                    'status': False,
                    'message': 'Account is inactive. Please contact admin.'
                }, status=status.HTTP_403_FORBIDDEN)
            
            from rest_framework_simplejwt.tokens import RefreshToken
            # Generate tokens
            refresh = RefreshToken.for_user(user)
            
            # Get role specific data
            user_data = None
            if user.role == 'MLM_MEMBER':
                position = user.mlm_profile.position
                user_data = {
                    'member_id': user.mlm_profile.member_id,
                    'position': user.mlm_profile.position.name,
                    'can_earn': user.mlm_profile.position.can_earn_commission,
                    'is_active': user.mlm_profile.is_active,
                    'total_earnings': str(user.mlm_profile.total_earnings),
                    'current_month_purchase': str(user.mlm_profile.current_month_purchase),
                    'position': {
                        'name': position.name,
                        'discount_percentage': float(position.discount_percentage),
                    },
                }
            
            response_data = {
                'status': True,
                'message': 'Login successful',
                'token': str(refresh.access_token),
                'refresh': str(refresh),
                'user_id': user.id,
                'username': user.username,
                'first_name': user.first_name,
                'last_name': user.last_name,
                'phone_number': user.phone_number,
                'email': user.email,
                'role': user.role,
                'user_data': user_data
            }
            
            return Response(response_data)
            
        except Exception as e:
            print(f"Error during login: {str(e)}")
            return Response({
                'status': False,
                'message': 'Internal server error'
            }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

@method_decorator(csrf_exempt, name='dispatch')
class RefreshToken(APIView):
    permission_classes = [AllowAny]
    
    def post(self, request):
        try:
            shipping_service = QuixGoShippingService()
            # Force a new login regardless of current token status
            success = shipping_service.login()
            
            if success:
                return Response({
                    'success': True,
                    'message': 'Token refreshed successfully'
                })
            else:
                return Response({
                    'success': False,
                    'message': 'Failed to refresh token'
                }, status=status.HTTP_400_BAD_REQUEST)
        except Exception as e:
            logger.error(f"Error refreshing token: {str(e)}")
            return Response({
                'success': False,
                'message': f'Error refreshing token: {str(e)}'
            }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
    # def post(self, request):
    #     refresh_token = request.data.get('refresh')
        
    #     if not refresh_token:
    #         return Response({
    #             'status': False,
    #             'message': 'Refresh token is required'
    #         }, status=status.HTTP_400_BAD_REQUEST)
            
    #     try:
    #         refresh = RefreshToken(refresh_token)
            
    #         return Response({
    #             'status': True,
    #             'message': 'Token refreshed successfully',
    #             'token': str(refresh.access_token)
    #         })
            
    #     except Exception as e:
    #         return Response({
    #             'status': False,
    #             'message': 'Invalid refresh token'
    #         }, status=status.HTTP_401_UNAUTHORIZED)
        

# ------------------------- middelware code for frontend -----------------------

class ValidateTokenView(APIView):
    authentication_classes = [JWTAuthentication]
    permission_classes = [IsAuthenticated]

    def get(self, request):
        try:
            # Token will only reach here if valid
            return Response({
                'status': True,
                'role': request.user.role,
                'username': request.user.username,
                'email': request.user.email
            })
        except Exception as e:
            return Response({
                'status': False,
                'message': str(e)
            }, status=status.HTTP_401_UNAUTHORIZED)

class CustomTokenRefreshView(TokenRefreshView):
    def post(self, request, *args, **kwargs):
        try:
            response = super().post(request, *args, **kwargs)
            if response.status_code == 200:
                return Response({
                    'status': True,
                    'access': response.data['access']
                })
            return Response({
                'status': False,
                'message': 'Invalid refresh token'
            }, status=status.HTTP_401_UNAUTHORIZED)
        except Exception as e:
            return Response({
                'status': False,
                'message': str(e)
            }, status=status.HTTP_400_BAD_REQUEST)
        


# ------------------------- Home Slider code for frontend -----------------------

class HomeSliderViewSet(viewsets.ModelViewSet):
    queryset = HomeSlider.objects.all().order_by('order')
    serializer_class = HomeSliderSerializer
    parser_classes = (MultiPartParser, FormParser)
    authentication_classes = [JWTAuthentication]


    def get_permissions(self):
        if self.request.method == 'GET':
            return [AllowAny()]
        return [IsAdminUser()]
    
    def create(self, request, *args, **kwargs):
        print("Create method called")
        print("Request data:", request.data)
        return super().create(request, *args, **kwargs)
    
    # def destroy(self, request, *args, **kwargs):
    #     print("Delete method called")
    #     print("kwargs:", kwargs)
    #     return super().destroy(request, *args, **kwargs)
    
    def list(self, request, *args, **kwargs):
        queryset = self.get_queryset()
        if not queryset.exists():
            return Response([], status=status.HTTP_200_OK)
        serializer = self.get_serializer(queryset, many=True)
        return Response(serializer.data)
    


# ------------------------ Categories Code for frontend ------------------------
class CategoryViewSet(viewsets.ModelViewSet):
    queryset = Category.objects.all().order_by('name')
    serializer_class = CategorySerializer
    parser_classes = (MultiPartParser, FormParser)
    authentication_classes = [JWTAuthentication]
    permission_classes = [IsAdminUser]

    def get_permissions(self):
        if self.request.method == 'GET':
            return [AllowAny()]
        return [IsAdminUser()]

    def get_queryset(self):
        queryset = Category.objects.all()

        # Filter by Slug
        slug = self.request.query_params.get('slug', None)
        if slug:
            queryset = queryset.filter(slug=slug)

        return queryset
    
    def create(self, request, *args, **kwargs):
        try:
            print("Create method called")
            print("Request data:", request.data)
            
            # Create serializer with explicit data
            serializer = self.get_serializer(data={
                'name': request.data.get('name'),
                'description': request.data.get('description'),
                'image': request.data.get('image'),
                'is_active': request.data.get('is_active', True),
                'parent': request.data.get('parent')
            })
            
            if serializer.is_valid():
                # self.perform_create(serializer)
                # instance = self.perform_create(serializer)
                instance = serializer.save()
                print(f"Created category with slug: {instance.slug}")
                return Response(serializer.data, status=status.HTTP_201_CREATED)
            else:
                print("Validation errors:", serializer.errors)
                return Response(
                    {'error': serializer.errors},
                    status=status.HTTP_400_BAD_REQUEST
                )
                
        except Exception as e:
            print("Error creating category:", str(e))
            return Response(
                {'error': str(e)},
                status=status.HTTP_400_BAD_REQUEST
            )
    
    @action(detail=True, methods=['GET'])
    def products(self, request, pk=None):
        """Get all products belonging to a specific category by slug"""
        category_slug = self.request.query_params.get('slug', None)
        
        if category_slug:
            category = Category.objects.filter(slug=category_slug).first()
            if not category:
                return Response({"error": "Category not found"}, status=404)
            
            products = category.products.all()  # Fetch related products
            serializer = ProductSerializer(products, many=True)
            return Response(serializer.data)
        
        return Response({"error": "Slug is required"}, status=400)



# ------------------------ Product Code for frontend ------------------------

class ProductViewSet(viewsets.ModelViewSet):
    queryset = Product.objects.all()
    serializer_class = ProductSerializer
    lookup_field = 'slug'
    authentication_classes = [JWTAuthentication]
    permission_classes = [IsAuthenticated]

    def get_permissions(self):
        if self.request.method == 'GET':
            return [AllowAny()]
        return [IsAdminUser()]
    
    def get_queryset(self):
        queryset = Product.objects.all()

        # Filter by Slug
        slug = self.request.query_params.get('slug', None)
        if slug:
            queryset = queryset.filter(slug=slug)

        # Filter for trending products
        is_trending = self.request.query_params.get('trending', None)
        if is_trending:
            queryset = queryset.filter(is_trending=True)

        # Filter for featured products
        is_featured = self.request.query_params.get('featured', None)
        if is_featured:
            queryset = queryset.filter(is_featured=True)
        
        # Filter for bestseller products
        is_bestseller = self.request.query_params.get('bestseller', None)
        if is_bestseller:
            queryset = queryset.filter(is_bestseller=True)

        # Filter for new_arrival products
        is_new_arrival = self.request.query_params.get('new_arrival', None)
        if is_new_arrival:
            queryset = queryset.filter(is_new_arrival=True)

        return queryset

    @action(detail=True, methods=['DELETE'])
    def delete_image(self, request, slug=None):
        product = self.get_object()
        image_id = request.data.get('image_id')
        if image_id:
            image = get_object_or_404(ProductImage, id=image_id, product=product)
            image.delete()
            return Response(status=status.HTTP_204_NO_CONTENT)
        return Response(status=status.HTTP_400_BAD_REQUEST)

    @action(detail=True, methods=['POST'])
    def set_feature_image(self, request, slug=None):
        product = self.get_object()
        image_id = request.data.get('image_id')
        if image_id:
            image = get_object_or_404(ProductImage, id=image_id, product=product)
            image.is_feature = True
            image.save()
            return Response(status=status.HTTP_200_OK)
        return Response(status=status.HTTP_400_BAD_REQUEST)
    

# ------------------------ Position Code for frontend ------------------------



class PositionViewSet(viewsets.ModelViewSet):
    queryset = Position.objects.all()
    serializer_class = PositionSerializer
    authentication_classes = [JWTAuthentication]
    permission_classes = [IsAuthenticated]

    def get_permissions(self):
        if self.request.method == 'GET':
            return [AllowAny()]
        return [IsAdminUser()]

    def get_queryset(self):
        queryset = Position.objects.all()
        # Add filtering by status if requested
        is_active = self.request.query_params.get('is_active')
        if is_active is not None:
            queryset = queryset.filter(is_active=is_active.lower() == 'true')
        return queryset.order_by('level_order')

    @action(detail=True, methods=['POST'])
    def toggle_status(self, request, pk=None):
        position = self.get_object()
        position.is_active = not position.is_active
        position.save()
        return Response({'status': 'success', 'is_active': position.is_active})
    



class MLMMemberViewSet(viewsets.ModelViewSet):
    queryset = MLMMember.objects.all()
    permission_classes = [IsAuthenticated]
    lookup_field = 'member_id'

    def get_serializer_class(self):
        if self.action in ['list', 'retrieve']:  # Add 'retrieve' here
            return MLMMemberListSerializer
        return MLMMemberSerializer

    def create(self, request, *args, **kwargs):
        # Use the existing serializer
        serializer = self.get_serializer(data=request.data)
        
        # Validate the data
        serializer.is_valid(raise_exception=True)
        
        try:
            # Perform the creation
            member = serializer.save()
            
            # Send welcome email if email is provided
            if member.user.email:
                # Get the password from the request data
                password = request.data.get('password')
                
                # Find the sponsor if applicable
                sponsor = None
                if 'sponsor_id' in request.data:
                    try:
                        sponsor = MLMMember.objects.get(member_id=request.data.get('sponsor_id'))
                    except MLMMember.DoesNotExist:
                        # Log that sponsor was not found, but continue
                        logger.warning(f"Sponsor with ID {request.data.get('sponsor_id')} not found")
                
                # Send welcome email
                # send_welcome_email(
                #     member.user, 
                #     password, 
                #     sponsor
                # )
            
            # Prepare response
            headers = self.get_success_headers(serializer.data)
            return Response(serializer.data, status=status.HTTP_201_CREATED, headers=headers)
        
        except Exception as e:
            # Log the error
            logger.error(f"Error creating MLM member: {str(e)}")
            return Response(
                {'error': 'Failed to create MLM member'},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )
        
    def get_queryset(self):
        queryset = MLMMember.objects.select_related(
            'user', 
            'position', 
            'sponsor', 
            'sponsor__user'
        ).prefetch_related(
            'earned_commissions',
            'generated_commissions',
            'user__wallet__transactions'
        )
        
        # Get query parameters for filtering
        search = self.request.query_params.get('search')
        position = self.request.query_params.get('position')
        sponsor = self.request.query_params.get('sponsor')
        join_date = self.request.query_params.get('join_date')
        is_active = self.request.query_params.get('is_active')
        
        # Apply filters
        if search:
            queryset = queryset.filter(
                Q(user__first_name__icontains=search) | 
                Q(user__last_name__icontains=search) |
                Q(member_id__icontains=search) |
                Q(user__email__icontains=search) |
                Q(user__phone_number__icontains=search)
            )
        
        if position:
            queryset = queryset.filter(position_id=position)
            
        if sponsor:
            queryset = queryset.filter(sponsor__member_id=sponsor)
            
        if join_date:
            queryset = queryset.filter(join_date__date=join_date)
            
        if is_active is not None:
            queryset = queryset.filter(is_active=is_active.lower() == 'true')
        
        return queryset.all()

    def retrieve(self, request, *args, **kwargs):
        instance = self.get_object()
        serializer = self.get_serializer(instance)
        data = serializer.data

        # Add earnings data
        earnings_data = self.get_earnings_data(instance)
        data.update(earnings_data)

        return Response(data)

    def get_earnings_data(self, member):
        """Helper method to get earnings data"""
        # Get monthly earnings data
        monthly_earnings = Commission.objects.filter(
            member=member
        ).annotate(
            month=TruncMonth('date')
        ).values('month').annotate(
            amount=Sum('amount')
        ).order_by('month')

        # Get recent commissions
        commissions = Commission.objects.filter(
            member=member
        ).select_related('from_member__user').order_by('-date')[:10]

        # Get withdrawal history
        withdrawals = WalletTransaction.objects.filter(
            wallet__user=member.user,
            transaction_type='WITHDRAWAL'
        ).order_by('-created_at')

        # Calculate total earnings
        total_earnings = Commission.objects.filter(
            member=member,
            is_paid=True
        ).aggregate(total=Sum('amount'))['total'] or 0

        # Calculate pending payouts
        pending_payouts = Commission.objects.filter(
            member=member,
            is_paid=False
        ).aggregate(total=Sum('amount'))['total'] or 0

        return {
            'monthly_earnings': [
                {
                    'month': entry['month'].strftime('%b %Y'),
                    'amount': float(entry['amount'])
                }
                for entry in monthly_earnings
            ],
            'recent_commissions': [
                {
                    'date': commission.date,
                    'amount': float(commission.amount),
                    'from_member_name': commission.from_member.user.get_full_name(),
                    'is_paid': commission.is_paid
                }
                for commission in commissions
            ],
            'withdrawals': [
                {
                    'date': withdrawal.created_at,
                    'amount': float(withdrawal.amount),
                    'status': withdrawal.status
                }
                for withdrawal in withdrawals
            ],
            'total_earnings': float(total_earnings),
            'pending_payouts': float(pending_payouts)
        }
    
    @action(detail=True, methods=['post'], url_path='verify-bank')
    def verify_bank_details(self, request, member_id=None):
        """Verify MLM member's bank details"""
        if request.user.role != 'ADMIN':
            return Response(
                {"error": "Only admin can verify bank details"}, 
                status=status.HTTP_403_FORBIDDEN
            )

        try:
            member = self.get_object()
            bank_details = member.bank_details

            if not bank_details:
                return Response(
                    {"error": "Bank details not found"}, 
                    status=status.HTTP_404_NOT_FOUND
                )

            verification_status = request.data.get('status')
            if verification_status not in ['VERIFIED', 'REJECTED']:
                return Response(
                    {"error": "Invalid status. Must be VERIFIED or REJECTED"}, 
                    status=status.HTTP_400_BAD_REQUEST
                )

            bank_details.is_verified = verification_status == 'VERIFIED'
            bank_details.verification_date = timezone.now()
            bank_details.save()

            serializer = BankDetailsSerializerNew(bank_details)
            return Response(serializer.data)

        except Exception as e:
            return Response(
                {"error": str(e)},
                status=status.HTTP_400_BAD_REQUEST
            )
    
    @action(detail=True, methods=['POST'], url_path='toggle-status')
    def toggle_status(self, request, member_id=None):
        try:
            member = MLMMember.objects.select_related('user').get(member_id=member_id)
            new_status = member.toggle_status()
            
            return Response({
                'status': 'success',
                'is_active': new_status,
                'message': f'Member status {"activated" if new_status else "deactivated"} successfully'
            })
        except MLMMember.DoesNotExist:
            return Response(
                {'error': 'Member not found'}, 
                status=status.HTTP_404_NOT_FOUND
            )
        except Exception as e:
            return Response(
                {'error': str(e)}, 
                status=status.HTTP_400_BAD_REQUEST
            )
    @action(detail=True, methods=['POST'])
    def update_profile(self, request, member_id=None):
        try:
            member = self.get_object()
            user = member.user

            # Update user fields
            user.first_name = request.data.get('first_name', user.first_name)
            user.last_name = request.data.get('last_name', user.last_name)
            user.email = request.data.get('email', user.email)
            user.phone_number = request.data.get('phone_number', user.phone_number)
            user.save()

            return Response({'status': 'success'})
        except Exception as e:
            return Response(
                {'error': str(e)},
                status=status.HTTP_400_BAD_REQUEST
            )

    @action(detail=True, methods=['POST'])
    def reset_password(self, request, member_id=None):
        try:
            member = self.get_object()
            new_password = request.data.get('new_password')

            if not new_password:
                raise ValidationError('New password is required')

            member.user.set_password(new_password)
            member.user.save()

            return Response({'status': 'success'})
        except Exception as e:
            return Response(
                {'error': str(e)},
                status=status.HTTP_400_BAD_REQUEST
            )


class TestimonialViewSet(viewsets.ModelViewSet):
    queryset = Testimonial.objects.all()
    serializer_class = TestimonialSerializer
    authentication_classes = [JWTAuthentication]
    permission_classes = [IsAuthenticated]

    def get_permissions(self):
        if self.request.method == 'GET':
            return [AllowAny()]
        return [IsAdminUser()]

    def get_queryset(self):
        queryset = Testimonial.objects.all()
        if self.action == 'list':
            is_active = self.request.query_params.get('is_active')
            if is_active is not None:
                queryset = queryset.filter(is_active=is_active.lower() == 'true')
        return queryset.order_by('display_order', '-created_at')

    @action(detail=True, methods=['POST'])
    def toggle_status(self, request, pk=None):
        testimonial = self.get_object()
        testimonial.is_active = not testimonial.is_active
        testimonial.save()
        return Response({
            'status': 'success',
            'is_active': testimonial.is_active
        })

    @action(detail=True, methods=['POST'])
    def reorder(self, request, pk=None):
        testimonial = self.get_object()
        new_order = request.data.get('new_order')
        
        if new_order is None:
            return Response(
                {'error': 'New order is required'},
                status=status.HTTP_400_BAD_REQUEST
            )

        testimonial.display_order = new_order
        testimonial.save()
        return Response({'status': 'success'})
    

class AdvertisementViewSet(viewsets.ModelViewSet):
    queryset = Advertisement.objects.all()
    serializer_class = AdvertisementSerializer
    authentication_classes = [JWTAuthentication]
    permission_classes = [IsAuthenticated]

    def get_permissions(self):
        if self.request.method == 'GET':
            return [AllowAny()]
        return [IsAdminUser()]

    def get_queryset(self):
        queryset = Advertisement.objects.all()
        if self.action == 'list':
            position = self.request.query_params.get('position')
            is_active = self.request.query_params.get('is_active')
            
            if position:
                queryset = queryset.filter(position=position)
            if is_active is not None:
                queryset = queryset.filter(is_active=is_active.lower() == 'true')
                
        return queryset.order_by('-created_at')

    def create(self, request, *args, **kwargs):
        # Add debug logging
        print(f"Received request data: {request.data}")
        
        serializer = self.get_serializer(data=request.data)
        if not serializer.is_valid():
            print(f"Validation errors: {serializer.errors}")
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
            
        self.perform_create(serializer)
        headers = self.get_success_headers(serializer.data)
        return Response(serializer.data, status=status.HTTP_201_CREATED, headers=headers)

    @action(detail=True, methods=['POST'])
    def toggle_status(self, request, pk=None):
        advertisement = self.get_object()
        advertisement.is_active = not advertisement.is_active
        advertisement.save()
        return Response({
            'status': 'success',
            'is_active': advertisement.is_active
        })
    
class SuccessStoryViewSet(viewsets.ModelViewSet):
    queryset = SuccessStory.objects.all()
    serializer_class = SuccessStorySerializer
    authentication_classes = [JWTAuthentication]
    permission_classes = [IsAuthenticated]

    def get_permissions(self):
        if self.request.method == 'GET':
            return [AllowAny()]
        return [IsAdminUser()]
    
    def get_queryset(self):
        queryset = SuccessStory.objects.all()
        if self.action == 'list':
            position = self.request.query_params.get('position')
            is_active = self.request.query_params.get('is_active')
            search = self.request.query_params.get('search')
            
            if position:
                queryset = queryset.filter(position=position)
            if is_active is not None:
                queryset = queryset.filter(is_active=is_active.lower() == 'true')
            if search:
                queryset = queryset.filter(
                    Q(title__icontains=search) | 
                    Q(description__icontains=search)
                )
            
        return queryset.order_by('position', '-created_at')
    
    def perform_create(self, serializer):
        if not serializer.validated_data.get('position'):
            max_position = SuccessStory.objects.aggregate(Max('position'))
            position = (max_position['position__max'] or 0) + 1
            serializer.save(position=position)
        else:
            serializer.save()
    
    @action(detail=True, methods=['POST'])
    def toggle_status(self, request, pk=None):
        success_story = self.get_object()
        success_story.is_active = not success_story.is_active
        success_story.save()
        return Response({
            'status': 'success',
            'is_active': success_story.is_active
        })

class CustomerPickViewSet(viewsets.ModelViewSet):
    queryset = CustomerPickReview.objects.all()
    serializer_class = CustomerPickSerializer
    authentication_classes = [JWTAuthentication]
    permission_classes = [IsAuthenticated]

    def get_permissions(self):
        if self.request.method == 'GET':
            return [AllowAny()]
        return [IsAdminUser()]
    
    def get_queryset(self):
        queryset = CustomerPickReview.objects.all()
        if self.action == 'list':
            position = self.request.query_params.get('position')
            is_active = self.request.query_params.get('is_active')
            search = self.request.query_params.get('search')
            
            if position:
                queryset = queryset.filter(position=position)
            if is_active is not None:
                queryset = queryset.filter(is_active=is_active.lower() == 'true')
            if search:
                queryset = queryset.filter(
                    Q(title__icontains=search) | 
                    Q(description__icontains=search)
                )
            
        return queryset.order_by('position', '-created_at')
    
    def perform_create(self, serializer):
        if not serializer.validated_data.get('position'):
            max_position = CustomerPickReview.objects.aggregate(Max('position'))
            position = (max_position['position__max'] or 0) + 1
            serializer.save(position=position)
        else:
            serializer.save()
    
    @action(detail=True, methods=['POST'])
    def toggle_status(self, request, pk=None):
        customer_pick = self.get_object()
        customer_pick.is_active = not customer_pick.is_active
        customer_pick.save()
        return Response({
            'status': 'success',
            'is_active': customer_pick.is_active
        })
    

class CompanyInfoViewSet(viewsets.ModelViewSet):
    queryset = CompanyInfo.objects.all()
    serializer_class = CompanyInfoSerializer
    authentication_classes = [JWTAuthentication]
    permission_classes = [IsAuthenticated]

    def get_permissions(self):
        if self.request.method == 'GET':
            return [AllowAny()]
        return [IsAdminUser()]

    def get_queryset(self):
        return CompanyInfo.objects.all()

    def list(self, request, *args, **kwargs):
        company_info = CompanyInfo.get_info()
        serializer = self.get_serializer(company_info)
        return Response(serializer.data)

    def update(self, request, *args, **kwargs):
        instance = self.get_object()
        serializer = self.get_serializer(instance, data=request.data, partial=True)
        serializer.is_valid(raise_exception=True)
        self.perform_update(serializer)
        return Response(serializer.data)

    def create(self, request, *args, **kwargs):
        if CompanyInfo.objects.exists():
            return Response(
                {'detail': 'Company information already exists. Use PATCH to update.'},
                status=status.HTTP_400_BAD_REQUEST
            )
        return super().create(request, *args, **kwargs)

    def get_object(self):
        queryset = self.get_queryset()
        obj = queryset.first()
        if not obj:
            obj = CompanyInfo.get_info()
        return obj

    @action(detail=False, methods=['patch'])
    def update_logo(self, request):
        company = self.get_object()
        if 'logo' not in request.FILES:
            return Response(
                {'detail': 'No logo file provided'},
                status=status.HTTP_400_BAD_REQUEST
            )
            
        company.logo = request.FILES['logo']
        company.save()
        serializer = self.get_serializer(company)
        return Response(serializer.data)

    @action(detail=False, methods=['patch'])
    def update_background_images(self, request):
        company = self.get_object()
        if 'footer_bg_image' in request.FILES:
            company.footer_bg_image = request.FILES['footer_bg_image']
        if 'testimonial_bg_image' in request.FILES:
            company.testimonial_bg_image = request.FILES['testimonial_bg_image']
            
        company.save()
        serializer = self.get_serializer(company)
        return Response(serializer.data)
    
class AboutViewSet(viewsets.ModelViewSet):
    queryset = About.objects.all()
    serializer_class = AboutSerializer
    authentication_classes = [JWTAuthentication]
    permission_classes = [IsAuthenticated]

    def get_permissions(self):
        if self.request.method == 'GET':
            return [AllowAny()]
        return [IsAdminUser()]

    def get_queryset(self):
        queryset = About.objects.all()
        about_type = self.request.query_params.get('type', None)
        if about_type:
            queryset = queryset.filter(type=about_type)
        return queryset

    @action(detail=False, methods=['GET'])
    def home(self, request):
        """Get homepage about content"""
        try:
            about = About.objects.get(type='HOME', is_active=True)
            serializer = self.get_serializer(about)
            return Response(serializer.data)
        except About.DoesNotExist:
            return Response(
                {'detail': 'Homepage about content not found'},
                status=status.HTTP_404_NOT_FOUND
            )

    @action(detail=False, methods=['GET'])
    def main(self, request):
        """Get main about page content"""
        try:
            about = About.objects.get(type='MAIN', is_active=True)
            serializer = self.get_serializer(about)
            return Response(serializer.data)
        except About.DoesNotExist:
            return Response(
                {'detail': 'Main about content not found'},
                status=status.HTTP_404_NOT_FOUND
            )

    @action(detail=True, methods=['PATCH'])
    def toggle_status(self, request, pk=None):
        about = self.get_object()
        about.is_active = not about.is_active
        about.save()
        return Response({
            'status': 'success',
            'is_active': about.is_active
        })
    
class HomeSectionViewSet(viewsets.ModelViewSet):
    queryset = HomeSection.objects.all()
    serializer_class = HomeSectionSerializer
    authentication_classes = [JWTAuthentication]
    permission_classes = [IsAuthenticated]

    def get_permissions(self):
        if self.request.method == 'GET':
            return [AllowAny()]
        return [IsAdminUser()]

    def get_serializer_context(self):
        context = super().get_serializer_context()
        context['request'] = self.request
        return context

    def get_queryset(self):
        try:
            queryset = HomeSection.objects.all()
            
            section_type = self.request.query_params.get('section_type', None)
            if section_type:
                queryset = queryset.filter(section_type=section_type)
            return queryset.order_by('display_order')
        except Exception as e:
            logger.error(f"Error in get_queryset: {str(e)}")
            raise

        
    def create(self, request, *args, **kwargs):
        try:
            logger.info(f"Creating home section with data: {request.data}")
            serializer = self.get_serializer(data=request.data)
            
            if not serializer.is_valid():
                logger.error(f"Validation error: {serializer.errors}")
                return Response(
                    {'error': 'Validation failed', 'details': serializer.errors},
                    status=status.HTTP_400_BAD_REQUEST
                )
            
            self.perform_create(serializer)
            headers = self.get_success_headers(serializer.data)
            
            return Response(
                serializer.data, 
                status=status.HTTP_201_CREATED, 
                headers=headers
            )
        except Exception as e:
            logger.error(f"Error creating home section: {str(e)}")
            return Response(
                {'error': 'Failed to create section', 'details': str(e)},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )

    def update(self, request, *args, **kwargs):
        try:
            partial = kwargs.pop('partial', False)
            instance = self.get_object()
            serializer = self.get_serializer(
                instance, 
                data=request.data, 
                partial=partial
            )
            
            if not serializer.is_valid():
                logger.error(f"Validation error: {serializer.errors}")
                return Response(
                    {'error': 'Validation failed', 'details': serializer.errors},
                    status=status.HTTP_400_BAD_REQUEST
                )
            
            self.perform_update(serializer)
            return Response(serializer.data)
        except Exception as e:
            logger.error(f"Error updating home section: {str(e)}")
            return Response(
                {'error': 'Failed to update section', 'details': str(e)},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )
        
    def list(self, request, *args, **kwargs):
        try:
            
            queryset = self.get_queryset()
            serializer = self.get_serializer(queryset, many=True)
            return Response(serializer.data)
        except Exception as e:
            logger.error(f"Error in list view: {str(e)}")
            return Response(
                {'error': 'Internal server error'},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )

    def retrieve(self, request, *args, **kwargs):
        try:
            instance = self.get_object()
            serializer = self.get_serializer(instance)
            return Response(serializer.data)
        except Exception as e:
            logger.error(f"Error in retrieve view: {str(e)}")
            return Response(
                {'error': 'Internal server error'},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )
        
    @action(detail=True, methods=['post'])
    def toggle_status(self, request, pk=None):
        section = self.get_object()
        section.is_active = not section.is_active
        section.save()
        serializer = self.get_serializer(section)
        return Response(serializer.data)

    @action(detail=True, methods=['post'])
    def update_display_order(self, request, pk=None):
        section = self.get_object()
        new_order = request.data.get('display_order')
        
        if new_order is None:
            return Response(
                {'detail': 'display_order is required'},
                status=status.HTTP_400_BAD_REQUEST
            )

        try:
            new_order = int(new_order)
        except (TypeError, ValueError):
            return Response(
                {'detail': 'display_order must be a valid integer'},
                status=status.HTTP_400_BAD_REQUEST
            )

        section.display_order = new_order
        section.save()
        serializer = self.get_serializer(section)
        return Response(serializer.data)

    @action(detail=False, methods=['get'])
    def section_types(self, request):
        return Response({
            'types': [
                {'value': choice[0], 'label': choice[1]}
                for choice in HomeSectionType.choices
            ]
        })



class MenuViewSet(viewsets.ModelViewSet):
    queryset = Menu.objects.all()
    serializer_class = MenuSerializer
    authentication_classes = [JWTAuthentication]
    permission_classes = [IsAuthenticated]

    def get_permissions(self):
        if self.request.method == 'GET':
            return [AllowAny()]
        return [IsAdminUser()]

    def get_queryset(self):
        queryset = Menu.objects.all()
        if self.action == 'list':
            # Only show active menu items by default
            is_active = self.request.query_params.get('is_active')
            if is_active is not None:
                queryset = queryset.filter(is_active=is_active.lower() == 'true')
        return queryset.order_by('position')

    @action(detail=True, methods=['POST'])
    def toggle_status(self, request, pk=None):
        menu_item = self.get_object()
        menu_item.is_active = not menu_item.is_active
        menu_item.save()
        serializer = self.get_serializer(menu_item)
        return Response(serializer.data)

    @action(detail=True, methods=['POST'])
    def update_position(self, request, pk=None):
        menu_item = self.get_object()
        new_position = request.data.get('position')
        
        if new_position is None:
            return Response(
                {'detail': 'Position is required'},
                status=status.HTTP_400_BAD_REQUEST
            )

        try:
            new_position = int(new_position)
            if new_position < 0:
                raise ValueError
        except (TypeError, ValueError):
            return Response(
                {'detail': 'Position must be a non-negative integer'},
                status=status.HTTP_400_BAD_REQUEST
            )

        menu_item.position = new_position
        menu_item.save()
        serializer = self.get_serializer(menu_item)
        return Response(serializer.data)


class CustomPageViewSet(viewsets.ModelViewSet):
    queryset = CustomPage.objects.filter(is_active=True)
    serializer_class = CustomPageSerializer
    lookup_field = 'slug'
    authentication_classes = [JWTAuthentication]
    permission_classes = [IsAuthenticated]

    def get_permissions(self):
        if self.request.method == 'GET':
            return [AllowAny()]
        return [IsAdminUser()]

    def get_queryset(self):
        queryset = CustomPage.objects.filter(is_active=True)
        location = self.request.query_params.get('location', None)
        
        if location == 'header':
            queryset = queryset.filter(show_in_header=True)
        elif location == 'footer':
            queryset = queryset.filter(show_in_footer=True)
            
        return queryset.order_by('order', 'title')
    



class KYCDocumentViewSet(viewsets.ModelViewSet):
    serializer_class = KYCDocumentSerializer
    authentication_classes = [JWTAuthentication]
    permission_classes = [IsAuthenticated]

    def get_queryset(self):
        if self.request.user.role == 'ADMIN':
            queryset = KYCDocument.objects.all()
            
            # Apply filters
            status = self.request.query_params.get('status', None)
            document_type = self.request.query_params.get('document_type', None)
            search = self.request.query_params.get('search', None)
            
            if status:
                queryset = queryset.filter(status=status)
            if document_type:
                queryset = queryset.filter(document_type=document_type)
            if search:
                queryset = queryset.filter(
                    Q(mlm_member__user__username__icontains=search) |
                    Q(mlm_member__member_id__icontains=search) |
                    Q(document_number__icontains=search)
                )
            
            return queryset.select_related('mlm_member', 'mlm_member__user', 'verified_by')
        else:
            return KYCDocument.objects.filter(mlm_member__user=self.request.user)


    def create(self, request, *args, **kwargs):
        serializer = self.get_serializer(data=request.data, context={'request': request})
        serializer.is_valid(raise_exception=True)
        try:
            self.perform_create(serializer)
            headers = self.get_success_headers(serializer.data)
            return Response(serializer.data, status=status.HTTP_201_CREATED, headers=headers)
        except Exception as e:
            return Response(
                {"error": str(e)},
                status=status.HTTP_400_BAD_REQUEST
            )
        

    def list(self, request, *args, **kwargs):
        queryset = self.get_queryset()
        serializer = self.get_serializer(queryset, many=True)
        return Response(serializer.data)  # This ensures we return an array
    
    @action(detail=False, methods=['get', 'post', 'put'], url_path='bank-details')
    def bank_details(self, request, *args, **kwargs):
        if not hasattr(request.user, 'mlm_profile'):
            return Response(
                {"error": "Only MLM members can access bank details"}, 
                status=status.HTTP_403_FORBIDDEN
            )

        if request.method == 'GET':
            try:
                bank_details = BankDetails.objects.get(mlm_member=request.user.mlm_profile)
                serializer = BankDetailsSerializerNew(bank_details)
                return Response(serializer.data)
            except BankDetails.DoesNotExist:
                return Response(status=status.HTTP_404_NOT_FOUND)
            
        elif request.method in ['POST', 'PUT']:
            bank_details, created = BankDetails.objects.get_or_create(
                mlm_member=request.user.mlm_profile
            )
            serializer = BankDetailsSerializerNew(
                instance=bank_details,
                data=request.data,
                partial=not created  # Allow partial updates if record exists
            )
            
            if serializer.is_valid():
                serializer.save()
                return Response(serializer.data)
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

    
    
    @action(detail=True, methods=['post'])
    def verify(self, request, pk=None):
        """
        Verify or reject a KYC document
        """
        try:
            if request.user.role != 'ADMIN':
                return Response(
                    {"error": "Only admin can verify documents"}, 
                    status=status.HTTP_403_FORBIDDEN
                )
                
            document = self.get_object()
            verification_status = request.data.get('status')
            rejection_reason = request.data.get('rejection_reason', '')

            if verification_status not in ['VERIFIED', 'REJECTED']:
                return Response(
                    {"error": "Invalid status. Must be VERIFIED or REJECTED"},
                    status=status.HTTP_400_BAD_REQUEST
                )

            # Use transaction to ensure all operations succeed or fail together
            with transaction.atomic():
                # Update document status
                document.status = verification_status
                document.verified_by = request.user
                document.verification_date = timezone.now()
                
                if verification_status == 'REJECTED':
                    if not rejection_reason:
                        return Response(
                            {"error": "Rejection reason is required for rejected documents"},
                            status=status.HTTP_400_BAD_REQUEST
                        )
                    document.rejection_reason = rejection_reason
                    
                document.save()
                
                # Create notification for the member
                notification_title = "KYC Document Verified" if verification_status == 'VERIFIED' else "KYC Document Rejected"
                notification_message = f"Your {document.get_document_type_display()} has been {verification_status.lower()}."
                
                if verification_status == 'REJECTED':
                    notification_message += f" Reason: {rejection_reason}"
                    
                Notification.objects.create(
                    title=notification_title,
                    message=notification_message,
                    notification_type='INDIVIDUAL',
                    recipient=document.mlm_member
                )
                
                # If document is verified, check if all required documents are verified
                if verification_status == 'VERIFIED':
                    # Get all KYC documents for the member
                    all_docs = KYCDocument.objects.filter(mlm_member=document.mlm_member)
                    required_doc_types = ['AADHAR', 'PAN']  # Define your required document types
                    
                    # Check if all required documents are verified
                    all_verified = True
                    for doc_type in required_doc_types:
                        doc_verified = all_docs.filter(
                            document_type=doc_type, 
                            status='VERIFIED'
                        ).exists()
                        
                        if not doc_verified:
                            all_verified = False
                            break
                            
                    # If all documents are verified, send email notification
                    if all_verified:
                        logger.info(f"All required documents verified for member {document.mlm_member.member_id}")
                        
                        # Send email notification using MSG91
                        email_service = MSG91EmailService()
                        email_result = email_service.send_kyc_approved_email(document.mlm_member)
                        
                        if not email_result['success']:
                            logger.warning(f"Failed to send KYC approval email: {email_result['message']}")
                        
                        # Create special notification for complete verification
                        Notification.objects.create(
                            title="KYC Verification Complete",
                            message="All your KYC documents have been verified successfully. You can now enjoy full benefits of your membership.",
                            notification_type='INDIVIDUAL',
                            recipient=document.mlm_member
                        )
            
            # Return updated document data
            serializer = self.get_serializer(document)
            return Response(serializer.data)
            
        except Exception as e:
            logger.error(f"Error in KYC verification: {str(e)}")
            return Response(
                {"error": str(e)},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )



class BlogViewSet(viewsets.ModelViewSet):
    queryset = Blog.objects.all()
    serializer_class = BlogSerializer
    filter_backends = [SearchFilter, OrderingFilter]
    search_fields = ['title', 'content']
    ordering_fields = ['created_at', 'order', 'title']
    authentication_classes = [JWTAuthentication]
    permission_classes = [IsAuthenticated]

    def get_permissions(self):
        if self.request.method == 'GET':
            return [AllowAny()]
        return [IsAdminUser()]

    def get_queryset(self):
        queryset = Blog.objects.all()
        
        # Get query parameters
        is_active = self.request.query_params.get('is_active', None)
        show_in_slider = self.request.query_params.get('show_in_slider', None)
        search = self.request.query_params.get('search', None)

        # Print debug info
        print("Query params received:", self.request.query_params)
        print("is_active:", is_active, type(is_active))
        print("show_in_slider:", show_in_slider, type(show_in_slider))

        # Apply filters
        if is_active is not None:
            is_active = is_active.lower() == 'true'  # Convert string to boolean
            queryset = queryset.filter(is_active=is_active)

        if show_in_slider is not None:
            show_in_slider = show_in_slider.lower() == 'true'  # Convert string to boolean
            queryset = queryset.filter(show_in_slider=show_in_slider)

        if search:
            queryset = queryset.filter(
                Q(title__icontains=search) |
                Q(content__icontains=search)
            )

        # For non-admin users, only show active blogs
        if not self.request.user.is_staff:
            queryset = queryset.filter(is_active=True)

        return queryset.order_by('order', '-created_at')

    @action(detail=True, methods=['post'])
    def toggle_status(self, request, pk=None):
        blog = self.get_object()
        blog.is_active = not blog.is_active
        blog.save()
        return Response({'status': 'success', 'is_active': blog.is_active})

    @action(detail=True, methods=['post'])
    def toggle_slider(self, request, pk=None):
        blog = self.get_object()
        blog.show_in_slider = not blog.show_in_slider
        blog.save()
        return Response({'status': 'success', 'show_in_slider': blog.show_in_slider})
    



# --------------------------------------------- Payment Secton --------------------------


class CreateOrderView(APIView):
    authentication_classes = [JWTAuthentication]
    permission_classes = [IsAuthenticated] 
    def post(self, request):
        try:
            # Initialize Razorpay client
            client = razorpay.Client(
                auth=(settings.RAZORPAY_KEY_ID, settings.RAZORPAY_KEY_SECRET)
            )

            # Create Razorpay order
            data = {
                'amount': int(request.data.get('amount')) * 100,  # Amount in paise
                'currency': 'INR',
                'receipt': f'order_rcptid_{int(time.time())}',
                'payment_capture': 1  # Auto-capture payment
            }
            
            order = client.order.create(data=data)
            print('order' , order)
            print('data' , request.data)
            return Response({
                'order_id': order['id'],
                'amount': order['amount'],
                'currency': order['currency']
            })
        except Exception as e:
            return Response({
                'error': str(e)
            }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
        
# def send_order_confirmation_sms(order):
#     msg91_service = MSG91Service(settings.MSG91_AUTH_KEY)
#     message = f"Dear User, your order {order.order_number} has been confirmed. Delivery by {order.expected_delivery_date}. For details, visit https://www.yourwebsite.com/OrderTracking"
    
#     result = msg91_service.send_transactional_sms(
#         order.user.phone_number, 
#         message
#     )
    
#     if not result['success']:
#         logger.error(f"Failed to send order confirmation SMS: {result['message']}")
def send_order_confirmation_sms(order):
    try:
        msg91_service = MSG91Service(settings.MSG91_AUTH_KEY)
        
        # Use a default delivery date if not specified
        expected_delivery = getattr(order, 'expected_delivery_date', 'soon')
        
        # Ensure user and phone number exist
        if not hasattr(order, 'user') or not order.user:
            logger.error(f"No user associated with order {order.order_number}")
            return
        
        phone_number = order.user.phone_number
        if not phone_number:
            logger.error(f"No phone number for user in order {order.order_number}")
            return
        
        message = f"Dear User, your order {order.order_number} has been confirmed. Delivery by {expected_delivery}. For details, visit https://www.yourwebsite.com/OrderTracking"
        
        result = msg91_service.send_transactional_sms(
            phone_number, 
            message
        )
        
        if not result['success']:
            logger.error(f"Failed to send order confirmation SMS for order {order.order_number}: {result['message']}")
    
    except Exception as e:
        logger.error(f"Unexpected error sending order confirmation SMS: {str(e)}")
class VerifyPaymentView(APIView):
    authentication_classes = [JWTAuthentication]
    permission_classes = [IsAuthenticated]

    def post(self, request):
        try:
            # Log the incoming request data
            logger.info(f"Verify Payment Request Data: {request.data}")

            # Get payment details
            payment_id = request.data.get('razorpay_payment_id')
            order_id = request.data.get('razorpay_order_id')
            signature = request.data.get('razorpay_signature')
            update_stock = request.data.get('update_stock', False)

            # Additional logging
            logger.info(f"Payment ID: {payment_id}")
            logger.info(f"Order ID: {order_id}")

            # Get the order
            order = Order.objects.get(razorpay_order_id=order_id)

            # Initialize Razorpay client
            client = razorpay.Client(
                auth=(settings.RAZORPAY_KEY_ID, settings.RAZORPAY_KEY_SECRET)
            )

            # Verify signature
            params_dict = {
                'razorpay_payment_id': payment_id,
                'razorpay_order_id': order_id,
                'razorpay_signature': signature
            }
            
            try:
                client.utility.verify_payment_signature(params_dict)
                
                # Use a transaction to ensure consistency
                with transaction.atomic():
                    # Update order status
                    order.status = 'CONFIRMED'
                    order.payment_id = payment_id
                    order.save()

                    # Send order confirmation SMS
                    send_order_confirmation_sms(order)

                    # Process BP points and check for position upgrades
                    from home.utils import update_bp_points_on_order
                    bp_updated = update_bp_points_on_order(order)
                    
                    logger.info(f"BP update result for order {order.id}: {bp_updated}")

                    # Process first payment bonus if applicable
                    from home.utils import process_first_payment
                    first_payment_processed = process_first_payment(order)
                    if first_payment_processed:
                        logger.info(f"First payment bonus processed for order {order.id}")

                    # Update product stock if requested
                    if update_stock:
                        for item in order.items.all():
                            product = item.product
                            if product.stock >= item.quantity:
                                product.stock -= item.quantity
                                product.save()
                                logger.info(f"Updated stock for product {product.id}, new stock: {product.stock}")
                            else:
                                logger.warning(f"Insufficient stock for product {product.id}: requested {item.quantity}, available {product.stock}")
                                # We still proceed with the order even if stock is insufficient
                                # This is to avoid issues with the customer who already paid
                                product.stock = 0  # Set to zero instead of negative
                                product.save()

                return Response({
                    'status': 'success',
                    'message': 'Payment verified successfully',
                    'order_id': order.id
                })
            except Exception as e:
                order.status = 'FAILED'
                order.save()
                raise e

        except Exception as e:
            logger.error(f"Error in VerifyPaymentView: {str(e)}")
            return Response({
                'status': 'error',
                'message': str(e)
            }, status=status.HTTP_400_BAD_REQUEST)
    
        
    def send_order_confirmation_sms(self, order):
        """Send order confirmation SMS using MSG91"""
        try:
            # Check if user has phone number
            if not order.user or not order.user.phone_number:
                logger.error(f"No phone number available for order {order.order_number}")
                return
            
            # Initialize MSG91 service
            msg91_service = MSG91Service(settings.MSG91_AUTH_KEY)
            
            # Get user's phone number
            phone_number = order.user.phone_number
            
            # Calculate expected delivery date (e.g., 5 days from now)
            expected_delivery_date = (datetime.datetime.now() + datetime.timedelta(days=5)).strftime('%d-%m-%Y')
            
            # Send confirmation SMS
            send_result = msg91_service.send_order_confirmation(
                phone_number=phone_number,
                order_number=order.order_number,
                date=expected_delivery_date
            )
            
            if not send_result['success']:
                logger.error(f"Failed to send order confirmation SMS: {send_result['message']}")
                
        except Exception as e:
            logger.error(f"Error sending order confirmation SMS: {str(e)}")
       

class AddressViewSet(viewsets.ModelViewSet):
    serializer_class = AddressSerializer
    authentication_classes = [JWTAuthentication]
    permission_classes = [IsAuthenticated]

    def get_queryset(self):
        return Address.objects.filter(user=self.request.user)

    def perform_create(self, serializer):
        # If this is the user's first address, make it default
        if not Address.objects.filter(user=self.request.user).exists():
            serializer.save(user=self.request.user, is_active=True)
        else:
            serializer.save(user=self.request.user)

    @action(detail=True, methods=['POST'])
    def set_default(self, request, pk=None):
        address = self.get_object()
        # Set all other addresses to non-default
        Address.objects.filter(user=request.user).update(is_active=False)
        # Set this address as default
        address.is_active = True
        address.save()
        return Response({'status': 'default address set'})

    @action(detail=False, methods=['GET'])
    def default(self, request):
        address = Address.objects.filter(user=request.user, is_active=True).first()
        if address:
            serializer = self.get_serializer(address)
            return Response(serializer.data)
        return Response({'message': 'No default address found'}, 
                       status=status.HTTP_404_NOT_FOUND)
    



class CustomerProfileView(APIView):
    authentication_classes = [JWTAuthentication]
    permission_classes = [IsAuthenticated]
    
    def post(self, request):
        """Update customer profile"""
        if request.user.role != 'CUSTOMER':
            return Response({
                'status': 'error',
                'message': 'Only customers can access this endpoint'
            }, status=status.HTTP_403_FORBIDDEN)

        serializer = CustomerProfileSerializer(
            request.user, 
            data=request.data, 
            partial=True
        )
        
        if serializer.is_valid():
            try:
                user = serializer.save()
                return Response({
                    'status': 'success',
                    'message': 'Profile updated successfully',
                    # 'user': CustomerProfileSerializer(user).data,
                    'userinfo': serializer.data 
                })
            except Exception as e:
                return Response({
                    'status': 'error',
                    'message': str(e)
                }, status=status.HTTP_400_BAD_REQUEST)
        
        return Response({
            'status': 'error',
            'message': 'Invalid data provided',
            'errors': serializer.errors
        }, status=status.HTTP_400_BAD_REQUEST)


class MLMProfileView(APIView):
    authentication_classes = [JWTAuthentication]
    permission_classes = [IsAuthenticated]

    def get(self, request):
        """
        Retrieve current user's profile details
        """
        try:
            user = request.user
            
            # Prepare user data
            user_data = {
                'id': user.id,
                'username': user.username,
                'first_name': user.first_name,
                'last_name': user.last_name,
                'email': user.email,
                'phone_number': user.phone_number,
                'role': user.role,
            }

            # If it's an MLM member, add additional details
            if user.role == 'MLM_MEMBER':
                try:
                    mlm_profile = user.mlm_profile
                    user_data.update({
                        'member_id': mlm_profile.member_id,
                        'position': mlm_profile.position.name if mlm_profile.position else None,
                        'total_bp': mlm_profile.total_bp,
                    })
                except Exception as mlm_error:
                    logger.error(f"Error fetching MLM profile: {str(mlm_error)}")

            return Response(user_data)
        
        except Exception as e:
            logger.error(f"Error in profile details: {str(e)}")
            return Response({
                'error': 'Failed to retrieve profile details'
            }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

    def post(self, request):
        """
        Update user profile
        """
        try:
            user = request.user
            
            # Validate input
            serializer = MLMProfileSerializer(
                user, 
                data=request.data, 
                partial=True
            )
            
            if serializer.is_valid():
                user = serializer.save()
                
                return Response({
                    'status': 'success',
                    'message': 'Profile updated successfully',
                    'userinfo': serializer.data
                })
            
            return Response({
                'status': 'error',
                'message': 'Invalid data',
                'errors': serializer.errors
            }, status=status.HTTP_400_BAD_REQUEST)
        
        except Exception as e:
            logger.error(f"Error updating profile: {str(e)}")
            return Response({
                'error': 'Failed to update profile'
            }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
#---------------------------------- payment / invoice -------------------------------------_#

class OrderProcessView(APIView):
    authentication_classes = [JWTAuthentication]
    permission_classes = [IsAuthenticated]
    
    def generate_order_number(self):
        return f"ORD-{int(time.time())}"
    
    def calculate_discount(self, user, subtotal):
        """Calculate discount based on user's MLM position"""
        if user.role == 'MLM_MEMBER':
            try:
                mlm_member = user.mlm_profile
                position = mlm_member.position
                if position and position.discount_percentage > 0:
                    return (subtotal * Decimal(str(position.discount_percentage))) / 100
            except Exception as e:
                logger.error(f"Error calculating MLM discount: {str(e)}")
        return Decimal('0.00')
    
    def calculate_item_totals(self, product, quantity, discount_percentage=0):
        """Calculate totals for a single item with discount"""
        price = product.selling_price
        base_amount = price * quantity
        
        # Apply discount if any
        if discount_percentage > 0:
            discount_amount = (base_amount * Decimal(str(discount_percentage))) / 100
            base_amount = base_amount - discount_amount
            
        # Calculate GST on discounted amount
        gst_amount = (base_amount * product.gst_percentage) / 100
        total_price = base_amount + gst_amount
        bp_points = product.bp_value * quantity
        
        return {
            'base_price': price,
            'discount_percentage': discount_percentage,
            'discount_amount': (price * quantity * Decimal(str(discount_percentage))) / 100 if discount_percentage > 0 else Decimal('0.00'),
            'gst_amount': gst_amount,
            'total_price': total_price,
            'bp_points': bp_points
        }
    
    def calculate_shipping(self, subtotal):
        """Calculate shipping cost based on subtotal"""
        return Decimal('0.00') if subtotal > 0 else Decimal('0.00')
    
    def check_position_upgrade(self, mlm_member):
        """Check and upgrade position based on BP points"""
        higher_position = Position.objects.filter(
            bp_required_min__lte=mlm_member.total_bp,
            level_order__gt=mlm_member.position.level_order,
            is_active=True
        ).order_by('level_order').first()
        
        if higher_position:
            mlm_member.position = higher_position
            mlm_member.save()
            return True
        return False
    
    def post(self, request):
        try:
            # Get cart items (only need product IDs and quantities)
            cart_items = request.data.get('items', [])
            if not cart_items:
                return Response({
                    'status': 'error',
                    'message': 'Cart is empty'
                }, status=status.HTTP_400_BAD_REQUEST)
            
            # Get default address
            default_address = Address.objects.filter(
                user=request.user, 
                is_active=True
            ).first()
            
            if not default_address:
                return Response({
                    'status': 'error',
                    'message': 'No default address found'
                }, status=status.HTTP_400_BAD_REQUEST)
            
            # Get MLM discount percentage if applicable
            discount_percentage = 0
            if request.user.role == 'MLM_MEMBER':
                discount_percentage = request.user.mlm_profile.position.discount_percentage

            # Initialize totals
            subtotal = Decimal('0.00')
            total_discount = Decimal('0.00')
            total_gst = Decimal('0.00')
            total_bp_points = 0
            order_items = []

            # Calculate totals for each item
            for item in cart_items:
                try:
                    product = Product.objects.get(id=item['id'])
                    quantity = int(item['quantity'])

                    # Validate quantity
                    if quantity <= 0:
                        raise ValueError(f"Invalid quantity for product {product.name}")
                    if quantity > product.stock:
                        raise ValueError(f"Not enough stock for {product.name}")

                    # Calculate item totals with MLM discount if applicable
                    item_totals = self.calculate_item_totals(
                        product, 
                        quantity, 
                        discount_percentage
                    )
                    
                    subtotal += item_totals['base_price'] * quantity
                    total_discount += item_totals['discount_amount']
                    total_gst += item_totals['gst_amount']
                    total_bp_points += item_totals['bp_points']

                    order_items.append({
                        'product': product,
                        'quantity': quantity,
                        'price': item_totals['base_price'],
                        'discount_amount': item_totals['discount_amount'],
                        'gst_amount': item_totals['gst_amount'],
                        'total_price': item_totals['total_price'],
                        'bp_points': item_totals['bp_points']
                    })

                except Product.DoesNotExist:
                    return Response({
                        'status': 'error',
                        'message': f'Product with ID {item["id"]} not found'
                    }, status=status.HTTP_400_BAD_REQUEST)

            # Calculate shipping and final total
            shipping_cost = self.calculate_shipping(subtotal - total_discount)
            final_total = subtotal - total_discount + total_gst + shipping_cost

            # Create order
            order = Order.objects.create(
                user=request.user,
                order_number=self.generate_order_number(),
                total_amount=subtotal,
                discount_amount=total_discount,
                final_amount=final_total,
                shipping_address=f"{default_address.name}, {default_address.street_address}, {default_address.city}, {default_address.state}, {default_address.postal_code}",
                billing_address=f"{default_address.name}, {default_address.street_address}, {default_address.city}, {default_address.state}, {default_address.postal_code}",
                total_bp=total_bp_points,
                status='PENDING'
            )

            # Create shipping address record
            ShippingAddress.objects.create(
                order=order,
                name=default_address.name,
                street_address=default_address.street_address,
                city=default_address.city,
                state=default_address.state,
                postal_code=default_address.postal_code,
            )

            # Create order items
            for item in order_items:
                OrderItem.objects.create(
                    order=order,
                    product=item['product'],
                    quantity=item['quantity'],
                    price=item['price'],
                    discount_percentage=discount_percentage,
                    discount_amount=item['discount_amount'],
                    gst_amount=item['gst_amount'],
                    final_price=item['total_price'],
                    bp_points=item['bp_points']
                )

            # Update MLM member data if applicable
            # if request.user.role == 'MLM_MEMBER':
            #     mlm_member = request.user.mlm_profile
            #     mlm_member.total_bp += total_bp_points
            #     mlm_member.current_month_purchase += final_total
            #     mlm_member.save()
                
            #     # Check for position upgrade
            #     # mlm_member.check_position_upgrade()
            #     self.check_position_upgrade(mlm_member)

            # Create Razorpay order
            client = razorpay.Client(
                auth=(settings.RAZORPAY_KEY_ID, settings.RAZORPAY_KEY_SECRET)
            )

            payment_data = {
                'amount': int(final_total * 100),  # Convert to paise
                'currency': 'INR',
                'receipt': order.order_number,
                'payment_capture': 1,
                'notes': {
                    'order_id': order.id,
                    'shipping_address': order.shipping_address,
                    'is_mlm_member': str(request.user.role == 'MLM_MEMBER'),
                    'discount_applied': str(discount_percentage) + '%' if discount_percentage > 0 else 'No'
                }
            }
            
            razorpay_order = client.order.create(payment_data)
            
            # Update order with razorpay order id
            order.razorpay_order_id = razorpay_order['id']
            order.save()

            return Response({
                'status': 'success',
                'order_id': order.id,
                'razorpay_order_id': razorpay_order['id'],
                'amount': razorpay_order['amount'],
                'currency': razorpay_order['currency'],
                'order_summary': {
                    'subtotal': float(subtotal),
                    'discount': {
                        'percentage': float(discount_percentage),
                        'amount': float(total_discount)
                    },
                    'gst': float(total_gst),
                    'shipping': float(shipping_cost),
                    'total': float(final_total),
                    'bp_points': total_bp_points
                }
            })

        except ValueError as e:
            return Response({
                'status': 'error',
                'message': str(e)
            }, status=status.HTTP_400_BAD_REQUEST)
        except Exception as e:
            logger.error(f"Order processing error: {str(e)}")
            return Response({
                'status': 'error',
                'message': 'An unexpected error occurred'
            }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)


class PaymentWebhookView(APIView):
    permission_classes = [AllowAny]

    def post(self, request):
        try:
            # Verify webhook signature
            webhook_secret = settings.RAZORPAY_WEBHOOK_SECRET
            webhook_signature = request.headers.get('X-Razorpay-Signature')
            
            client = razorpay.Client(
                auth=(settings.RAZORPAY_KEY_ID, settings.RAZORPAY_KEY_SECRET)
            )

            client.utility.verify_webhook_signature(
                request.body.decode(),
                webhook_signature,
                webhook_secret
            )

            # Process payment
            payload = request.data
            payment_id = payload['payload']['payment']['entity']['id']
            order_id = payload['payload']['order']['entity']['receipt']

            order = Order.objects.get(order_number=order_id)
            
            if payload['event'] == 'payment.captured':
                order.status = 'CONFIRMED'
                order.save()

                # Generate invoice
                self.generate_invoice(order)

                # Process MLM commissions if applicable
                if order.user.role == 'MLM_MEMBER':
                    self.process_mlm_commissions(order)

            elif payload['event'] == 'payment.failed':
                order.status = 'CANCELLED'
                order.save()

            return Response({'status': 'success'})

        except Exception as e:
            return Response({
                'status': 'error',
                'message': str(e)
            }, status=status.HTTP_400_BAD_REQUEST)

    def generate_invoice(self, order):
        # Add invoice generation logic here
        pass

    def process_mlm_commissions(self, order):
        member = order.user.mlm_profile
        if member.sponsor:
            # Calculate commission based on sponsor's position
            commission_percentage = member.sponsor.position.commission_percentage
            commission_amount = (order.final_amount * commission_percentage) / 100

            Commission.objects.create(
                member=member.sponsor,
                from_member=member,
                order=order,
                amount=commission_amount,
                level=1  # Direct sponsor
            )


@api_view(['GET'])
@permission_classes([IsAuthenticated])
def download_invoice(request, order_id):
    try:
        # For admin, allow access to any order
        if request.user.role == 'ADMIN':
            order = get_object_or_404(Order, id=order_id)
        else:
            # For regular users, only allow their own orders
            order = get_object_or_404(Order, id=order_id, user=request.user)
        
        # Generate PDF
        pdf_buffer = generate_invoice_pdf(order)
        
        # Create the response
        response = FileResponse(
            pdf_buffer,
            as_attachment=True,
            filename=f'invoice-{order.order_number}.pdf',
            content_type='application/pdf'
        )
        
        return response
        
    except Exception as e:
        logger.error(f"Invoice download error for order {order_id}: {str(e)}")
        return Response({
            'status': 'error',
            'message': str(e)
        }, status=status.HTTP_400_BAD_REQUEST)


class OrderViewSet(viewsets.ReadOnlyModelViewSet):
    serializer_class = OrderSerializer
    permission_classes = [IsAuthenticated]

    def get_queryset(self):
        return Order.objects.filter(
            user=self.request.user
        ).order_by('-order_date').select_related(
            'user'
        ).prefetch_related(
            'items',
            'items__product'
        )
    


#------------------------ Wallet Section ------------------------------

class WalletViewSet(viewsets.ModelViewSet):
    serializer_class = WalletSerializer
    permission_classes = [IsAuthenticated]

    def get_queryset(self):
        return Wallet.objects.filter(user=self.request.user)

    @action(detail=False, methods=['post'])
    def withdraw(self, request):
        amount = request.data.get('amount')
        if not amount:
            return Response({'error': 'Amount is required'}, 
                          status=status.HTTP_400_BAD_REQUEST)

        try:
            amount = Decimal(amount)
        except:
            return Response({'error': 'Invalid amount'}, 
                          status=status.HTTP_400_BAD_REQUEST)

        wallet = request.user.wallet
        if amount > wallet.balance:
            return Response({'error': 'Insufficient balance'}, 
                          status=status.HTTP_400_BAD_REQUEST)

        # Create withdrawal request
        withdrawal = WithdrawalRequest.objects.create(
            wallet=wallet,
            amount=amount
        )

        return Response(WithdrawalRequestSerializer(withdrawal).data)

class WalletTransactionViewSet(viewsets.ReadOnlyModelViewSet):
    serializer_class = WalletTransactionSerializer
    permission_classes = [IsAuthenticated]

    def get_queryset(self):
        return WalletTransaction.objects.filter(wallet__user=self.request.user)

class WithdrawalRequestViewSet(viewsets.ModelViewSet):
    serializer_class = WithdrawalRequestSerializer
    permission_classes = [IsAuthenticated]

    def get_queryset(self):
        user = self.request.user
        if user.role == 'ADMIN':
            queryset = WithdrawalRequest.objects.all()
            
            # Apply filters
            status = self.request.query_params.get('status')
            search = self.request.query_params.get('search')
            date_range = self.request.query_params.get('date_range')

            if status:
                queryset = queryset.filter(status=status)
            if search:
                queryset = queryset.filter(
                    Q(wallet__user__username__icontains=search) |
                    Q(wallet__user__mlm_profile__member_id__icontains=search)
                )
            if date_range:
                if date_range == 'today':
                    queryset = queryset.filter(created_at__date=timezone.now().date())
                elif date_range == 'week':
                    queryset = queryset.filter(
                        created_at__date__gte=timezone.now().date() - timezone.timedelta(days=7)
                    )
                elif date_range == 'month':
                    queryset = queryset.filter(
                        created_at__date__gte=timezone.now().date() - timezone.timedelta(days=30)
                    )

            return queryset.order_by('-created_at')
        else:
            return WithdrawalRequest.objects.filter(wallet__user=user).order_by('-created_at')

    @action(detail=True, methods=['post'])
    def approve(self, request, pk=None):
        if request.user.role != 'ADMIN':
            return Response({'error': 'Unauthorized'}, 
                          status=status.HTTP_403_FORBIDDEN)

        withdrawal = self.get_object()
        if withdrawal.status != 'PENDING':
            return Response({'error': 'Can only approve pending withdrawals'}, 
                          status=status.HTTP_400_BAD_REQUEST)

        withdrawal.status = 'APPROVED'
        withdrawal.processed_at = timezone.now()
        withdrawal.save()

        # Create transaction record
        WalletTransaction.objects.create(
            wallet=withdrawal.wallet,
            amount=withdrawal.amount,
            transaction_type='WITHDRAWAL',
            description=f'Withdrawal request {withdrawal.id} approved',
            reference_id=str(withdrawal.id)
        )

        # Update wallet balance
        wallet = withdrawal.wallet
        wallet.balance -= withdrawal.amount
        wallet.save()

        # Create notification for user
        if hasattr(wallet.user, 'mlm_profile'):
            Notification.objects.create(
                title='Withdrawal Approved',
                message=f'Your withdrawal request for ₹{withdrawal.amount} has been approved.',
                notification_type='WITHDRAWAL',
                recipient=wallet.user.mlm_profile
            )

        return Response(WithdrawalRequestSerializer(withdrawal).data)

    @action(detail=True, methods=['post'])
    def reject(self, request, pk=None):
        if request.user.role != 'ADMIN':
            return Response({'error': 'Unauthorized'}, 
                          status=status.HTTP_403_FORBIDDEN)

        withdrawal = self.get_object()
        if withdrawal.status != 'PENDING':
            return Response({'error': 'Can only reject pending withdrawals'}, 
                          status=status.HTTP_400_BAD_REQUEST)

        reason = request.data.get('reason')
        if not reason:
            return Response({'error': 'Rejection reason is required'}, 
                          status=status.HTTP_400_BAD_REQUEST)

        withdrawal.status = 'REJECTED'
        withdrawal.rejection_reason = reason
        withdrawal.processed_at = timezone.now()
        withdrawal.save()

        # Create notification for user
        if hasattr(withdrawal.wallet.user, 'mlm_profile'):
            Notification.objects.create(
                title='Withdrawal Rejected',
                message=f'Your withdrawal request for ₹{withdrawal.amount} has been rejected. Reason: {reason}',
                notification_type='WITHDRAWAL',
                recipient=withdrawal.wallet.user.mlm_profile
            )

        return Response(WithdrawalRequestSerializer(withdrawal).data)


    def create(self, request, *args, **kwargs):
        """
        Create a new withdrawal request with date constraints
        """
        try:
            wallet = request.user.wallet
            amount = request.data.get('amount')
            
            # Validate amount
            if not amount:
                return Response(
                    {'error': 'Amount is required'}, 
                    status=status.HTTP_400_BAD_REQUEST
                )
                
            try:
                amount = Decimal(amount)
            except:
                return Response(
                    {'error': 'Invalid amount'}, 
                    status=status.HTTP_400_BAD_REQUEST
                )
                
            # Check for sufficient balance
            if amount > wallet.balance:
                return Response(
                    {'error': 'Insufficient balance'}, 
                    status=status.HTTP_400_BAD_REQUEST
                )
                
            # Check date constraints - only allow before 15th of the month
            today = timezone.now()
            if today.day > 15:
                return Response(
                    {'error': 'Withdrawal requests can only be made before the 15th of the month'}, 
                    status=status.HTTP_400_BAD_REQUEST
                )
                
            # Check for existing pending requests
            pending_requests = WithdrawalRequest.objects.filter(
                wallet=wallet,
                status='PENDING'
            ).exists()
            
            if pending_requests:
                return Response(
                    {'error': 'You already have a pending withdrawal request'}, 
                    status=status.HTTP_400_BAD_REQUEST
                )
                
            # Create withdrawal request
            withdrawal = WithdrawalRequest.objects.create(
                wallet=wallet,
                amount=amount
            )
            
            # Create notification
            if hasattr(request.user, 'mlm_profile'):
                Notification.objects.create(
                    title='Withdrawal Request Submitted',
                    message=f'Your withdrawal request for ₹{amount} has been submitted and is pending approval.',
                    notification_type='WITHDRAWAL',
                    recipient=request.user.mlm_profile
                )
                
            # Create admin notification
            Notification.objects.create(
                title='New Withdrawal Request',
                message=f'A new withdrawal request of ₹{amount} has been submitted by {request.user.username}.',
                notification_type='SYSTEM'
            )
            
            return Response(
                WithdrawalRequestSerializer(withdrawal).data,
                status=status.HTTP_201_CREATED
            )
            
        except Exception as e:
            logger.error(f"Error creating withdrawal request: {str(e)}")
            return Response(
                {'error': 'An unexpected error occurred'},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )

# ------------------ Notification -----------------------

    
class NotificationViewSet(viewsets.ModelViewSet):
    serializer_class = NotificationSerializer
    permission_classes = [IsAuthenticated]

    def get_queryset(self):
        user = self.request.user
        if user.role == 'ADMIN':
            return Notification.objects.all().order_by('-created_at')
        else:
            try:
                mlm_member = user.mlm_profile
                return Notification.objects.filter(
                    Q(recipient=mlm_member) | Q(notification_type='GENERAL', recipient__isnull=True)
                ).order_by('-created_at')
            except Exception as e:
                logger.error(f"Error getting notifications: {str(e)}")
                return Notification.objects.none()

    def create(self, request, *args, **kwargs):
        try:
            if request.user.role != 'ADMIN':
                return Response(
                    {"error": "Only admin can create notifications"},
                    status=status.HTTP_403_FORBIDDEN
                )

            # Log the incoming data
            logger.info(f"Creating notification with data: {request.data}")

            data = request.data.copy()
            recipient_id = data.get('recipient')

            # Convert user ID to MLM member instance
            if recipient_id and data.get('notification_type') == 'INDIVIDUAL':
                try:
                    mlm_member = MLMMember.objects.get(id=recipient_id)
                    data['recipient'] = mlm_member.id
                except MLMMember.DoesNotExist:
                    return Response(
                        {"error": "Selected recipient does not exist"},
                        status=status.HTTP_400_BAD_REQUEST
                    )

            serializer = self.get_serializer(data=data)
            if not serializer.is_valid():
                logger.error(f"Validation error: {serializer.errors}")
                return Response(
                    {"error": "Invalid data", "details": serializer.errors},
                    status=status.HTTP_400_BAD_REQUEST
                )

            notification = serializer.save()
            
            return Response(
                self.get_serializer(notification).data,
                status=status.HTTP_201_CREATED
            )

        except Exception as e:
            logger.error(f"Error creating notification: {str(e)}")
            return Response(
                {"error": "Failed to create notification"},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )

    @action(detail=True, methods=['POST'])
    def mark_read(self, request, pk=None):
        try:
            notification = self.get_object()
            if notification.notification_type != 'GENERAL':
                if not hasattr(request.user, 'mlm_profile') or notification.recipient != request.user.mlm_profile:
                    return Response(
                        {"error": "Cannot mark other user's notification as read"},
                        status=status.HTTP_403_FORBIDDEN
                    )

            notification.mark_as_read()
            return Response({"status": "success"})
        except Exception as e:
            logger.error(f"Error marking notification as read: {str(e)}")
            return Response(
                {"error": "Failed to mark notification as read"},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )
    @action(detail=False, methods=['GET'])
    def unread_count(self, request):
        try:
            user = request.user
            
            # If user is MLM member, get their profile
            if hasattr(user, 'mlm_profile'):
                mlm_member = user.mlm_profile
                count = Notification.objects.filter(
                    Q(recipient=mlm_member) | Q(notification_type='GENERAL', recipient__isnull=True),
                    is_read=False
                ).count()
            else:
                # For non-MLM members, only count general notifications
                count = Notification.objects.filter(
                    notification_type='GENERAL',
                    recipient__isnull=True,
                    is_read=False
                ).count()
                
            return Response({"count": count})
        except Exception as e:
            logger.error(f"Error getting unread count: {str(e)}")
            return Response(
                {"error": "Failed to get unread count"},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )
        
    @action(detail=False, methods=['POST'])
    def mark_all_read(self, request):
        try:
            user = request.user
            
            # If user is MLM member, get their profile
            if hasattr(user, 'mlm_profile'):
                mlm_member = user.mlm_profile
                notifications = Notification.objects.filter(
                    Q(recipient=mlm_member) | Q(notification_type='GENERAL', recipient__isnull=True),
                    is_read=False
                )
            else:
                # For non-MLM members, only mark general notifications
                notifications = Notification.objects.filter(
                    notification_type='GENERAL',
                    recipient__isnull=True,
                    is_read=False
                )
                
            # Update all notifications
            count = notifications.count()
            notifications.update(is_read=True, read_at=timezone.now())
            
            return Response({
                "status": "success", 
                "message": f"{count} notifications marked as read"
            })
            
        except Exception as e:
            logger.error(f"Error marking all notifications as read: {str(e)}")
            return Response(
                {"error": "Failed to mark all notifications as read"},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )

#------------------ admin / member orders ---------------

class AdminOrderListView(APIView):
    permission_classes = [IsAdminUser]
    
    def get(self, request):
        # Filtering logic
        queryset = Order.objects.all().order_by('-order_date')
        
        # Filter by status
        status = request.query_params.get('status')
        if status:
            queryset = queryset.filter(status=status)
        
        # Filter by date range
        date_range = request.query_params.get('date_range')
        if date_range == 'today':
            queryset = queryset.filter(order_date__date=timezone.now().date())
        elif date_range == 'week':
            queryset = queryset.filter(
                order_date__gte=timezone.now() - timedelta(days=7)
            )
        elif date_range == 'month':
            queryset = queryset.filter(
                order_date__gte=timezone.now() - timedelta(days=30)
            )
        
        # Search functionality
        search = request.query_params.get('search')
        if search:
            queryset = queryset.filter(
                Q(order_number__icontains=search) |
                Q(user__first_name__icontains=search) |
                Q(user__last_name__icontains=search) |
                Q(user__email__icontains=search)
            )
        
        serializer = OrderSerializer(queryset, many=True)
        return Response(serializer.data)

class UpdateOrderStatusView(APIView):
    permission_classes = [IsAdminUser]
    
    def post(self, request, order_id):
        try:
            # Get the order
            try:
                order = Order.objects.get(id=order_id)
            except Order.DoesNotExist:
                return Response(
                    {'error': 'Order not found'},
                    status=status.HTTP_404_NOT_FOUND
                )
            
            # Get the new status from request
            new_status = request.data.get('status')
            old_status = order.status


            # Validate status
            valid_statuses = [choice[0] for choice in Order.OrderStatus.choices]
            if new_status not in valid_statuses:
                return Response(
                    {'error': f'Invalid status. Must be one of: {", ".join(valid_statuses)}'},
                    status=status.HTTP_400_BAD_REQUEST
                )
            # If transitioning to CANCELLED and previously was CONFIRMED/SHIPPED/DELIVERED
            # We need to reverse BP and commissions
            if new_status == 'CANCELLED' and old_status in ['CONFIRMED', 'SHIPPED', 'DELIVERED']:
                try:
                    self.reverse_bp_and_commissions(order)
                except Exception as reverse_error:
                    logger.error(f"Error reversing BP and commissions: {reverse_error}")
                    return Response(
                        {'error': 'Failed to reverse BP and commissions for canceled order'},
                        status=status.HTTP_500_INTERNAL_SERVER_ERROR
                    )
            
            # Update status
            order.status = new_status
            
            try:
                order.save()
            except Exception as save_error:
                logger.error(f"Error saving order status: {save_error}")
                return Response(
                    {'error': 'Failed to update order status'},
                    status=status.HTTP_500_INTERNAL_SERVER_ERROR
                )
            
            # Serialize and return updated order
            serializer = OrderSerializer(order, context={'request': request})
            
            return Response({
                'message': 'Order status updated successfully',
                'order': serializer.data
            })
        
        except Exception as e:
            # Catch any unexpected errors
            logger.error(f"Unexpected error in update order status: {e}")
            return Response(
                {'error': 'An unexpected error occurred'},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )
    def reverse_bp_and_commissions(self, order):
        """
        Reverse BP points and commissions for a canceled order
        """
        with transaction.atomic():
            # 1. Reverse BP points if the user is an MLM member
            user = order.user
            if hasattr(user, 'mlm_profile'):
                mlm_member = user.mlm_profile
                # Subtract BP points that were added from this order
                if order.total_bp > 0:
                    mlm_member.total_bp = F('total_bp') - order.total_bp
                    
                    # Subtract from monthly purchase amount if needed
                    mlm_member.current_month_purchase = F('current_month_purchase') - order.final_amount
                    
                    mlm_member.save()
                    
                    # Log the BP point reversal
                    logger.info(f"Reversed {order.total_bp} BP points for member {mlm_member.member_id} due to order cancellation")
            
            # 2. Find and reverse any commissions generated from this order
            commissions = Commission.objects.filter(order=order)
            
            # For each commission record
            for commission in commissions:
                # If commission was paid, subtract from recipient's total earnings
                if commission.is_paid:
                    commission.member.total_earnings = F('total_earnings') - commission.amount
                    commission.member.save()
                    
                    # Log the commission reversal
                    logger.info(f"Reversed paid commission of {commission.amount} for member {commission.member.member_id}")
                
                # Delete or mark the commission as reversed
                # Option 1: Delete the commission record
                # commission.delete()
                
                # Option 2: Mark as reversed (preferred for audit trail)
                commission.is_reversed = True  # You'll need to add this field to your Commission model
                commission.reversed_at = timezone.now()
                commission.save()
            
            # If this was a first purchase bonus that triggered first_purchase_bonus_received
            # Check if this was the first confirmed order and reset the flag if needed
            if user.mlm_profile.first_purchase_bonus_received:
                # Check if this was the only confirmed order
                other_orders = Order.objects.filter(
                    user=user,
                    status__in=['CONFIRMED', 'SHIPPED', 'DELIVERED']
                ).exclude(id=order.id).exists()
                
                if not other_orders:
                    # This was the only confirmed order, reset the flag
                    user.mlm_profile.first_purchase_bonus_received = False
                    user.mlm_profile.save()
                    logger.info(f"Reset first_purchase_bonus_received flag for member {user.mlm_profile.member_id}")

class MLMOrderListView(APIView):
    permission_classes = [IsAuthenticated]
    
    def get(self, request):
        # Ensure only MLM members can access this
        if request.user.role != 'MLM_MEMBER':
            return Response({
                'error': 'Only MLM members can view their orders'
            }, status=status.HTTP_403_FORBIDDEN)
        
        queryset = Order.objects.filter(user=request.user).select_related(
            'user'
        ).prefetch_related(
            'items', 
            'items__product', 
            'items__product__images'
        ).order_by('-order_date')
        
        # Similar filtering logic as admin view, but restricted to user's orders
        
        serializer = OrderSerializer(queryset, many=True)
        return Response(serializer.data)
    

class MLMMemberTreeView(APIView):
    """
    API endpoint to get MLM member hierarchy tree or forest
    """
    authentication_classes = [JWTAuthentication]
    permission_classes = [IsAuthenticated]
    
    def get(self, request):
        try:
            # Check if a specific root member is requested
            root_member_id = request.query_params.get('root')
            
            if root_member_id:
                # Return tree for a specific root member
                return self.get_specific_tree(root_member_id)
            else:
                # Return the entire forest (all root members)
                return self.get_forest()
                
        except Exception as e:
            logger.error(f"Error in MLM member tree: {str(e)}")
            return Response(
                {'error': 'Failed to fetch member tree', 'details': str(e)},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )
    
    def get_specific_tree(self, root_member_id):
        """Get tree for a specific root member"""
        try:
            # Get the requested root member
            root_member = MLMMember.objects.filter(member_id=root_member_id).first()
            
            if not root_member:
                return Response(
                    {'error': f'Member with ID {root_member_id} not found'},
                    status=status.HTTP_404_NOT_FOUND
                )
            
            # Build and return the tree
            tree = self.build_member_tree(root_member)
            return Response({'tree': tree})
            
        except Exception as e:
            logger.error(f"Error in get_specific_tree: {str(e)}")
            return Response(
                {'error': 'Failed to fetch member tree', 'details': str(e)},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )
    
    def get_forest(self):
        """Get all root members and their trees"""
        try:
            # If user is MLM member, get their tree only
            if self.request.user.role == 'MLM_MEMBER':
                mlm_profile = MLMMember.objects.filter(user=self.request.user).first()
                
                if not mlm_profile:
                    return Response(
                        {'error': 'MLM profile not found for current user'},
                        status=status.HTTP_404_NOT_FOUND
                    )
                
                tree = self.build_member_tree(mlm_profile)
                return Response({'tree': tree})
            
            # For admins, get all root members (those without sponsors)
            elif self.request.user.role == 'ADMIN':
                root_members = MLMMember.objects.filter(sponsor__isnull=True)
                
                if not root_members.exists():
                    return Response(
                        {'error': 'No root members found'},
                        status=status.HTTP_404_NOT_FOUND
                    )
                
                # If there's only one root member, return it as a single tree
                if root_members.count() == 1:
                    tree = self.build_member_tree(root_members.first())
                    return Response({'tree': tree})
                
                # Otherwise, return all root members
                forest = [self.build_member_tree(member) for member in root_members]
                return Response({'forest': forest})
            
            else:
                return Response(
                    {'error': 'Unauthorized access'},
                    status=status.HTTP_403_FORBIDDEN
                )
                
        except Exception as e:
            logger.error(f"Error in get_forest: {str(e)}")
            return Response(
                {'error': 'Failed to fetch member forest', 'details': str(e)},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )
    
    def build_member_tree(self, member):
        """Build tree for a single member"""
        if not member:
            return None
            
        # Get member data
        user = member.user
        full_name = f"{user.first_name} {user.last_name}".strip() if user else "Unknown"
        
        # Get direct downline members
        direct_members = MLMMember.objects.filter(sponsor=member)
        
        # Calculate member statistics
        total_earnings = Commission.objects.filter(
            member=member, is_paid=True
        ).aggregate(Sum('amount'))['amount__sum'] or 0
        
        # Create node data
        node = {
            'id': member.id,
            'member_id': member.member_id,
            'name': full_name,
            'email': user.email if user else None,
            'phone_number': user.phone_number if user else None,
            'is_active': member.is_active,
            'position_name': member.position.name if member.position else None,
            'referral_count': direct_members.count(),
            'total_bp': member.total_bp or 0,
            'total_earnings': float(total_earnings),
        }
        
        # Add children recursively
        if direct_members.exists():
            node['children'] = [
                self.build_member_tree(child) 
                for child in direct_members
            ]
        else:
            node['children'] = []
            
        return node
class MLMMemberDetailsView(APIView):
    permission_classes = [IsAuthenticated]


    def get(self, request, member_id):
        try:
            # Determine if the user has permission to view the member
            if request.user.role == 'ADMIN':
                # Admins can view any member's details
                member = get_object_or_404(MLMMember, member_id=member_id)
            elif request.user.role == 'MLM_MEMBER':
                # MLM member can only view their direct and indirect downline
                current_member = request.user.mlm_profile
                
                # Get the target member
                member = get_object_or_404(MLMMember, member_id=member_id)
                
                # Check if the requested member is in the current member's downline
                def is_in_downline(current, target):
                    if current == target:
                        return False
                    
                    referrals = MLMMember.objects.filter(sponsor=current)
                    for referral in referrals:
                        if referral == target or is_in_downline(referral, target):
                            return True
                    return False

                # If not in downline and not the same member, deny access
                if not is_in_downline(current_member, member) and current_member != member:
                    return Response({
                        'error': 'You are not authorized to view this member\'s details'
                    }, status=status.HTTP_403_FORBIDDEN)
            else:
                return Response({
                    'error': 'Unauthorized access'
                }, status=status.HTTP_403_FORBIDDEN)

            # Detailed member information
            member_details = {
                'personal_info': {
                    'member_id': member.member_id,
                    'name': member.user.get_full_name() or member.user.username,
                    'email': member.user.email,
                    'phone_number': member.user.phone_number,
                    'date_joined': member.created_at,
                    'is_active': member.is_active
                },
                'position_details': {
                    'current_position': member.position.name if member.position else None,
                    'discount_percentage': float(member.position.discount_percentage) if member.position else None
                },
                'financial_details': {
                    'total_earnings': float(member.total_earnings),
                    'total_bp': member.total_bp,
                    'current_month_purchase': float(member.current_month_purchase)
                },
                'network_details': {
                    'direct_referrals': MLMMember.objects.filter(sponsor=member).count(),
                    'total_network_size': self.get_total_network_size(member)
                },
                'recent_commissions': self.get_recent_commissions(member)
            }

            # Add commission preview data
            commission_preview = self.get_commission_preview(member)
            member_details['financial_details']['commission_preview'] = commission_preview

            return Response(member_details)
        
        except Exception as e:
            logger.error(f"Error fetching member details: {e}")
            return Response({
                'error': 'An error occurred while fetching member details'
            }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

    def get_total_network_size(self, member):
        # Recursive function to count total network size
        def count_network(current_member):
            referrals = MLMMember.objects.filter(sponsor=current_member)
            total = referrals.count()
            for referral in referrals:
                total += count_network(referral)
            return total
        
        return count_network(member)

    def get_recent_commissions(self, member, limit=5):
        # Get recent commissions for the member
        recent_commissions = Commission.objects.filter(
            member=member
        ).order_by('-date')[:limit]

        return [
            {
                'date': commission.date,
                'amount': float(commission.amount),
                'from_member': commission.from_member.user.get_full_name() or commission.from_member.member_id
            }
            for commission in recent_commissions
        ]
        
    def get_commission_preview(self, member):
        """
        Get commission preview data for a member
        """
        try:
            # Check if position allows earning commission
            if not member.position.can_earn_commission:
                return {
                    'current_month': '₹0.00',
                    'last_month': '₹0.00',
                    'pending': '₹0.00'
                }
                
            # Get dates for current and last month
            today = timezone.now()
            first_day_current_month = today.replace(day=1, hour=0, minute=0, second=0, microsecond=0)
            last_month = (today.replace(day=1) - timezone.timedelta(days=1))
            first_day_last_month = last_month.replace(day=1, hour=0, minute=0, second=0, microsecond=0)
            
            # Get last month's earned commissions
            last_month_earned = Commission.objects.filter(
                member=member,
                is_paid=True,
                date__gte=first_day_last_month,
                date__lt=first_day_current_month
            ).aggregate(total=Sum('amount'))['total'] or Decimal('0.00')
            
            # Get pending commissions
            total_pending = Commission.objects.filter(
                member=member,
                is_paid=False
            ).aggregate(total=Sum('amount'))['total'] or Decimal('0.00')
            
            # Calculate current month estimate (simplified version)
            # For a more detailed estimate, you would use the full calculation from MLMLiveCommissionView
            downline_members = MLMMember.objects.filter(sponsor=member).select_related('position')
            current_month_estimate = Decimal('0.00')
            
            for downline in downline_members:
                # Only calculate if member's position percentage is higher
                if member.position.discount_percentage > downline.position.discount_percentage:
                    percentage_diff = member.position.discount_percentage - downline.position.discount_percentage
                    
                    # Get downline purchases this month
                    downline_purchases = Order.objects.filter(
                        user=downline.user,
                        order_date__gte=first_day_current_month,
                        status__in=['CONFIRMED', 'SHIPPED', 'DELIVERED']
                    ).aggregate(total=Sum('final_amount'))['total'] or Decimal('0.00')
                    
                    # Calculate commission
                    commission = (downline_purchases * Decimal(str(percentage_diff)) / 100)
                    current_month_estimate += commission
            
            return {
                'current_month': f'₹{current_month_estimate:.2f}',
                'last_month': f'₹{last_month_earned:.2f}',
                'pending': f'₹{total_pending:.2f}'
            }
        
        except Exception as e:
            logger.error(f"Error calculating commission preview: {str(e)}")
            return {
                'current_month': '₹0.00',
                'last_month': '₹0.00', 
                'pending': '₹0.00'
            }

    # def get(self, request, member_id):
    #     try:
    #         # Get the current logged-in user's MLM profile
    #         current_member = request.user.mlm_profile

    #         # Find the target member
    #         try:
    #             target_member = MLMMember.objects.get(member_id=member_id)
    #         except MLMMember.DoesNotExist:
    #             return Response({
    #                 'error': 'Member not found'
    #             }, status=status.HTTP_404_NOT_FOUND)

    #         # Check if the target member is in the current member's network
    #         def is_in_network(current, target):
    #             """
    #             Recursively check if target is in current's network
    #             """
    #             if current == target:
    #                 return False  # Prevent self-view
                
    #             # Get direct downline members
    #             direct_downline = MLMMember.objects.filter(sponsor=current)
                
    #             for referral in direct_downline:
    #                 if referral == target or is_in_network(referral, target):
    #                     return True
                
    #             return False

    #         # Allow access for:
    #         # 1. Admin users
    #         # 2. The member themselves
    #         # 3. Members within the same network
    #         if (request.user.role == 'ADMIN' or 
    #             current_member == target_member or 
    #             is_in_network(current_member, target_member)):
                
    #             # Prepare detailed member information
    #             member_details = {
    #                 'personal_info': {
    #                     'member_id': target_member.member_id,
    #                     'name': target_member.user.get_full_name() or target_member.user.username,
    #                     'email': target_member.user.email,
    #                     'phone_number': target_member.user.phone_number,
    #                     'date_joined': target_member.created_at,
    #                     'is_active': target_member.is_active
    #                 },
    #                 'position_details': {
    #                     'current_position': target_member.position.name if target_member.position else None,
    #                     'discount_percentage': float(target_member.position.discount_percentage) if target_member.position else None
    #                 },
    #                 'financial_details': {
    #                     'total_earnings': float(target_member.total_earnings),
    #                     'total_bp': target_member.total_bp,
    #                     'current_month_purchase': float(target_member.current_month_purchase)
    #                 },
    #                 'network_details': {
    #                     'direct_referrals': MLMMember.objects.filter(sponsor=target_member).count(),
    #                     'total_network_size': self.get_total_network_size(target_member)
    #                 },
    #                 'recent_commissions': self.get_recent_commissions(target_member)
    #             }

    #             return Response(member_details)
            
    #         else:
    #             return Response({
    #                 'error': 'You are not authorized to view this member\'s details'
    #             }, status=status.HTTP_403_FORBIDDEN)
        
    #     except Exception as e:
    #         logger.error(f"Error fetching member details: {str(e)}")
    #         return Response({
    #             'error': 'An error occurred while fetching member details'
    #         }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
    # def get(self, request, member_id):
    #     try:
    #         # Determine if the user has permission to view the member
    #         if request.user.role == 'ADMIN':
    #             # Admins can view any member's details
    #             member = get_object_or_404(MLMMember, member_id=member_id)
    #         elif request.user.role == 'MLM_MEMBER':
    #             # MLM member can only view their direct and indirect downline
    #             current_member = request.user.mlm_profile
                
    #             # Get the target member
    #             member = get_object_or_404(MLMMember, member_id=member_id)
                
    #             # Check if the requested member is in the current member's downline
    #             def is_in_downline(current, target):
    #                 if current == target:
    #                     return False
                    
    #                 referrals = MLMMember.objects.filter(sponsor=current)
    #                 for referral in referrals:
    #                     if referral == target or is_in_downline(referral, target):
    #                         return True
    #                 return False

    #             # If not in downline and not the same member, deny access
    #             if not is_in_downline(current_member, member) and current_member != member:
    #                 return Response({
    #                     'error': 'You are not authorized to view this member\'s details'
    #                 }, status=status.HTTP_403_FORBIDDEN)
    #         else:
    #             return Response({
    #                 'error': 'Unauthorized access'
    #             }, status=status.HTTP_403_FORBIDDEN)

    #         # Detailed member information
    #         member_details = {
    #             'personal_info': {
    #                 'member_id': member.member_id,
    #                 'name': member.user.get_full_name() or member.user.username,
    #                 'email': member.user.email,
    #                 'phone_number': member.user.phone_number,
    #                 'date_joined': member.created_at,
    #                 'is_active': member.is_active
    #             },
    #             'position_details': {
    #                 'current_position': member.position.name if member.position else None,
    #                 'discount_percentage': float(member.position.discount_percentage) if member.position else None
    #             },
    #             'financial_details': {
    #                 'total_earnings': float(member.total_earnings),
    #                 'total_bp': member.total_bp,
    #                 'current_month_purchase': float(member.current_month_purchase)
    #             },
    #             'network_details': {
    #                 'direct_referrals': MLMMember.objects.filter(sponsor=member).count(),
    #                 'total_network_size': self.get_total_network_size(member)
    #             },
    #             'recent_commissions': self.get_recent_commissions(member)
    #         }

    #         return Response(member_details)
        
    #     except Exception as e:
    #         logger.error(f"Error fetching member details: {e}")
    #         return Response({
    #             'error': 'An error occurred while fetching member details'
    #         }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
    # def get(self, request, member_id):
    #     try:
    #         # Determine if the user has permission to view the member
    #         if request.user.role == 'ADMIN':
    #             member = get_object_or_404(MLMMember, member_id=member_id)
    #         elif request.user.role == 'MLM_MEMBER':
    #             # MLM member can only view their direct and indirect downline
    #             current_member = request.user.mlm_profile
                
    #             # Check if the requested member is in the current member's downline
    #             def is_in_downline(current, target):
    #                 if current == target:
    #                     return False
                    
    #                 referrals = MLMMember.objects.filter(sponsor=current)
    #                 for referral in referrals:
    #                     if referral == target or is_in_downline(referral, target):
    #                         return True
    #                 return False

    #             member = get_object_or_404(MLMMember, member_id=member_id)
                
    #             if not is_in_downline(current_member, member):
    #                 return Response({
    #                     'error': 'You are not authorized to view this member\'s details'
    #                 }, status=status.HTTP_403_FORBIDDEN)
    #         else:
    #             return Response({
    #                 'error': 'Unauthorized access'
    #             }, status=status.HTTP_403_FORBIDDEN)

    #         # Detailed member information
    #         member_details = {
    #             'personal_info': {
    #                 'member_id': member.member_id,
    #                 'name': member.user.get_full_name() or member.user.username,
    #                 'email': member.user.email,
    #                 'phone_number': member.user.phone_number,
    #                 'date_joined': member.created_at,
    #                 'is_active': member.is_active
    #             },
    #             'position_details': {
    #                 'current_position': member.position.name if member.position else None,
    #                 'discount_percentage': float(member.position.discount_percentage) if member.position else None
    #             },
    #             'financial_details': {
    #                 'total_earnings': float(member.total_earnings),
    #                 'total_bp': member.total_bp,
    #                 'current_month_purchase': float(member.current_month_purchase)
    #             },
    #             'network_details': {
    #                 'direct_referrals': MLMMember.objects.filter(sponsor=member).count(),
    #                 'total_network_size': self.get_total_network_size(member)
    #             },
    #             'recent_commissions': self.get_recent_commissions(member)
    #         }

    #         return Response(member_details)

    #     except Exception as e:
    #         logger.error(f"Error fetching member details: {e}")
    #         return Response({
    #             'error': 'An error occurred while fetching member details'
    #         }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

    # def get_total_network_size(self, member):
    #     # Recursive function to count total network size
    #     def count_network(current_member):
    #         referrals = MLMMember.objects.filter(sponsor=current_member)
    #         total = referrals.count()
    #         for referral in referrals:
    #             total += count_network(referral)
    #         return total
        
    #     return count_network(member)

    # def get_recent_commissions(self, member, limit=5):
    #     # Get recent commissions for the member
    #     recent_commissions = Commission.objects.filter(
    #         member=member
    #     ).order_by('-date')[:limit]

    #     return [
    #         {
    #             'date': commission.date,
    #             'amount': float(commission.amount),
    #             'from_member': commission.from_member.user.get_full_name() or commission.from_member.member_id
    #         }
    #         for commission in recent_commissions
        # ]

class MLMReportView(APIView):
    permission_classes = [IsAdminUser]

    def get(self, request):
        # Get report type from query parameters
        report_type = request.query_params.get('type', '')
        
        # Common filtering parameters
        start_date = request.query_params.get('start_date')
        end_date = request.query_params.get('end_date')
        
        try:
            if report_type == 'level_wise':
                return self.generate_level_wise_report(start_date, end_date)
            
            elif report_type == 'joining':
                period = request.query_params.get('period', 'daily')
                return self.generate_joining_report(period, start_date, end_date)
            
            elif report_type == 'member_search':
                return self.generate_member_search_report(request.query_params)
            
            elif report_type == 'custom':
                return self.generate_custom_report(request.query_params)
            
            elif report_type == 'sales':
                return self.generate_sales_report(request.query_params)
            
            else:
                return Response({
                    'error': 'Invalid report type'
                }, status=status.HTTP_400_BAD_REQUEST)
        
        except Exception as e:
            logger.error(f"Error generating report: {e}")
            return Response({
                'error': 'Failed to generate report',
                'details': str(e)
            }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

    # Your existing methods remain unchanged
    def generate_level_wise_report(self, start_date=None, end_date=None):
        # Base queryset with optional date filtering
        queryset = MLMMember.objects.select_related('position', 'user')
        
        if start_date:
            queryset = queryset.filter(join_date__date__gte=start_date)
        if end_date:
            queryset = queryset.filter(join_date__date__lte=end_date)
        
        # Group by position and aggregate data
        level_report = queryset.values(
            'position__name'
        ).annotate(
            total_members=Count('id'),
            total_earnings=Sum('total_earnings'),
            total_bp=Sum('total_bp'),
            avg_monthly_purchase=Avg('current_month_purchase')
        ).order_by('position__level_order')
        
        return Response({
            'report_type': 'level_wise',
            'data': list(level_report)
        })

    def generate_joining_report(self, period='daily', start_date=None, end_date=None):
        # Base queryset
        queryset = MLMMember.objects.select_related('user')
        
        # Date filtering
        if start_date:
            queryset = queryset.filter(join_date__date__gte=start_date)
        if end_date:
            queryset = queryset.filter(join_date__date__lte=end_date)
        
        # Period-based grouping
        if period == 'daily':
            queryset = queryset.annotate(
                period=TruncDay('join_date')
            )
        elif period == 'weekly':
            queryset = queryset.annotate(
                period=TruncWeek('join_date')
            )
        elif period == 'monthly':
            queryset = queryset.annotate(
                period=TruncMonth('join_date')
            )
        else:
            return Response({
                'error': 'Invalid period'
            }, status=status.HTTP_400_BAD_REQUEST)
        
        # Aggregate joining data
        joining_report = queryset.values(
            'period'
        ).annotate(
            total_members=Count('id'),
            total_bp=Sum('total_bp'),
            total_earnings=Sum('total_earnings')
        ).order_by('period')
        
        return Response({
            'report_type': 'joining',
            'period': period,
            'data': list(joining_report)
        })

    def generate_member_search_report(self, params):
        # Search parameters
        name = params.get('name')
        city = params.get('city')
        state = params.get('state')
        
        # Base queryset
        queryset = MLMMember.objects.select_related('user')
        
        # Apply filters
        if name:
            queryset = queryset.filter(
                Q(user__first_name__icontains=name) | 
                Q(user__last_name__icontains=name)
            )
        
        # For city and state, you might need to adjust based on your exact model structure
        if city or state:
            # Option 1: If address is a related model
            queryset = queryset.filter(
                Q(user__address__city__icontains=city) if city else Q(),
                Q(user__address__state__icontains=state) if state else Q()
            )
        
        # Serialize member data
        report_data = [{
            'member_id': member.member_id,
            'name': member.user.get_full_name(),
            'email': member.user.email,
            'phone': member.user.phone_number,
            'position': member.position.name if member.position else None,
            'total_earnings': float(member.total_earnings),
            'total_bp': member.total_bp,
            'join_date': member.join_date,
            # Careful address handling
            'city': (member.user.address.city if hasattr(member.user, 'address') and hasattr(member.user.address, 'city') else None),
            'state': (member.user.address.state if hasattr(member.user, 'address') and hasattr(member.user.address, 'state') else None)
        } for member in queryset]
        
        return Response({
            'report_type': 'member_search',
            'total_count': len(report_data),
            'data': report_data
        })

    def generate_custom_report(self, params):
        # More flexible custom reporting
        queryset = MLMMember.objects.select_related('user', 'position')
        
        # Possible custom filters with type hints and validation
        filter_options = {
            'min_earnings': {
                'field': 'total_earnings',
                'lookup': 'gte',
                'type': float
            },
            'max_earnings': {
                'field': 'total_earnings',
                'lookup': 'lte',
                'type': float
            },
            'min_bp': {
                'field': 'total_bp',
                'lookup': 'gte',
                'type': int
            },
            'max_bp': {
                'field': 'total_bp',
                'lookup': 'lte',
                'type': int
            },
            'position': {
                'field': 'position__name',
                'lookup': 'iexact',
                'type': str
            },
            'is_active': {
                'field': 'is_active',
                'lookup': 'exact',
                'type': bool
            },
            'min_current_purchase': {
                'field': 'current_month_purchase',
                'lookup': 'gte',
                'type': float
            },
            'max_current_purchase': {
                'field': 'current_month_purchase',
                'lookup': 'lte',
                'type': float
            },
            'sponsor_member_id': {
                'field': 'sponsor__member_id',
                'lookup': 'iexact',
                'type': str
            }
        }
        
        # Dynamic filter application
        filter_kwargs = {}
        
        for param, value in params.items():
            if param in filter_options:
                try:
                    # Convert value to appropriate type
                    converted_value = filter_options[param]['type'](value)
                    
                    # Construct filter key
                    filter_key = f"{filter_options[param]['field']}__{filter_options[param]['lookup']}"
                    filter_kwargs[filter_key] = converted_value
                except (ValueError, TypeError):
                    # Skip invalid filters
                    continue
        
        # Apply filters
        queryset = queryset.filter(**filter_kwargs)
        
        # Prepare report data
        report_data = [{
            'member_id': member.member_id,
            'name': member.user.get_full_name(),
            'email': member.user.email,
            'phone': member.user.phone_number,
            'position': member.position.name if member.position else None,
            'is_active': member.is_active,
            'total_earnings': float(member.total_earnings),
            'total_bp': member.total_bp,
            'current_month_purchase': float(member.current_month_purchase),
            'sponsor_member_id': member.sponsor.member_id if member.sponsor else None,
            'join_date': member.join_date
        } for member in queryset]
        
        return Response({
            'report_type': 'custom',
            'total_count': len(report_data),
            'filter_applied': list(filter_kwargs.keys()),
            'data': report_data
        })

    def generate_sales_report(self, params):
        """Generate sales report with detailed order and revenue data"""
        # Get parameters
        start_date = params.get('start_date')
        end_date = params.get('end_date')
        period = params.get('period', 'daily')
        category = params.get('category')
        min_amount = params.get('min_amount')
        max_amount = params.get('max_amount')
        order_status = params.get('order_status')
        
        # Base queryset
        queryset = Order.objects.all()
        
        # Apply date filters
        if start_date:
            queryset = queryset.filter(order_date__date__gte=start_date)
        if end_date:
            queryset = queryset.filter(order_date__date__lte=end_date)
            
        # Apply status filter
        if order_status:
            queryset = queryset.filter(status=order_status)
            
        # Apply amount filters
        if min_amount:
            queryset = queryset.filter(final_amount__gte=min_amount)
        if max_amount:
            queryset = queryset.filter(final_amount__lte=max_amount)
            
        # Apply category filter (requires joining with OrderItem and Product)
        if category:
            queryset = queryset.filter(
                items__product__categories__id=category
            ).distinct()
        
        # Group by period
        if period == 'daily':
            queryset = queryset.annotate(
                period=TruncDay('order_date')
            )
        elif period == 'weekly':
            queryset = queryset.annotate(
                period=TruncWeek('order_date')
            )
        elif period == 'monthly':
            queryset = queryset.annotate(
                period=TruncMonth('order_date')
            )
        elif period == 'yearly':
            queryset = queryset.annotate(
                period=TruncYear('order_date')
            )
        else:
            return Response({
                'error': 'Invalid period'
            }, status=status.HTTP_400_BAD_REQUEST)
        
        # Calculate aggregates by period
        sales_report = queryset.values(
            'period'
        ).annotate(
            total_orders=Count('id'),
            total_revenue=Sum('final_amount'),
            total_bp=Sum('total_bp'),
            avg_order_value=Avg('final_amount')
        ).order_by('period')
        
        # If category filter is applied, include the category name
        if category:
            try:
                category_name = Category.objects.get(id=category).name
                for item in sales_report:
                    item['category_name'] = category_name
            except Category.DoesNotExist:
                pass
        
        # Calculate overall summary
        summary = {
            'total_revenue': queryset.aggregate(total=Sum('final_amount'))['total'] or 0,
            'total_orders': queryset.count(),
            'total_bp': queryset.aggregate(total=Sum('total_bp'))['total'] or 0,
            'avg_order_value': queryset.aggregate(avg=Avg('final_amount'))['avg'] or 0
        }
        
        # Format the periods properly
        formatted_report = []
        for item in sales_report:
            period_date = item['period']
            if period == 'daily':
                period_str = period_date.strftime('%Y-%m-%d')
            elif period == 'weekly':
                period_str = f"Week {period_date.strftime('%U')}, {period_date.year}"
            elif period == 'monthly':
                period_str = period_date.strftime('%b %Y')
            elif period == 'yearly':
                period_str = str(period_date.year)
                
            formatted_item = {
                **{k: v for k, v in item.items() if k != 'period'},
                'period': period_str
            }
            formatted_report.append(formatted_item)
            
        return Response({
            'report_type': 'sales',
            'data': formatted_report,
            'summary': summary
        })


class MLMDashboardView(APIView):
    permission_classes = [IsAuthenticated]

    def get(self, request):
        try:
            # Ensure the user is an MLM member
            if request.user.role != 'MLM_MEMBER':
                return Response({
                    'status': False,
                    'message': 'Only MLM members can access this dashboard'
                }, status=status.HTTP_403_FORBIDDEN)
                
            # Get the MLM member profile
            member = request.user.mlm_profile
            
            # Get verification status information
            kyc_verification_status = self.get_kyc_verification_status(member)
            bank_verification_status = self.get_bank_verification_status(member)
            
            # Get monthly quota status
            monthly_quota_status, monthly_quota_remaining = self.get_monthly_quota_status(member)
            
            # Calculate metrics
            total_income = float(member.total_earnings)
            
            # Get current month's earnings
            current_month = timezone.now().replace(day=1, hour=0, minute=0, second=0, microsecond=0)
            current_month_income = float(Commission.objects.filter(
                member=member,
                date__gte=current_month,
                is_paid=True
            ).aggregate(Sum('amount'))['amount__sum'] or 0)
            
            # Calculate network size
            total_team_members = self.get_total_network_size(member)
            
            # Get self income, team income, and bonus income
            self_income = float(member.current_month_purchase or 0)
            team_income = float(Commission.objects.filter(
                member=member,
                from_member__isnull=False,
                is_first_purchase_bonus=False
            ).aggregate(Sum('amount'))['amount__sum'] or 0)
            bonus_income = float(Commission.objects.filter(
                member=member,
                is_first_purchase_bonus=True
            ).aggregate(Sum('amount'))['amount__sum'] or 0)
            
            # Get monthly performance data
            monthly_performance = self.get_monthly_performance(member)
            
            # Get featured products
            featured_products = self.get_featured_products()
            
            # Get recent purchases (last 3)
            recent_purchases = self.get_recent_purchases(member)
            
            # Get recent orders
            recent_orders = self.get_recent_orders(member)
            
            # Total team commission
            total_team_commission = team_income + bonus_income
            
            # Current rank and target
            current_rank = member.position.name
            current_rank_level = member.position.level_order
            
            # Find next rank
            try:
                next_rank = Position.objects.filter(
                    level_order__gt=current_rank_level,
                    is_active=True
                ).order_by('level_order').first()
                
                rank_target = float(next_rank.monthly_quota) if next_rank else 0
            except Exception as e:
                logger.error(f"Error getting next rank: {str(e)}")
                rank_target = 0
            
            response_data = {
                'total_income': total_income,
                'current_month_income': current_month_income,
                'total_team_members': total_team_members,
                'self_income': self_income,
                'team_income': team_income,
                'bonus_income': bonus_income,
                'current_rank': current_rank,
                'current_rank_level': current_rank_level,
                'rank_target': rank_target,
                'total_bp': member.total_bp,
                'monthly_performance': monthly_performance,
                'featured_products': featured_products,
                'recent_purchases': recent_purchases,
                'recent_orders': recent_orders,
                'total_team_commission': total_team_commission,
                
                # Verification statuses
                'kyc_status': kyc_verification_status,
                'bank_verification_status': bank_verification_status,
                'monthly_quota_status': monthly_quota_status,
                'monthly_quota_remaining': monthly_quota_remaining
            }
            
            return Response(response_data)
            
        except Exception as e:
            logger.error(f"Error in MLM dashboard: {str(e)}")
            return Response({
                'status': False,
                'message': 'Failed to load dashboard data',
                'error': str(e)
            }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

    def get_kyc_verification_status(self, member):
        """
        Check if all required KYC documents are verified
        """
        try:
            # Get all KYC documents
            kyc_docs = KYCDocument.objects.filter(mlm_member=member)
            
            # If no documents, return pending
            if not kyc_docs.exists():
                return "PENDING"
                
            # Get required document types
            required_doc_types = ['AADHAR', 'PAN']
            
            # Check if all required documents are verified
            for doc_type in required_doc_types:
                try:
                    doc = kyc_docs.get(document_type=doc_type)
                    if doc.status == 'REJECTED':
                        return "REJECTED"
                    elif doc.status != 'VERIFIED':
                        return "PENDING"
                except KYCDocument.DoesNotExist:
                    return "PENDING"
            
            # If all checks pass, return verified
            return "VERIFIED"
            
        except Exception as e:
            logger.error(f"Error checking KYC status: {str(e)}")
            return "PENDING"
    
    def get_bank_verification_status(self, member):
        """
        Check if bank details are verified
        """
        try:
            # Check if bank details exist
            try:
                bank_details = BankDetails.objects.get(mlm_member=member)
                return "VERIFIED" if bank_details.is_verified else "PENDING"
            except BankDetails.DoesNotExist:
                return "PENDING"
        except Exception as e:
            logger.error(f"Error checking bank verification status: {str(e)}")
            return "PENDING"
    
    def get_monthly_quota_status(self, member):
        """
        Check monthly quota status
        """
        try:
            # Get position
            position = member.position
            
            # Get current month purchases
            current_month_purchase = float(member.current_month_purchase or 0)
            
            # Get required monthly quota
            monthly_quota = float(position.monthly_quota)
            
            # Calculate remaining amount
            remaining = max(0, monthly_quota - current_month_purchase)
            
            # Determine status
            if current_month_purchase >= monthly_quota:
                return "COMPLETED", 0
            else:
                return "PENDING", remaining
                
        except Exception as e:
            logger.error(f"Error checking monthly quota: {str(e)}")
            return "PENDING", 0
    
    def get_total_network_size(self, member):
        """
        Calculate total network size recursively
        """
        try:
            def count_network(current_member):
                # Count direct downline
                direct_downline = MLMMember.objects.filter(sponsor=current_member)
                count = direct_downline.count()
                
                # Count indirect downline recursively
                for downline in direct_downline:
                    count += count_network(downline)
                
                return count
            
            return count_network(member)
            
        except Exception as e:
            logger.error(f"Error calculating network size: {str(e)}")
            return 0
    
    def get_monthly_performance(self, member):
        """
        Get monthly performance data for the past 6 months
        """
        try:
            # Get current date
            now = timezone.now()
            
            # Calculate the past 6 months
            performance_data = []
            
            for i in range(5, -1, -1):
                month_start = (now - timedelta(days=30*i)).replace(day=1, hour=0, minute=0, second=0, microsecond=0)
                next_month = (month_start + timedelta(days=32)).replace(day=1)
                
                # Get total purchases for this month
                monthly_purchase = Order.objects.filter(
                    user=member.user,
                    order_date__gte=month_start,
                    order_date__lt=next_month,
                    status__in=['CONFIRMED', 'SHIPPED', 'DELIVERED']
                ).aggregate(total=Sum('final_amount'))['total'] or 0
                
                performance_data.append({
                    'month': month_start.strftime('%b'),
                    'performance': float(monthly_purchase)
                })
            
            return performance_data
            
        except Exception as e:
            logger.error(f"Error calculating monthly performance: {str(e)}")
            return []
    
    def get_featured_products(self):
        """
        Get featured products
        """
        try:
            featured_products = Product.objects.filter(
                is_featured=True,
                is_active=True
            )[:4]
            
            return [{
                'id': product.id,
                'name': product.name,
                'slug': product.slug,
                'price': float(product.selling_price),
                'image': product.get_feature_image_url(self.request)
            } for product in featured_products]
            
        except Exception as e:
            logger.error(f"Error getting featured products: {str(e)}")
            return []
    
    def get_recent_purchases(self, member):
        """
        Get user's recent purchases (last 3)
        """
        try:
            # Get recent orders first
            recent_orders = Order.objects.filter(
                user=member.user,
                status__in=['CONFIRMED', 'SHIPPED', 'DELIVERED']
            ).order_by('-order_date')[:3]
            
            # Extract purchased products
            recent_products = []
            
            for order in recent_orders:
                # Get order items
                items = OrderItem.objects.filter(order=order).select_related('product')
                
                for item in items:
                    product = item.product
                    
                    if product and product.id:
                        recent_products.append({
                            'id': product.id,
                            'name': product.name,
                            'slug': product.slug,
                            'price': float(item.final_price),
                            'image': product.get_feature_image_url(self.request),
                            'purchase_date': order.order_date.isoformat(),
                            'quantity': item.quantity
                        })
            
            # Return the last 3 unique products
            unique_products = []
            product_ids = set()
            
            for product in recent_products:
                if product['id'] not in product_ids:
                    product_ids.add(product['id'])
                    unique_products.append(product)
                    
                    if len(unique_products) >= 3:
                        break
            
            return unique_products
            
        except Exception as e:
            logger.error(f"Error getting recent purchases: {str(e)}")
            return []
    
    def get_recent_orders(self, member):
        """
        Get user's recent orders (last 5)
        """
        try:
            recent_orders = Order.objects.filter(
                user=member.user
            ).order_by('-order_date')[:5]
            
            return [{
                'id': order.id,
                'order_number': order.order_number,
                'order_date': order.order_date.isoformat(),
                'status': order.status,
                'total_amount': float(order.final_amount)
            } for order in recent_orders]
            
        except Exception as e:
            logger.error(f"Error getting recent orders: {str(e)}")
            return []
    



class AdminDashboardView(APIView):
    permission_classes = [IsAdminUser]

    def get(self, request):
        try:
            # Prepare dashboard data
            dashboard_data = {
                # Financial Metrics
                'total_revenue': self.safe_calculate_total_revenue(),
                
                # MLM Member Metrics
                'total_mlm_members': self.safe_get_total_mlm_members(),
                
                # Order Metrics
                'total_orders': self.safe_get_total_orders(),
                
                # Position Metrics
                'active_positions': self.safe_get_active_positions(),
                
                # Time-based Analysis
                'monthly_revenue': self.safe_get_monthly_revenue(),
                
                # Member Distribution
                'member_distribution': self.safe_get_member_distribution(),
                
                # Sales Analysis
                'sales_by_category': self.safe_get_sales_by_category(),
                
                # Critical Alerts
                'critical_alerts': self.safe_get_critical_alerts(),
                
                # Recent Activities
                'recent_activities': self.safe_get_recent_activities()
            }

            return Response(dashboard_data)

        except Exception as e:
            logger.error(f"Admin dashboard error: {str(e)}", exc_info=True)
            return Response({
                'error': 'Failed to load dashboard',
                'details': str(e)
            }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

    def safe_calculate_total_revenue(self):
        try:
            from home.models import Order  # Adjust import based on your project structure
            total_revenue = Order.objects.filter(
                status__in=['CONFIRMED', 'SHIPPED', 'DELIVERED']
            ).aggregate(total=Sum('final_amount'))['total'] or Decimal('0.00')
            
            return float(total_revenue)
        except Exception as e:
            logger.error(f"Error calculating total revenue: {str(e)}")
            return 0.00

    def safe_get_total_mlm_members(self):
        try:
            from home.models import MLMMember
            return MLMMember.objects.filter(is_active=True).count()
        except Exception as e:
            logger.error(f"Error getting total MLM members: {str(e)}")
            return 0

    def safe_get_total_orders(self):
        try:
            from home.models import Order
            return Order.objects.filter(
                status__in=['CONFIRMED', 'SHIPPED', 'DELIVERED']
            ).count()
        except Exception as e:
            logger.error(f"Error getting total orders: {str(e)}")
            return 0

    def safe_get_active_positions(self):
        try:
            from home.models import Position
            return Position.objects.filter(is_active=True).count()
        except Exception as e:
            logger.error(f"Error getting active positions: {str(e)}")
            return 0

    def safe_get_monthly_revenue(self):
        try:
            from home.models import Order
            current_year = timezone.now().year
            monthly_revenue = []

            for month in range(1, 13):
                start_date = timezone.datetime(current_year, month, 1)
                end_date = (start_date + timezone.timedelta(days=32)).replace(day=1) - timezone.timedelta(days=1)

                monthly_total = Order.objects.filter(
                    order_date__range=[start_date, end_date],
                    status__in=['CONFIRMED', 'SHIPPED', 'DELIVERED']
                ).aggregate(total=Sum('final_amount'))['total'] or Decimal('0.00')

                monthly_revenue.append({
                    'month': start_date.strftime('%b'),
                    'revenue': float(monthly_total)
                })

            return monthly_revenue
        except Exception as e:
            logger.error(f"Error getting monthly revenue: {str(e)}")
            return []

    def safe_get_member_distribution(self):
        try:
            from home.models import Position, MLMMember
            distribution = Position.objects.annotate(
                member_count=Count('mlmmember', filter=Q(mlmmember__is_active=True))
            ).values('name', 'member_count')

            return [
                {
                    'name': item['name'],
                    'value': item['member_count']
                }
                for item in distribution if item['member_count'] > 0
            ]
        except Exception as e:
            logger.error(f"Error getting member distribution: {str(e)}")
            return []

    def safe_get_sales_by_category(self):
        try:
            from home.models import Category, OrderItem, Order
            category_sales = Category.objects.annotate(
                total_sales=Sum('products__orderitem__final_price', 
                    filter=Q(products__orderitem__order__status__in=['CONFIRMED', 'SHIPPED', 'DELIVERED']))
            ).values('name', 'total_sales')

            return [
                {
                    'category': item['name'],
                    'sales': float(item['total_sales'] or 0)
                }
                for item in category_sales if item['total_sales']
            ]
        except Exception as e:
            logger.error(f"Error getting sales by category: {str(e)}")
            return []

    def safe_get_critical_alerts(self):
        try:
            from home.models import Product, WithdrawalRequest, KYCDocument, MLMMember
            alerts = []
            
            # Check for pending password reset requests
            pending_resets = PasswordResetRequest.objects.filter(
                status='PENDING'
            ).select_related('user').count()

            if pending_resets > 0:
                alerts.append({
                    'title': 'Pending Password Reset Requests',
                    'description': f'{pending_resets} password reset requests awaiting approval',
                    'severity': 'high',
                    'type': 'password_reset'
                })
                
            # Low Stock Products Alert
            low_stock_products = Product.objects.filter(
                stock__lt=F('low_stock_threshold')
            ) if hasattr(Product, 'low_stock_threshold') else Product.objects.none()
            
            if low_stock_products.exists():
                alerts.append({
                    'title': 'Low Stock Alert',
                    'description': f'{low_stock_products.count()} products below low stock threshold',
                    'severity': 'high'
                })

            # Pending Withdrawals Alert
            pending_withdrawals = WithdrawalRequest.objects.filter(status='PENDING')
            if pending_withdrawals.exists():
                alerts.append({
                    'title': 'Pending Withdrawals',
                    'description': f'{pending_withdrawals.count()} withdrawal requests pending',
                    'severity': 'medium'
                })

            # Unverified KYC Documents Alert
            unverified_kyc = KYCDocument.objects.filter(status='PENDING')
            if unverified_kyc.exists():
                alerts.append({
                    'title': 'Pending KYC Verifications',
                    'description': f'{unverified_kyc.count()} KYC documents awaiting verification',
                    'severity': 'medium'
                })

            # New Member Registrations Alert
            new_members = MLMMember.objects.filter(
                created_at__gte=timezone.now() - timezone.timedelta(days=7)
            )
            if new_members.exists():
                alerts.append({
                    'title': 'New Member Growth',
                    'description': f'{new_members.count()} new members joined in the last 7 days',
                    'severity': 'low'
                })

            return alerts
        except Exception as e:
            logger.error(f"Error getting critical alerts: {str(e)}")
            return []

    def safe_get_recent_activities(self):
        try:
            from home.models import Order, MLMMember, Commission
            activities = []

            # Recent Orders
            recent_orders = Order.objects.order_by('-order_date')[:10]
            for order in recent_orders:
                activities.append({
                    'type': 'order',
                    'description': f'Order #{order.order_number} - ₹{order.final_amount}',
                    'timestamp': order.order_date.strftime('%Y-%m-%d %H:%M')
                })

            # Recent MLM Member Registrations
            recent_members = MLMMember.objects.order_by('-created_at')[:10]
            for member in recent_members:
                activities.append({
                    'type': 'member',
                    'description': f'New MLM Member: {member.user.get_full_name() or member.member_id}',
                    'timestamp': member.created_at.strftime('%Y-%m-%d %H:%M')
                })

            # Recent Commissions
            recent_commissions = Commission.objects.order_by('-date')[:10] if hasattr(globals(), 'Commission') else []
            for commission in recent_commissions:
                activities.append({
                    'type': 'commission',
                    'description': f'Commission of ₹{commission.amount} to {commission.member.user.get_full_name() or commission.member.member_id}',
                    'timestamp': commission.date.strftime('%Y-%m-%d %H:%M')
                })

            # Sort activities by timestamp
            return sorted(
                activities, 
                key=lambda x: x['timestamp'], 
                reverse=True
            )[:10]  # Return top 10 recent activities
        except Exception as e:
            logger.error(f"Error getting recent activities: {str(e)}")
            return []


class MLMMemberRegistrationView(APIView):
    permission_classes = [IsAuthenticated]

    def post(self, request):
        try:
            # Validate that the current user is an MLM member
            if request.user.role != 'MLM_MEMBER':
                return Response({
                    'error': 'Only MLM members can register new members'
                }, status=status.HTTP_403_FORBIDDEN)

            # Get current MLM member (sponsor)
            current_member = MLMMember.objects.get(user=request.user)
            
            # # Get current member's position level
            # current_level = current_member.position.level_order if current_member.position else 0
            
            # # Members can only create members up to level 2
            # if current_level > 2:
            #     # Limit to creating only level 1 or 2 members
            #     max_creation_level = 2
            # else:
            #     # Can only create members of lower level than themselves
            #     max_creation_level = current_level - 1
                
            # if max_creation_level < 1:
            #     return Response({
            #         'error': 'You do not have permission to register new members with your current position'
            #     }, status=status.HTTP_403_FORBIDDEN)
            # Get current member's position level
            current_level = current_member.position.level_order if current_member.position else 0

            # Determine which levels this member can create
            if current_level >= 3:
                # Level 3+ can create both Level 1 and 2
                max_creation_level = 2
            elif current_level == 2:
                # Level 2 can only create Level 1
                max_creation_level = 1
            else:
                # Level 1 can't create any members
                max_creation_level = 0

            if max_creation_level < 1:
                return Response({
                    'error': 'You do not have permission to register new members with your current position'
                }, status=status.HTTP_403_FORBIDDEN)
            
            # Extract document related data
            documents = request.FILES.getlist('document_file')
            document_types = request.POST.getlist('document_types[]')
            
            # Validate basic form data
            validation_result = self.validate_form_data(request.POST)
            if not validation_result['valid']:
                return Response({
                    'error': validation_result['message']
                }, status=status.HTTP_400_BAD_REQUEST)
            
            # Store password for email
            password = request.POST.get('password')

            # Create new member with transaction to ensure all operations succeed or fail together
            with transaction.atomic():
                # Create new user
                new_user = User.objects.create_user(
                    username=request.POST.get('username'),
                    password=request.POST.get('password'),
                    phone_number=request.POST.get('phone_number'),
                    first_name=request.POST.get('first_name'),
                    last_name=request.POST.get('last_name', ''),
                    email=request.POST.get('email', ''),
                    role='MLM_MEMBER'
                )

                # Determine position based on level restriction
                # Position level 1 is the lowest level
                position = Position.objects.filter(
                    level_order__lte=max_creation_level,
                    is_active=True
                ).order_by('level_order').first()
                
                if not position:
                    raise ValueError("No valid position available for new member")

                # Create MLM Member
                new_mlm_member = MLMMember.objects.create(
                    user=new_user,
                    sponsor=current_member,
                    position=position,
                    is_active=True,
                    first_payment_complete=False
                )

                # Process KYC Documents
                kyc_docs_list = []
                
                # Create a mapping of document types to their numbers
                document_numbers = {}
                for doc_type in ['AADHAR', 'PAN']:
                    if doc_type in request.POST:
                        document_numbers[doc_type] = request.POST.get(doc_type)
                
                for doc, doc_type in zip(documents, document_types):
                    try:
                        # Validate document numbers
                        if doc_type == 'AADHAR':
                            if not re.match(r'^\d{12}$', document_numbers.get(doc_type, '')):
                                raise ValueError("Aadhar number must be exactly 12 digits")
                        elif doc_type == 'PAN':
                            if not re.match(r'^[A-Z]{5}[0-9]{4}[A-Z]{1}$', document_numbers.get(doc_type, '')):
                                raise ValueError("PAN number must be in format AAAAA0000A")
                        
                        kyc_doc = KYCDocument.objects.create(
                            mlm_member=new_mlm_member,
                            document_file=doc,
                            document_type=doc_type,
                            document_number=document_numbers.get(doc_type, ''),
                            status='PENDING'
                        )
                        kyc_docs_list.append(kyc_doc)
                    except Exception as doc_error:
                        logger.error(f"Error creating KYC document: {str(doc_error)}")
                        raise ValueError(f"Failed to process document: {str(doc_error)}")
                    
                # Send welcome email if email is provided
                # if new_user.email:
                #     try:
                #         # Pass the plain text password only for email purposes
                #         send_welcome_email(new_user, password, current_member)
                #     except Exception as email_error:
                #         logger.error(f"Error sending welcome email: {str(email_error)}")
                        # Don't fail the registration if email fails
                        # You might want to log this or set a flag to retry later

                # Create notification about new member registration if needed
                # Notification.objects.create(...)
                # Create notification about new member registration and first payment requirement
                Notification.objects.create(
                    title='New Member Registration',
                    message=f"You've been registered as a new MLM member. Please complete your first payment of at least ₹{position.monthly_quota} to activate your account.",
                    notification_type='INDIVIDUAL',
                    recipient=new_mlm_member
                )

                # Create notification for sponsor
                Notification.objects.create(
                    title='New Downline Member',
                    message=f"You've successfully registered {new_user.get_full_name()} as your downline. You'll receive a ₹1000 bonus when they complete their first payment.",
                    notification_type='INDIVIDUAL',
                    recipient=current_member
                )

                return Response({
                    'status': 'success',
                    'message': 'Member registered successfully',
                    'member_details': {
                        'member_id': new_mlm_member.member_id,
                        'username': new_user.username,
                        'full_name': new_user.get_full_name(),
                        'email': new_user.email,
                        'phone': new_user.phone_number,
                        'sponsor': current_member.member_id,
                        'position': position.name,
                        'level': position.level_order,
                        'first_payment_required': float(position.monthly_quota)
                    }
                })

        except User.DoesNotExist:
            return Response({
                'error': 'User does not exist'
            }, status=status.HTTP_404_NOT_FOUND)
        except MLMMember.DoesNotExist:
            return Response({
                'error': 'MLM member profile not found'
            }, status=status.HTTP_404_NOT_FOUND)
        except ValueError as ve:
            return Response({
                'error': str(ve)
            }, status=status.HTTP_400_BAD_REQUEST)
        except Exception as e:
            logger.error(f"Error in MLM member registration: {str(e)}")
            return Response({
                'error': f'Registration failed: {str(e)}'
            }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

    def validate_form_data(self, data):
        # Username validation
        username = data.get('username', '')
        if not username or len(username) < 5:
            return {'valid': False, 'message': 'Username must be at least 5 characters'}
        
        if User.objects.filter(username=username).exists():
            return {'valid': False, 'message': 'Username is already taken'}
        
        # Password validation
        password = data.get('password', '')
        if not password or len(password) < 6:
            return {'valid': False, 'message': 'Password must be at least 6 characters'}
        
        # Phone number validation
        phone_number = data.get('phone_number', '')
        if not re.match(r'^\d{10}$', phone_number):
            return {'valid': False, 'message': 'Phone number must be 10 digits'}
        
        if User.objects.filter(phone_number=phone_number).exists():
            return {'valid': False, 'message': 'Phone number is already registered'}
        
        # Email validation if provided
        email = data.get('email', '')
        if email and not re.match(r'\S+@\S+\.\S+', email):
            return {'valid': False, 'message': 'Invalid email format'}
        
        if email and User.objects.filter(email=email).exists():
            return {'valid': False, 'message': 'Email is already registered'}
        
        # Required fields validation
        if not data.get('first_name', ''):
            return {'valid': False, 'message': 'First name is required'}
        
        # Aadhar validation
        aadhar = data.get('AADHAR', '')
        if not re.match(r'^\d{12}$', aadhar):
            return {'valid': False, 'message': 'Aadhar number must be exactly 12 digits'}
        
        # PAN validation
        pan = data.get('PAN', '')
        if not re.match(r'^[A-Z]{5}[0-9]{4}[A-Z]{1}$', pan):
            return {'valid': False, 'message': 'PAN number must be in format AAAAA0000A'}
        
        return {'valid': True}



class DownlineListView(APIView):
    permission_classes = [IsAuthenticated]

    def get(self, request):
        try:
            # Determine the base member for the tree view
            if request.user.role == 'ADMIN':
                # Admin sees entire tree, starting from root
                base_member = MLMMember.objects.filter(sponsor__isnull=True).first()
            elif request.user.role == 'MLM_MEMBER':
                # MLM member sees their own downline
                base_member = request.user.mlm_profile
            else:
                return Response({
                    'error': 'Unauthorized access'
                }, status=status.HTTP_403_FORBIDDEN)

            # If no base member found, return empty list
            if not base_member:
                return Response({
                    'message': 'No downline available',
                    'downline': []
                })

            # Paginate the downline
            page = int(request.query_params.get('page', 1))
            page_size = int(request.query_params.get('page_size', 10))
            
            # Filter options
            name_filter = request.query_params.get('name', '')
            status_filter = request.query_params.get('status', '')
            position_filter = request.query_params.get('position', '')

            # Recursive function to build downline list with filtering
            def build_downline_list(current_member, depth=0):
                # Get direct referrals with filtering
                referrals_query = MLMMember.objects.filter(sponsor=current_member)
                
                # Apply filters
                if name_filter:
                    referrals_query = referrals_query.filter(
                        Q(user__first_name__icontains=name_filter) | 
                        Q(user__last_name__icontains=name_filter)
                    )
                
                if status_filter:
                    referrals_query = referrals_query.filter(
                        is_active=status_filter.lower() == 'active'
                    )
                
                if position_filter:
                    referrals_query = referrals_query.filter(
                        position__name__iexact=position_filter
                    )

                # Prepare referrals data
                referrals_data = []
                for referral in referrals_query:
                    referral_info = {
                        'id': referral.id,
                        'member_id': referral.member_id,
                        'name': referral.user.get_full_name(),
                        'email': referral.user.email,
                        'phone': referral.user.phone_number,
                        'position': referral.position.name if referral.position else None,
                        'is_active': referral.is_active,
                        'join_date': referral.created_at,
                        'direct_referrals_count': MLMMember.objects.filter(sponsor=referral).count(),
                        'depth': depth
                    }
                    referrals_data.append(referral_info)

                return referrals_data

            # Get downline
            downline = build_downline_list(base_member)

            # Pagination
            total_members = len(downline)
            total_pages = (total_members + page_size - 1) // page_size
            start_index = (page - 1) * page_size
            end_index = start_index + page_size
            paginated_downline = downline[start_index:end_index]

            return Response({
                'downline': paginated_downline,
                'total_members': total_members,
                'current_page': page,
                'total_pages': total_pages
            })

        except Exception as e:
            logger.error(f"Downline List Error: {str(e)}")
            return Response({
                'error': 'Failed to fetch downline',
                'details': str(e)
            }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
        

class ContactViewSet(viewsets.ModelViewSet):
    queryset = Contact.objects.all()
    serializer_class = ContactSerializer

    def get_permissions(self):
        if self.action == 'create':
            return [AllowAny()]
        return [IsAdminUser()]

    def create(self, request, *args, **kwargs):
        try:
            logger.info(f"Contact form submission: {request.data}")
            serializer = self.get_serializer(data=request.data)
            
            if serializer.is_valid():
                self.perform_create(serializer)
                
                # You can add email notification logic here
                # send_notification_email(serializer.data)
                
                return Response({
                    'status': 'success',
                    'message': 'Thank you for contacting us. We will get back to you soon.'
                }, status=status.HTTP_201_CREATED)
            
            logger.error(f"Contact form validation error: {serializer.errors}")
            return Response({
                'status': 'error',
                'message': 'Please check your input',
                'errors': serializer.errors
            }, status=status.HTTP_400_BAD_REQUEST)

        except Exception as e:
            logger.error(f"Error in contact form submission: {str(e)}")
            return Response({
                'status': 'error',
                'message': 'An error occurred while processing your request'
            }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

    def list(self, request, *args, **kwargs):
        try:
            queryset = self.get_queryset()
            
            # Filter by read status
            is_read = request.query_params.get('is_read')
            if is_read is not None:
                queryset = queryset.filter(is_read=is_read.lower() == 'true')

            # Search functionality
            search = request.query_params.get('search')
            if search:
                queryset = queryset.filter(
                    Q(name__icontains=search) |
                    Q(email__icontains=search) |
                    Q(subject__icontains=search) |
                    Q(message__icontains=search)
                )

            # Date range filter
            start_date = request.query_params.get('start_date')
            end_date = request.query_params.get('end_date')
            if start_date:
                queryset = queryset.filter(created_at__date__gte=start_date)
            if end_date:
                queryset = queryset.filter(created_at__date__lte=end_date)

            serializer = self.get_serializer(queryset, many=True)
            return Response(serializer.data)

        except Exception as e:
            logger.error(f"Error fetching contacts: {str(e)}")
            return Response({
                'status': 'error',
                'message': 'An error occurred while fetching contacts'
            }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
        


class NewsletterViewSet(viewsets.ModelViewSet):
    queryset = Newsletter.objects.all()
    serializer_class = NewsletterSerializer

    def get_permissions(self):
        if self.action == 'create':
            return [AllowAny()]
        return [IsAdminUser()]

    def create(self, request, *args, **kwargs):
        try:
            serializer = self.get_serializer(data=request.data)
            if serializer.is_valid():
                self.perform_create(serializer)
                return Response({
                    'status': 'success',
                    'message': 'Thank you for subscribing to our newsletter!'
                }, status=status.HTTP_201_CREATED)
            
            return Response({
                'status': 'error',
                'message': 'Invalid email address',
                'errors': serializer.errors
            }, status=status.HTTP_400_BAD_REQUEST)

        except Exception as e:
            logger.error(f"Error in newsletter subscription: {str(e)}")
            return Response({
                'status': 'error',
                'message': 'An error occurred while processing your request'
            }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

    def list(self, request, *args, **kwargs):
        try:
            queryset = self.get_queryset()
            
            # Filter by active status
            is_active = request.query_params.get('is_active')
            if is_active is not None:
                queryset = queryset.filter(is_active=is_active.lower() == 'true')

            # Search functionality
            search = request.query_params.get('search')
            if search:
                queryset = queryset.filter(email__icontains=search)

            # Date range filter
            start_date = request.query_params.get('start_date')
            end_date = request.query_params.get('end_date')
            if start_date:
                queryset = queryset.filter(created_at__date__gte=start_date)
            if end_date:
                queryset = queryset.filter(created_at__date__lte=end_date)

            serializer = self.get_serializer(queryset, many=True)
            return Response(serializer.data)

        except Exception as e:
            logger.error(f"Error fetching newsletter subscriptions: {str(e)}")
            return Response({
                'status': 'error',
                'message': 'An error occurred while fetching subscriptions'
            }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
        

class MLMLiveCommissionView(APIView):
    authentication_classes = [JWTAuthentication]
    permission_classes = [IsAuthenticated]
    
    def get(self, request, member_id):
        try:
            # Check permissions - either admin or the member themselves can view
            if request.user.role != 'ADMIN' and (not hasattr(request.user, 'mlm_profile') or request.user.mlm_profile.member_id != member_id):
                return Response({
                    'error': 'You do not have permission to view this data'
                }, status=status.HTTP_403_FORBIDDEN)
            
            # Get the MLM member
            try:
                member = MLMMember.objects.get(member_id=member_id)
            except MLMMember.DoesNotExist:
                return Response({
                    'error': 'Member not found'
                }, status=status.HTTP_404_NOT_FOUND)
            
            # Check if member's position can earn commissions
            if not member.position.can_earn_commission:
                return Response({
                    'current_month_estimate': "0.00",
                    'last_month_earned': "0.00",
                    'total_pending': "0.00",
                    'level_breakdown': [],
                    'top_performers': [],
                    'recent_transactions': []
                })

            # Get current month and last month dates
            today = timezone.now()
            first_day_current_month = today.replace(day=1, hour=0, minute=0, second=0, microsecond=0)
            last_month = (today.replace(day=1) - timedelta(days=1))
            first_day_last_month = last_month.replace(day=1, hour=0, minute=0, second=0, microsecond=0)
            
            # Calculate last month's earned commissions
            last_month_earned = Commission.objects.filter(
                member=member,
                is_paid=True,
                date__gte=first_day_last_month,
                date__lt=first_day_current_month
            ).aggregate(total=Sum('amount'))['total'] or Decimal('0.00')

            # Calculate total pending commissions
            total_pending = Commission.objects.filter(
                member=member,
                is_paid=False
            ).aggregate(total=Sum('amount'))['total'] or Decimal('0.00')

            # Get downline members by level for organizational purposes only
            downline_by_level = self.get_downline_by_level(member)
            
            # Calculate level breakdown - using pure differential model
            level_breakdown, current_month_estimate = self.calculate_level_commission_differential(
                member, 
                downline_by_level
            )
            
            # Get top performers
            top_performers = self.get_top_performers_differential(member, downline_by_level)
            
            # Get recent transactions
            recent_transactions = self.get_recent_transactions_differential(member, downline_by_level)

            return Response({
                'current_month_estimate': str(current_month_estimate),
                'last_month_earned': str(last_month_earned),
                'total_pending': str(total_pending),
                'level_breakdown': level_breakdown,
                'top_performers': top_performers,
                'recent_transactions': recent_transactions
            })
            
        except Exception as e:
            logger.error(f"Error in MLMLiveCommissionView: {str(e)}", exc_info=True)
            return Response({
                'error': 'An error occurred while calculating commissions'
            }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
    
    def get_downline_by_level(self, member, max_level=5):
        """Get all downline members organized by level (for display purposes)"""
        result = {}
        
        def traverse(current_member, level=1):
            if level > max_level:
                return
                
            # Get direct downline
            downline = MLMMember.objects.filter(
                sponsor=current_member,
                is_active=True
            ).select_related('user', 'position')
            
            if downline.exists():
                if level not in result:
                    result[level] = []
                    
                for downline_member in downline:
                    result[level].append({
                        'id': downline_member.id,
                        'member_id': downline_member.member_id,
                        'user_id': downline_member.user.id,
                        'position': downline_member.position,
                        'position_percentage': downline_member.position.discount_percentage,
                        'position_name': downline_member.position.name
                    })
                    
                    # Recursively get next level
                    traverse(downline_member, level + 1)
        
        traverse(member)
        return result
    
    def calculate_level_commission_differential(self, member, downline_data):
        """
        Calculate commission breakdown by level using pure differential model
        Commission is based solely on position percentage difference
        """
        level_breakdown = []
        current_month_estimate = Decimal('0.00')
        
        # Get current month orders
        today = timezone.now()
        first_day_current_month = today.replace(day=1, hour=0, minute=0, second=0, microsecond=0)
        
        current_month_orders = Order.objects.filter(
            order_date__gte=first_day_current_month,
            status__in=['CONFIRMED', 'SHIPPED', 'DELIVERED']
        )
        
        # Member's position percentage
        member_percentage = member.position.discount_percentage
        
        # Calculate level breakdown
        for level, members in downline_data.items():
            level_total_purchases = Decimal('0.00')
            level_total_commission = Decimal('0.00')
            downline_count = 0
            
            for downline_info in members:
                # Only consider downline with lower position percentage
                downline_percentage = downline_info['position_percentage']
                
                if member_percentage > downline_percentage:
                    # Calculate percentage difference
                    difference_percentage = member_percentage - downline_percentage
                    
                    # Get user's purchases
                    user_id = downline_info['user_id']
                    user_purchases = current_month_orders.filter(
                        user_id=user_id
                    ).aggregate(total=Sum('final_amount'))['total'] or Decimal('0.00')
                    
                    if user_purchases > 0:
                        # Calculate commission based on differential model
                        commission = (user_purchases * difference_percentage) / 100
                        
                        # Add to totals
                        level_total_purchases += user_purchases
                        level_total_commission += commission
                        downline_count += 1
            
            # Add level breakdown if there were qualifying purchases
            if level_total_purchases > 0:
                # Calculate effective commission rate for this level
                # This is just for display purposes - the actual calculation uses individual differences
                effective_rate = (level_total_commission / level_total_purchases) * 100
                
                level_breakdown.append({
                    'level': level,
                    'member_count': downline_count,
                    'total_purchases': str(level_total_purchases),
                    'commission_rate': str(effective_rate),  # Average effective rate
                    'estimated_commission': str(level_total_commission)
                })
                
                current_month_estimate += level_total_commission
        
        # Sort breakdown by level
        level_breakdown.sort(key=lambda x: x['level'])
        
        return level_breakdown, current_month_estimate
    
    def calculate_commission_differential(self, member, downline_member, purchase_amount):
        """
        Calculate commission based purely on position percentage difference
        """
        member_percentage = member.position.discount_percentage
        downline_percentage = downline_member['position_percentage']
        
        # Only calculate if member's percentage is higher
        if member_percentage <= downline_percentage:
            return Decimal('0.00')
        
        # Calculate difference percentage
        difference_percentage = member_percentage - downline_percentage
        
        # Calculate commission amount based on differential model
        commission_amount = (purchase_amount * difference_percentage) / 100
        
        return commission_amount
    
    def get_top_performers_differential(self, member, downline_by_level, limit=5):
        """Get top performing downline members using differential model"""
        try:
            # Flatten downline data
            all_downline = []
            for level, members in downline_by_level.items():
                for m in members:
                    m['level'] = level
                    all_downline.append(m)
            
            # Get user IDs
            user_ids = [m['user_id'] for m in all_downline]
            
            if not user_ids:
                return []
            
            # Get current month
            today = timezone.now()
            first_day_current_month = today.replace(day=1, hour=0, minute=0, second=0, microsecond=0)
            
            # Calculate purchases for each downline member
            user_purchases = {}
            
            current_month_orders = Order.objects.filter(
                user_id__in=user_ids,
                order_date__gte=first_day_current_month,
                status__in=['CONFIRMED', 'SHIPPED', 'DELIVERED']
            )
            
            for order in current_month_orders:
                if order.user_id not in user_purchases:
                    user_purchases[order.user_id] = Decimal('0.00')
                user_purchases[order.user_id] += order.final_amount
            
            # Calculate commissions based on differential model
            user_commissions = {}
            for user_id, purchase_amount in user_purchases.items():
                downline_info = next((m for m in all_downline if m['user_id'] == user_id), None)
                if downline_info:
                    # Calculate commission using differential model
                    commission = self.calculate_commission_differential(
                        member, 
                        downline_info, 
                        purchase_amount
                    )
                    user_commissions[user_id] = {
                        'purchase_amount': purchase_amount,
                        'commission': commission,
                        'downline_info': downline_info
                    }
            
            # Sort by commission amount (highest first)
            sorted_users = sorted(
                user_commissions.items(),
                key=lambda x: x[1]['commission'],
                reverse=True
            )[:limit]
            
            top_performers = []
            for user_id, data in sorted_users:
                if data['commission'] > 0:
                    # Get MLM member object to access full details
                    downline_member = MLMMember.objects.select_related('user', 'position').get(
                        id=data['downline_info']['id']
                    )
                    
                    top_performers.append({
                        'member_id': downline_member.member_id,
                        'name': f"{downline_member.user.first_name} {downline_member.user.last_name}",
                        'level': data['downline_info']['level'],
                        'position': downline_member.position.name,
                        'position_percentage': str(downline_member.position.discount_percentage),
                        'your_percentage': str(member.position.discount_percentage),
                        'difference': str(member.position.discount_percentage - downline_member.position.discount_percentage),
                        'total_purchases': str(data['purchase_amount']),
                        'your_commission': str(data['commission'])
                    })
            
            return top_performers
            
        except Exception as e:
            logger.error(f"Error getting top performers: {str(e)}")
            return []
    
    def get_recent_transactions_differential(self, member, downline_by_level, limit=10):
        """Get recent transactions from downline members using differential model"""
        try:
            # Flatten downline data
            all_downline = []
            for level, members in downline_by_level.items():
                for m in members:
                    m['level'] = level
                    all_downline.append(m)
            
            # Get user IDs
            user_ids = [m['user_id'] for m in all_downline]
            
            if not user_ids:
                return []
            
            # Get current month
            today = timezone.now()
            first_day_current_month = today.replace(day=1, hour=0, minute=0, second=0, microsecond=0)
            
            # Get recent orders
            recent_orders = Order.objects.filter(
                user_id__in=user_ids,
                order_date__gte=first_day_current_month,
                status__in=['CONFIRMED', 'SHIPPED', 'DELIVERED']
            ).select_related('user').order_by('-order_date')[:limit]
            
            transactions = []
            for order in recent_orders:
                # Find member details
                downline_info = next((m for m in all_downline if m['user_id'] == order.user.id), None)
                
                if downline_info:
                    # Calculate commission using differential model
                    commission_amount = self.calculate_commission_differential(
                        member,
                        downline_info,
                        order.final_amount
                    )
                    
                    # Only include transactions that generate commission
                    if commission_amount > 0:
                        transactions.append({
                            'date': order.order_date.isoformat(),
                            'member_name': f"{order.user.first_name} {order.user.last_name}",
                            'level': downline_info['level'],
                            'order_id': order.order_number,
                            'amount': str(order.final_amount),
                            'your_percentage': str(member.position.discount_percentage),
                            'their_percentage': str(downline_info['position_percentage']),
                            'difference': str(member.position.discount_percentage - downline_info['position_percentage']),
                            'your_commission': str(commission_amount)
                        })
            
            return transactions
            
        except Exception as e:
            logger.error(f"Error getting recent transactions: {str(e)}")
            return []
        
    def get_monthly_quota_status(self, member):
        """
        Check monthly quota status
        """
        try:
            # Get position
            position = member.position
            
            # Get current month purchases
            current_month_purchase = float(member.current_month_purchase or 0)
            
            # Get required monthly quota
            monthly_quota = float(position.monthly_quota)
            
            # Calculate remaining amount
            remaining = max(0, monthly_quota - current_month_purchase)
            
            # Determine status
            if current_month_purchase >= monthly_quota:
                return "COMPLETED", 0
            else:
                return "PENDING", remaining
                
        except Exception as e:
            logger.error(f"Error checking monthly quota: {str(e)}")
            return "PENDING", 0


class AdminCustomerViewSet(viewsets.ReadOnlyModelViewSet):
    """
    ViewSet for admin to manage customers
    """
    authentication_classes = [JWTAuthentication]
    permission_classes = [IsAdminUser]
    
    def get_queryset(self):
        # Base queryset - only CUSTOMER role users
        queryset = User.objects.filter(role='CUSTOMER').annotate(
            order_count=Count('orders')
        ).select_related(
            'customer'  # If you have a customer profile model
        ).prefetch_related(
            'addresses'
        )
        
        # Apply filters
        search = self.request.query_params.get('search')
        date_joined = self.request.query_params.get('date_joined')
        has_orders = self.request.query_params.get('has_orders')
        
        # Search filter
        if search:
            queryset = queryset.filter(
                Q(first_name__icontains=search) |
                Q(last_name__icontains=search) |
                Q(email__icontains=search) |
                Q(phone_number__icontains=search)
            )
        
        # Date joined filter
        if date_joined:
            queryset = queryset.filter(date_joined__date=date_joined)
        
        # Has orders filter
        if has_orders == 'true':
            queryset = queryset.filter(order_count__gt=0)
        elif has_orders == 'false':
            queryset = queryset.filter(order_count=0)
        
        return queryset.order_by('-date_joined')
    
    def get_serializer_class(self):
        if self.action == 'retrieve':
            return CustomerDetailSerializer
        return CustomerListSerializer
    
    def list(self, request, *args, **kwargs):
        queryset = self.get_queryset()
        serializer = self.get_serializer(queryset, many=True)
        return Response(serializer.data)
    
    def retrieve(self, request, *args, **kwargs):
        instance = self.get_object()
        serializer = self.get_serializer(instance)
        return Response(serializer.data)
    
    @action(detail=True, methods=['get'])
    def orders(self, request, pk=None):
        """Get all orders for a specific customer"""
        customer = self.get_object()
        orders = Order.objects.filter(user=customer).order_by('-order_date')
        serializer = OrderSerializer(orders, many=True)
        return Response(serializer.data)
    
    @action(detail=False, methods=['get'])
    def stats(self, request):
        """Get customer statistics for admin dashboard"""
        # Total customers
        total_customers = User.objects.filter(role='CUSTOMER').count()
        
        # New customers this month
        first_day_of_month = timezone.now().replace(day=1, hour=0, minute=0, second=0, microsecond=0)
        new_this_month = User.objects.filter(
            role='CUSTOMER',
            date_joined__gte=first_day_of_month
        ).count()
        
        # Active customers (placed order in last 30 days)
        thirty_days_ago = timezone.now() - timedelta(days=30)
        active_customers = User.objects.filter(
            role='CUSTOMER',
            orders__order_date__gte=thirty_days_ago
        ).distinct().count()
        
        # Customers with orders
        with_orders = User.objects.filter(
            role='CUSTOMER',
            orders__isnull=False
        ).distinct().count()
        
        # Monthly growth data (last 6 months)
        six_months_ago = timezone.now() - timedelta(days=180)
        monthly_growth = User.objects.filter(
            role='CUSTOMER',
            date_joined__gte=six_months_ago
        ).annotate(
            month=TruncMonth('date_joined')
        ).values('month').annotate(
            count=Count('id')
        ).order_by('month')
        
        return Response({
            'total_customers': total_customers,
            'new_this_month': new_this_month,
            'active_customers': active_customers,
            'with_orders': with_orders,
            'monthly_growth': [
                {
                    'month': item['month'].strftime('%b %Y'),
                    'count': item['count']
                }
                for item in monthly_growth
            ]
        })
    
class OrderTrackingView(APIView):
    permission_classes = [AllowAny]

    def get(self, request):
        try:
            # Get order number from query parameters
            order_number = request.query_params.get('order_number', '')
            
            if not order_number:
                return Response(
                    {'error': 'Order number is required'}, 
                    status=status.HTTP_400_BAD_REQUEST
                )
                
            # Find the order
            order = get_object_or_404(Order, order_number=order_number)
            
            # Get shipments for this order
            shipments = order.shipments.all()
            
            # Get tracking information
            tracking_info = self.get_tracking_info(order, shipments)
            
            return Response(tracking_info)
            
        except Order.DoesNotExist:
            return Response(
                {'error': 'Order not found. Please check the order number and try again.'}, 
                status=status.HTTP_404_NOT_FOUND
            )
        except Exception as e:
            logger.error(f"Error in order tracking: {str(e)}")
            return Response(
                {'error': 'An error occurred while fetching order tracking information'}, 
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )
    
    def get_tracking_info(self, order, shipments):
        """Generate tracking information based on order status and shipments"""
        
        # Initialize dates based on order status
        confirmed_date = order.updated_at if order.status in ['CONFIRMED', 'SHIPPED', 'DELIVERED'] else None
        shipped_date = None
        delivered_date = None
        expected_delivery = None
        current_location = None
        
        # Shipment details
        shipment_details = []
        
        # If we have shipments, use that data
        if shipments.exists():
            shipment = shipments.first()  # Use the first shipment for main tracking info
            
            # Set current status based on shipment
            if shipment.status == 'BOOKED':
                shipped_date = None
                current_location = "Order Processing Center"
                expected_delivery = (order.order_date + timedelta(days=5)).strftime('%Y-%m-%d')
            elif shipment.status == 'PICKED_UP':
                shipped_date = shipment.status_updates.filter(status='PICKED_UP').first().timestamp if shipment.status_updates.filter(status='PICKED_UP').exists() else None
                current_location = "Shipment Picked Up"
                expected_delivery = (order.order_date + timedelta(days=4)).strftime('%Y-%m-%d')
            elif shipment.status == 'IN_TRANSIT':
                shipped_date = shipment.status_updates.filter(status='PICKED_UP').first().timestamp if shipment.status_updates.filter(status='PICKED_UP').exists() else None
                current_location = "In Transit"
                expected_delivery = (order.order_date + timedelta(days=3)).strftime('%Y-%m-%d')
            elif shipment.status == 'OUT_FOR_DELIVERY':
                shipped_date = shipment.status_updates.filter(status='PICKED_UP').first().timestamp if shipment.status_updates.filter(status='PICKED_UP').exists() else None
                current_location = "Out For Delivery"
                expected_delivery = timezone.now().strftime('%Y-%m-%d')
            elif shipment.status == 'DELIVERED':
                shipped_date = shipment.status_updates.filter(status='PICKED_UP').first().timestamp if shipment.status_updates.filter(status='PICKED_UP').exists() else None
                delivered_date = shipment.status_updates.filter(status='DELIVERED').first().timestamp if shipment.status_updates.filter(status='DELIVERED').exists() else None
                current_location = "Delivered"
            elif shipment.status == 'FAILED_DELIVERY':
                shipped_date = shipment.status_updates.filter(status='PICKED_UP').first().timestamp if shipment.status_updates.filter(status='PICKED_UP').exists() else None
                current_location = "Delivery Attempt Failed"
                expected_delivery = (timezone.now() + timedelta(days=1)).strftime('%Y-%m-%d')
            elif shipment.status == 'RETURNED':
                shipped_date = shipment.status_updates.filter(status='PICKED_UP').first().timestamp if shipment.status_updates.filter(status='PICKED_UP').exists() else None
                current_location = "Returned to Seller"
            elif shipment.status == 'CANCELLED':
                current_location = "Shipment Cancelled"
            
            # Get status history
            status_history = []
            for status_update in shipment.status_updates.all():
                status_history.append({
                    'status': status_update.status,
                    'details': status_update.status_details,
                    'location': status_update.location,
                    'timestamp': status_update.timestamp.isoformat(),
                })
            
            # Add shipment details
            shipment_details.append({
                'awb_number': shipment.awb_number,
                'courier': shipment.courier_name,
                'status': shipment.status,
                'weight': str(shipment.weight),
                'dimensions': f"{shipment.length} x {shipment.width} x {shipment.height} cm",
                'tracking_url': shipment.tracking_url or f"https://example.com/track?awb={shipment.awb_number}",
                'status_history': status_history
            })
        else:
            # Set tracking info based on order status if no shipments
            if order.status == 'CONFIRMED':
                confirmed_date = order.updated_at
                expected_delivery = (order.order_date + timedelta(days=5)).strftime('%Y-%m-%d')
                current_location = "Order Processing Center"
                
            elif order.status == 'SHIPPED':
                confirmed_date = order.order_date + timedelta(days=1)  # Estimate confirmation 1 day after order
                shipped_date = order.updated_at
                expected_delivery = (shipped_date + timedelta(days=3)).strftime('%Y-%m-%d')
                current_location = "In Transit"
                
            elif order.status == 'DELIVERED':
                confirmed_date = order.order_date + timedelta(days=1)
                shipped_date = order.order_date + timedelta(days=2)
                delivered_date = order.updated_at
                current_location = "Delivered"
                
            elif order.status == 'CANCELLED':
                current_location = "Order Cancelled"
                
            else:  # PENDING
                expected_delivery = (order.order_date + timedelta(days=7)).strftime('%Y-%m-%d')
                current_location = "Order Received"
        
        # Construct the tracking info response
        tracking_info = {
            'id': order.id,
            'order_number': order.order_number,
            'status': order.status,
            'order_date': order.order_date.isoformat(),
            'confirmed_date': confirmed_date.isoformat() if confirmed_date else None,
            'shipped_date': shipped_date.isoformat() if shipped_date else None,
            'delivered_date': delivered_date.isoformat() if delivered_date else None,
            'expected_delivery': expected_delivery,
            'current_location': current_location,
            'total_amount': float(order.total_amount),
            'final_amount': float(order.final_amount),
            'shipping_address': order.shipping_address,
            'shipments': shipment_details
        }
        
        return tracking_info
    

class CheckUsernameView(APIView):
    permission_classes = [IsAuthenticated]
    
    def get(self, request):
        try:
            username = request.query_params.get('username', '')
            
            if not username:
                return Response(
                    {'error': 'Username parameter is required'}, 
                    status=status.HTTP_400_BAD_REQUEST
                )
                
            # Check if username exists
            exists = User.objects.filter(username=username).exists()
            
            return Response({
                'available': not exists,
                'message': 'Username is available' if not exists else 'Username is already taken'
            })
            
        except Exception as e:
            logger.error(f"Error checking username: {str(e)}")
            return Response(
                {'error': 'An error occurred while checking username'}, 
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )
        

class UpdateStockView(APIView):
    """
    API endpoint to update product stock after successful payment
    """
    authentication_classes = [JWTAuthentication]
    permission_classes = [IsAuthenticated]
    
    def post(self, request):
        try:
            items = request.data.get('items', [])
            
            if not items:
                return Response(
                    {'error': 'No items provided'}, 
                    status=status.HTTP_400_BAD_REQUEST
                )
            
            with transaction.atomic():
                updated_items = []
                out_of_stock_items = []
                
                for item in items:
                    product_id = item.get('product_id')
                    quantity = item.get('quantity', 0)
                    
                    try:
                        product = Product.objects.select_for_update().get(id=product_id)
                        
                        # Check if sufficient stock is available
                        if product.stock < quantity:
                            out_of_stock_items.append({
                                'product_id': product_id,
                                'name': product.name,
                                'available_stock': product.stock,
                                'requested_quantity': quantity
                            })
                            continue
                        
                        # Update the stock
                        product.stock -= quantity
                        product.save()
                        
                        updated_items.append({
                            'product_id': product_id,
                            'name': product.name,
                            'previous_stock': product.stock + quantity,
                            'new_stock': product.stock
                        })
                        
                    except Product.DoesNotExist:
                        return Response(
                            {'error': f'Product with ID {product_id} not found'}, 
                            status=status.HTTP_404_NOT_FOUND
                        )
                
                if out_of_stock_items:
                    # If any items are out of stock, rollback transaction and return error
                    transaction.set_rollback(True)
                    return Response({
                        'success': False,
                        'message': 'Some items are out of stock',
                        'out_of_stock_items': out_of_stock_items
                    }, status=status.HTTP_400_BAD_REQUEST)
                
                return Response({
                    'success': True,
                    'message': 'Stock updated successfully',
                    'updated_items': updated_items
                })
                
        except Exception as e:
            logger.error(f"Error updating stock: {str(e)}")
            return Response(
                {'error': 'An error occurred while updating stock'}, 
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )

class CheckStockAvailabilityView(APIView):
    """
    API endpoint to check if requested products are in stock
    """
    authentication_classes = [JWTAuthentication]
    permission_classes = [IsAuthenticated]
    
    def post(self, request):
        try:
            items = request.data.get('items', [])
            
            if not items:
                return Response(
                    {'success': False, 'message': 'No items provided'}, 
                    status=status.HTTP_400_BAD_REQUEST
                )
            
            out_of_stock_items = []
            
            for item in items:
                product_id = item.get('product_id')
                quantity = item.get('quantity', 0)
                
                try:
                    product = Product.objects.get(id=product_id)
                    
                    # Check if sufficient stock is available
                    if product.stock < quantity:
                        out_of_stock_items.append({
                            'product_id': product_id,
                            'name': product.name,
                            'available_stock': product.stock,
                            'requested_quantity': quantity
                        })
                        
                except Product.DoesNotExist:
                    return Response(
                        {'success': False, 'message': f'Product with ID {product_id} not found'}, 
                        status=status.HTTP_404_NOT_FOUND
                    )
            
            if out_of_stock_items:
                return Response({
                    'success': False,
                    'message': 'Some items are out of stock',
                    'out_of_stock_items': out_of_stock_items
                })
            
            return Response({
                'success': True,
                'message': 'All items are in stock'
            })
            
        except Exception as e:
            logger.error(f"Error checking stock availability: {str(e)}")
            return Response(
                {'success': False, 'message': 'An error occurred while checking stock'}, 
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )

class OrderCancellationView(APIView):
    """
    API endpoint to cancel an incomplete order
    """
    authentication_classes = [JWTAuthentication]
    permission_classes = [IsAuthenticated]
    
    def post(self, request, order_id):
        try:
            order = Order.objects.get(id=order_id, user=request.user)
            
            # Only allow cancellation for pending orders
            if order.status != 'PENDING':
                return Response(
                    {'error': 'Only pending orders can be cancelled'}, 
                    status=status.HTTP_400_BAD_REQUEST
                )
            
            # Update order status
            order.status = 'CANCELLED'
            order.save()
            
            return Response({
                'success': True,
                'message': 'Order cancelled successfully'
            })
            
        except Order.DoesNotExist:
            return Response(
                {'error': 'Order not found or you do not have permission to cancel it'}, 
                status=status.HTTP_404_NOT_FOUND
            )
        except Exception as e:
            logger.error(f"Error cancelling order: {str(e)}")
            return Response(
                {'error': 'An error occurred while cancelling the order'}, 
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )





class RequestPasswordResetView(APIView):
    permission_classes = [AllowAny]

    def post(self, request):
        try:
            username = request.data.get('username')
            if not username:
                return Response({
                    'status': False,
                    'message': 'Username is required'
                }, status=status.HTTP_400_BAD_REQUEST)

            try:
                user = User.objects.get(username=username)
            except User.DoesNotExist:
                return Response({
                    'status': False,
                    'message': 'User not found'
                }, status=status.HTTP_404_NOT_FOUND)

            # Check if user is MLM member or admin
            if user.role not in ['MLM_MEMBER', 'ADMIN']:
                return Response({
                    'status': False,
                    'message': 'Password reset not available for customers'
                }, status=status.HTTP_400_BAD_REQUEST)

            # Check for existing pending requests
            existing_request = PasswordResetRequest.objects.filter(
                user=user,
                status='PENDING'
            ).exists()

            if existing_request:
                return Response({
                    'status': False,
                    'message': 'A password reset request is already pending'
                }, status=status.HTTP_400_BAD_REQUEST)

            # Create password reset request without specifying processed_by
            reset_request = PasswordResetRequest.objects.create(
                user=user,
                # Note: processed_by will remain NULL until an admin processes it
            )

            # Send notification to admins
            try:
                admin_emails = User.objects.filter(
                    role='ADMIN',
                    email__isnull=False
                ).values_list('email', flat=True)

                if admin_emails:
                    # Send email notification to admins
                    send_mail(
                        subject='New Password Reset Request',
                        message=f'A password reset request has been submitted for user: {username}',
                        from_email=settings.DEFAULT_FROM_EMAIL,
                        recipient_list=list(admin_emails),
                        fail_silently=True
                    )

                # Create a system notification
                Notification.objects.create(
                    title='New Password Reset Request',
                    message=f'Password reset requested by user: {username}',
                    notification_type='SYSTEM'
                )

            except Exception as e:
                logger.error(f"Error sending notifications: {str(e)}")

            return Response({
                'status': True,
                'message': 'Password reset request submitted successfully'
            })

        except Exception as e:
            logger.error(f"Password reset request error: {str(e)}")
            return Response({
                'status': False,
                'message': 'An error occurred processing your request'
            }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

class ProcessPasswordResetView(APIView):
    permission_classes = [IsAuthenticated]

    def post(self, request, request_id):
        # Add extensive logging
        logger.info(f"Password reset process initiated")
        logger.info(f"Request ID: {request_id}")
        logger.info(f"User: {request.user.username}")
        logger.info(f"User Role: {request.user.role}")
        logger.info(f"Request Data: {request.data}")

        try:
            # Validate admin access
            if request.user.role != 'ADMIN':
                logger.warning(f"Unauthorized access attempt by {request.user.username}")
                return Response({
                    'error': 'Only admin can process reset requests'
                }, status=status.HTTP_403_FORBIDDEN)

            # Retrieve the reset request
            try:
                reset_request = PasswordResetRequest.objects.get(id=request_id)
            except PasswordResetRequest.DoesNotExist:
                logger.error(f"Password reset request {request_id} not found")
                return Response({
                    'error': 'Reset request not found'
                }, status=status.HTTP_404_NOT_FOUND)

            # Validate action
            action = request.data.get('action')
            if action not in ['approve', 'reject']:
                logger.error(f"Invalid action: {action}")
                return Response({
                    'error': 'Invalid action. Must be "approve" or "reject"'
                }, status=status.HTTP_400_BAD_REQUEST)

            # Check request status
            if reset_request.status != 'PENDING':
                logger.warning(f"Attempt to process non-pending request. Current status: {reset_request.status}")
                return Response({
                    'error': f'Cannot process request with status {reset_request.status}'
                }, status=status.HTTP_400_BAD_REQUEST)

            # Process the request
            if action == 'approve':
                # Generate new password
                new_password = ''.join(random.choices(
                    string.ascii_letters + string.digits, k=12
                ))
                
                # Update user password
                user = reset_request.user
                user.set_password(new_password)
                user.save()

                # Log the password reset
                logger.info(f"Password reset approved for user: {user.username}")

                # Update request status
                reset_request.status = 'APPROVED'
                reset_request.processed_at = timezone.now()
                reset_request.processed_by = request.user
                reset_request.save()

                return Response({
                    'message': 'Password reset request approved successfully'
                })
            else:  # reject
                reset_request.status = 'REJECTED'
                reset_request.processed_at = timezone.now()
                reset_request.processed_by = request.user
                reset_request.save()

                logger.info(f"Password reset request rejected for user: {reset_request.user.username}")

                return Response({
                    'message': 'Password reset request rejected successfully'
                })

        except Exception as e:
            # Comprehensive error logging
            logger.error(f"Unexpected error in password reset process: {str(e)}", exc_info=True)
            return Response({
                'error': 'An unexpected error occurred',
                'details': str(e)
            }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)


class PasswordResetRequestListView(APIView):
    permission_classes = [IsAuthenticated]

    def get(self, request):
        try:
            # Only admin and MLM members can view reset requests
            if request.user.role not in ['ADMIN', 'MLM_MEMBER']:
                return Response({
                    'error': 'Unauthorized access'
                }, status=status.HTTP_403_FORBIDDEN)

            # Query the reset requests
            queryset = PasswordResetRequest.objects.all()

            # Filter based on user role
            if request.user.role == 'MLM_MEMBER':
                # MLM members can only see their own requests
                queryset = queryset.filter(user=request.user)

            # Apply filters from query parameters
            status_filter = request.query_params.get('status')
            if status_filter:
                queryset = queryset.filter(status=status_filter.upper())

            # Order by most recent first
            queryset = queryset.select_related('user', 'processed_by').order_by('-requested_at')

            # Prepare the response data
            requests_data = []
            for reset_request in queryset:
                request_data = {
                    'id': reset_request.id,
                    'username': reset_request.user.username,
                    'email': reset_request.user.email,
                    'requested_at': reset_request.requested_at,
                    'status': reset_request.status,
                    'processed_at': reset_request.processed_at,
                }

                if reset_request.processed_by:
                    request_data['processed_by'] = {
                        'id': reset_request.processed_by.id,
                        'username': reset_request.processed_by.username,
                        'role': reset_request.processed_by.role
                    }

                requests_data.append(request_data)

            return Response(requests_data)

        except Exception as e:
            logger.error(f"Error fetching password reset requests: {str(e)}")
            return Response({
                'error': 'Failed to fetch password reset requests'
            }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

    def post(self, request, request_id=None):
        try:
            if request.user.role != 'ADMIN':
                return Response({
                    'error': 'Only admin can process reset requests'
                }, status=status.HTTP_403_FORBIDDEN)

            reset_request = get_object_or_404(PasswordResetRequest, id=request_id)
            action = request.data.get('action')

            if action not in ['approve', 'reject']:
                return Response({
                    'error': 'Invalid action. Must be either "approve" or "reject"'
                }, status=status.HTTP_400_BAD_REQUEST)

            if reset_request.status != 'PENDING':
                return Response({
                    'error': 'Can only process pending requests'
                }, status=status.HTTP_400_BAD_REQUEST)

            if action == 'approve':
                # Generate new password
                new_password = ''.join(random.choices(
                    string.ascii_letters + string.digits, k=12
                ))

                # Update user password
                user = reset_request.user
                user.set_password(new_password)
                user.save()

                # Send email to user
                try:
                    context = {
                        'username': user.username,
                        'new_password': new_password,
                        'login_url': f"{settings.FRONTEND_URL}/login"
                    }
                    
                    send_mail(
                        subject='Your Password Has Been Reset',
                        message=f'Your new password is: {new_password}',
                        from_email=settings.DEFAULT_FROM_EMAIL,
                        recipient_list=[user.email],
                        html_message=render_to_string('emails/password_reset_user.html', context),
                        fail_silently=True
                    )
                except Exception as e:
                    logger.error(f"Error sending password reset email: {str(e)}")

                reset_request.status = 'APPROVED'
                
            else:  # reject
                reset_request.status = 'REJECTED'

            reset_request.processed_at = timezone.now()
            reset_request.processed_by = request.user
            reset_request.save()

            # Create notification
            Notification.objects.create(
                title='Password Reset Request Processed',
                message=f'Your password reset request has been {action}d',
                notification_type='SYSTEM',
                recipient=reset_request.user.mlm_profile if hasattr(reset_request.user, 'mlm_profile') else None
            )

            return Response({
                'message': f'Password reset request {action}d successfully'
            })

        except PasswordResetRequest.DoesNotExist:
            return Response({
                'error': 'Reset request not found'
            }, status=status.HTTP_404_NOT_FOUND)
        except ValidationError as e:
            return Response({
                'error': str(e)
            }, status=status.HTTP_400_BAD_REQUEST)
        except Exception as e:
            logger.error(f"Error processing password reset request: {str(e)}")
            return Response({
                'error': 'Failed to process password reset request'
            }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

    def get_queryset(self):
        """Helper method to get filtered queryset"""
        queryset = PasswordResetRequest.objects.all().select_related(
            'user',
            'processed_by'
        )

        # Filter by status if provided
        status = self.request.query_params.get('status')
        if status:
            queryset = queryset.filter(status=status.upper())

        # Filter by date range if provided
        start_date = self.request.query_params.get('start_date')
        end_date = self.request.query_params.get('end_date')
        if start_date:
            queryset = queryset.filter(requested_at__date__gte=start_date)
        if end_date:
            queryset = queryset.filter(requested_at__date__lte=end_date)

        return queryset.order_by('-requested_at')
    




class CommissionActivationRequestViewSet(viewsets.ModelViewSet):
    serializer_class = CommissionActivationRequestSerializer
    permission_classes = [IsAuthenticated]
    
    def get_queryset(self):
        user = self.request.user
        
        if user.role == 'ADMIN':
            # Admin sees all requests
            return CommissionActivationRequest.objects.select_related(
                'requester__user', 
                'sponsor__user', 
                'current_position', 
                'target_position'
            ).all()
        
        if user.role == 'MLM_MEMBER':
            mlm_member = user.mlm_profile
            # MLM member sees their own requests and requests in their downline
            return CommissionActivationRequest.objects.select_related(
                'requester__user', 
                'sponsor__user', 
                'current_position', 
                'target_position'
            ).filter(
                Q(requester=mlm_member) | Q(sponsor=mlm_member)
            )
        
        return CommissionActivationRequest.objects.none()

    def create(self, request, *args, **kwargs):
        try:
            if request.user.role != 'MLM_MEMBER':
                return Response({
                    'error': 'Only MLM members can create commission activation requests'
                }, status=status.HTTP_403_FORBIDDEN)

            requester = request.user.mlm_profile
            
            # Create a new request directly without the serializer
            activation_request = CommissionActivationRequest.objects.create(
                requester=requester,
                sponsor=requester.sponsor,  # This can be None
                current_position=requester.position,
                target_position=Position.objects.filter(
                    can_earn_commission=True,
                    level_order__gt=requester.position.level_order
                ).first()
            )
            
            # Create notifications
            self.create_notifications(activation_request)
            
            # Return the created object using the serializer
            serializer = self.get_serializer(activation_request)
            return Response(serializer.data, status=status.HTTP_201_CREATED)
        
        except Exception as e:
            logger.error(f"Error creating commission activation request: {str(e)}")
            return Response({'error': str(e)}, status=status.HTTP_400_BAD_REQUEST)

    def create_notifications(self, request_instance):
        """
        Create notifications for sponsor and admin
        """
        try:
            # Notification for sponsor (if exists)
            if request_instance.sponsor:
                Notification.objects.create(
                    title='Commission Activation Request',
                    message=f'New commission activation request from {request_instance.requester.user.get_full_name()}',
                    notification_type='INDIVIDUAL',
                    recipient=request_instance.sponsor
                )

            # Notification for admin
            Notification.objects.create(
                title='Commission Activation Request',
                message=f'New commission activation request from {request_instance.requester.user.get_full_name()}',
                notification_type='GENERAL'
            )
        except Exception as e:
            logger.error(f"Error creating notifications: {str(e)}")

    @action(detail=True, methods=['POST'], permission_classes=[IsAdminUser])
    def process_request(self, request, pk=None):
        try:
            activation_request = self.get_object()
            status = request.data.get('status')
            reason = request.data.get('reason', '')

            if status not in ['APPROVED', 'REJECTED']:
                return Response({
                    'error': 'Invalid status'
                }, status=status.HTTP_400_BAD_REQUEST)

            # Use transaction to ensure atomic operation
            with transaction.atomic():
                # Update request
                activation_request.status = status
                activation_request.processed_by = request.user
                activation_request.processed_at = timezone.now()
                activation_request.reason = reason
                activation_request.save()

                # If approved, update requester's position
                if status == 'APPROVED':
                    requester = activation_request.requester
                    target_position = activation_request.target_position

                    # Update position
                    requester.position = target_position
                    requester.save()

                    # Create success notification
                    Notification.objects.create(
                        title='Commission Activation Approved',
                        message=f'Your commission activation request has been approved. Your new position is {target_position.name}',
                        notification_type='INDIVIDUAL',
                        recipient=requester
                    )

                # Create notification for requester
                Notification.objects.create(
                    title='Commission Activation Request Processed',
                    message=f'Your commission activation request has been {status.lower()}.',
                    notification_type='INDIVIDUAL',
                    recipient=activation_request.requester
                )

            return Response({
                'message': 'Request processed successfully',
                'status': activation_request.status
            })

        except Exception as e:
            logger.error(f"Error processing commission activation request: {str(e)}")
            return Response({
                'error': 'Failed to process commission activation request'
            }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
        


class QuixGoPickupAddressView(APIView):
    permission_classes = [IsAuthenticated]
    
    # def get(self, request):
    #     """Get all pickup addresses from QuixGo"""
    #     try:
    #         logger.info("Getting pickup addresses from QuixGo")
    #         service = QuixGoShippingService()
    #         result = service.get_pickup_addresses()
            
    #         logger.info(f"Pickup addresses result: {result}")
            
    #         if result['success']:
    #             return Response(result['addresses'])  # Return just the addresses array
    #         else:
    #             logger.error(f"Failed to fetch pickup addresses: {result.get('error')}")
    #             return Response({
    #                 'success': False,
    #                 'message': 'Failed to fetch pickup addresses',
    #                 'error': result.get('error')
    #             }, status=status.HTTP_400_BAD_REQUEST)
                
    #     except Exception as e:
    #         logger.error(f"Error fetching pickup addresses: {str(e)}", exc_info=True)
    #         return Response({
    #             'success': False,
    #             'message': 'An error occurred',
    #             'error': str(e)
    #         }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
    def get(self, request):
        """Get all pickup addresses from QuixGo and save to database"""
        try:
            logger.info("Getting pickup addresses from QuixGo")
            service = QuixGoShippingService()
            result = service.get_pickup_addresses()
            
            logger.info(f"Pickup addresses result: {result}")
            
            if result['success']:
                addresses = result['addresses']
                
                # Save addresses to database
                saved_addresses = self.save_addresses_to_db(addresses)
                
                # Return the saved addresses
                return Response(saved_addresses)
            else:
                logger.error(f"Failed to fetch pickup addresses: {result.get('error')}")
                
                # If API fails, return addresses from database as fallback
                db_addresses = PickupAddress.objects.filter(is_active=True)
                if db_addresses.exists():
                    serializer = PickupAddressSerializer(db_addresses, many=True)
                    return Response(serializer.data)
                
                return Response({
                    'success': False,
                    'message': 'Failed to fetch pickup addresses',
                    'error': result.get('error')
                }, status=status.HTTP_400_BAD_REQUEST)
                
        except Exception as e:
            logger.error(f"Error fetching pickup addresses: {str(e)}", exc_info=True)
            
            # If exception occurs, return addresses from database as fallback
            db_addresses = PickupAddress.objects.filter(is_active=True)
            if db_addresses.exists():
                serializer = PickupAddressSerializer(db_addresses, many=True)
                return Response(serializer.data)
            
            return Response({
                'success': False,
                'message': 'An error occurred',
                'error': str(e)
            }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
    
    def save_addresses_to_db(self, addresses):
        """
        Save QuixGo addresses to local database
        
        Args:
            addresses (list): List of address dictionaries from QuixGo
            
        Returns:
            list: Serialized address data
        """
        saved_addresses = []
        
        for addr in addresses:
            try:
                # Check if address already exists by addressId
                address_id = addr.get('addressId')
                
                # Map QuixGo fields to our model fields
                address_data = {
                    'name': addr.get('pickupName', ''),
                    'address_id': address_id,
                    'customer_id': addr.get('customerId', ''),
                    'contact_person': addr.get('cpPerson', ''),
                    'address_line1': addr.get('address1', ''),
                    'address_line2': addr.get('address2', ''),
                    'city': addr.get('city', ''),
                    'state': addr.get('state', ''),
                    'country': addr.get('country', 'India'),
                    'pincode': addr.get('pincode', ''),
                    'phone': addr.get('cpMobile', ''),
                    'alternate_phone': addr.get('alternateNumber', ''),
                    'email': addr.get('email', ''),
                    'landmark': addr.get('landmark', ''),
                    'address_type': addr.get('addressType', 'Office'),
                    'is_active': addr.get('isActive', True)
                }
                
                # Check if this is marked as a default address
                # You might need to adjust this based on QuixGo's response format
                is_default = False
                
                # Update or create the address
                db_address, created = PickupAddress.objects.update_or_create(
                    address_id=address_id,
                    defaults={**address_data, 'is_default': is_default}
                )
                
                # Serialize for response
                serializer = PickupAddressSerializer(db_address)
                saved_addresses.append(serializer.data)
                
                logger.info(f"{'Created' if created else 'Updated'} pickup address: {db_address.name}")
                
            except Exception as e:
                logger.error(f"Error saving pickup address: {str(e)}")
                # Continue with next address
        
        # If no address is set as default, set the first one
        default_exists = PickupAddress.objects.filter(is_default=True).exists()
        if not default_exists and saved_addresses:
            first_address = PickupAddress.objects.first()
            if first_address:
                first_address.is_default = True
                first_address.save()
                logger.info(f"Set {first_address.name} as default address")
                
                # Update the serialized data for the default address
                for i, addr in enumerate(saved_addresses):
                    if addr.get('id') == first_address.id:
                        saved_addresses[i]['is_default'] = True
                        break
        
        return saved_addresses
        
class PickupAddressViewSet(viewsets.ModelViewSet):
    queryset = PickupAddress.objects.all()
    serializer_class = PickupAddressSerializer
    permission_classes = [IsAuthenticated]
    
     
    def get(self, request):
        """Get all pickup addresses from QuixGo"""
        try:
            logger.info("Getting pickup addresses from QuixGo")
            service = QuixGoShippingService()
            result = service.get_pickup_addresses()
            
            logger.info(f"Pickup addresses result: {result}")
            
            if result['success']:
                return Response(result['addresses'])  # Return just the addresses array
            else:
                logger.error(f"Failed to fetch pickup addresses: {result.get('error')}")
                return Response({
                    'success': False,
                    'message': 'Failed to fetch pickup addresses',
                    'error': result.get('error')
                }, status=status.HTTP_400_BAD_REQUEST)
                    
        except Exception as e:
            logger.error(f"Error fetching pickup addresses: {str(e)}", exc_info=True)
            return Response({
                'success': False,
                'message': 'An error occurred',
                'error': str(e)
            }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
        
    # def create(self, request, *args, **kwargs):
    #     serializer = self.get_serializer(data=request.data)
    #     if serializer.is_valid():
    #         # Create address in QuixGo first
    #         shipping_service = QuixGoShippingService()
    #         response = shipping_service.create_pickup_address(serializer.validated_data)
            
    #         if response['success']:
    #             # Save the QuixGo address ID
    #             address = serializer.save(
    #                 address_id=response['address_id'],
    #                 customer_id=shipping_service.customer_id
    #             )
    #             return Response(self.get_serializer(address).data, status=status.HTTP_201_CREATED)
    #         else:
    #             return Response(
    #                 {'error': 'Failed to create pickup address in QuixGo', 'details': response['error']},
    #                 status=status.HTTP_400_BAD_REQUEST
    #             )
    #     return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

    # @action(detail=True, methods=['post'])
    # def set_default(self, request, pk=None):
    #     address = self.get_object()
    #     address.is_default = True
    #     address.save()  # This will unset any other defaults due to the model's save method
    #     return Response({'status': 'success', 'message': 'Default pickup address set'})

class ShipmentViewSet(viewsets.ModelViewSet):
    queryset = Shipment.objects.all()
    serializer_class = ShipmentSerializer
    permission_classes = [IsAuthenticated]
    
    def get_permissions(self):
        if self.action in ['create', 'update', 'partial_update', 'destroy']:
            self.permission_classes = [IsAdminUser]
        return super().get_permissions()
    
    def get_queryset(self):
        user = self.request.user
        if user.role == 'ADMIN':
            return Shipment.objects.all()
        else:
            return Shipment.objects.filter(order__user=user)
    def create(self, request, *args, **kwargs):
        serializer = self.get_serializer(data=request.data)
        if serializer.is_valid():
            # Get the order and pickup address
            order = get_object_or_404(Order, id=serializer.validated_data['order'].id)
            pickup_address = get_object_or_404(PickupAddress, id=serializer.validated_data['pickup_address'].id)
            
            from django.db import models
            # Calculate total quantity of items in the order
            total_quantity = order.items.aggregate(total=models.Sum('quantity'))['total'] or 1

            # Extract shipment data from request
            shipment_data = {
                'weight': serializer.validated_data.get('weight', 1.0),
                'length': serializer.validated_data.get('length', 10.0),
                'width': serializer.validated_data.get('width', 10.0),
                'height': serializer.validated_data.get('height', 10.0),
                'is_cod': serializer.validated_data.get('is_cod', False),
                'cod_amount': serializer.validated_data.get('cod_amount', 0.0),
                'courier': serializer.validated_data.get('courier_name', 'DTC'),
                'service_type': serializer.validated_data.get('service_type', 'SF'),
                'invoice_value': order.final_amount,
                'product_name': 'Order Products',
                'product_type': 'Nutritional supplements',
                'quantity': str(total_quantity),
                'order_number': order.order_number,
            }
            
            # Create delivery address from order shipping address  
            # shipping_address = order.shipping_address
            shipping_info = order.shipping_details
            delivery_address = {
                'name': order.user.get_full_name()  or 'Customer',
                'email': order.user.email or '',
                'mobile': order.user.phone_number or '',
                'address1': shipping_info.street_address,
                'address2': '',
                "landmark": '',
                'city': shipping_info.city,
                'state': shipping_info.state,
                'pincode': shipping_info.postal_code,
                'addressType': shipping_info.name or 'Home',
            }
            
            # Get QuixGo pickup address data (already registered)
            quixgo_pickup_address = {
                'addressId': pickup_address.address_id,
                'customerId': pickup_address.customer_id,
                'pickupName': pickup_address.name,
                'addressCategory': 'pickup',
                'addressType': pickup_address.address_type,
                'shipmentType': 'B2C',
                'cpPerson': pickup_address.contact_person,
                'address1': pickup_address.address_line1,
                'address2': pickup_address.address_line2,
                'city': pickup_address.city,
                'state': pickup_address.state,
                'country': pickup_address.country,
                'landmark': pickup_address.landmark,
                'pincode': pickup_address.pincode,
                'cpMobile': pickup_address.phone,
                'alternateNumber': pickup_address.alternate_phone,
                'email': pickup_address.email,
                'isActive': True,
                'isDeleted': False,
                'addName': f"{pickup_address.contact_person}-{pickup_address.pincode}-{pickup_address.customer_id}-{pickup_address.address_id}"
            }
            
            # Book shipment with QuixGo
            shipping_service = QuixGoShippingService()
            response = shipping_service.book_shipment(shipment_data, quixgo_pickup_address, delivery_address)
            
            if response['success']:
                # Save shipment details
                shipment = serializer.save(
                    awb_number=response['awb_number'],
                    shipment_id=response['shipment_id'],
                    courier_name=response['courier'],
                    shipping_charge=response['charge'],
                    status='BOOKED',
                    status_details={'booked_at': timezone.now().isoformat()}
                )
                
                # Create initial status update
                ShipmentStatusUpdate.objects.create(
                    shipment=shipment,
                    status='BOOKED',
                    status_details=f"Shipment booked with {response['courier']}",
                    timestamp=timezone.now()
                )
                
                # Update order status if needed
                order.status = 'SHIPPED'
                order.save()
                
                # return Response(self.get_serializer(shipment).data, status=status.HTTP_201_CREATED)
                return Response({
                    'success': True,
                    'message': 'Shipment created successfully',
                    'data': self.get_serializer(shipment).data
                }, status=status.HTTP_201_CREATED)
            else:
                return Response({
                    'success': False,
                    'message': 'Failed to book shipment',
                    'details': response['error']
                }, status=status.HTTP_400_BAD_REQUEST)
                # return Response(
                #     {'error': 'Failed to book shipment', 'details': response['error']},
                #     status=status.HTTP_400_BAD_REQUEST
                # )
        # return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
        return Response({
                'success': False,
                'message': 'Failed to book shipment',
                'details': response['error']
            }, status=status.HTTP_400_BAD_REQUEST)
        
    
    @action(detail=True, methods=['post'])
    def track(self, request, pk=None):
        """Track a shipment and update its status"""
        try:
            shipment = self.get_object()
            
            if not shipment.awb_number:
                return Response({
                    'success': False,
                    'message': 'No AWB number available for tracking'
                }, status=status.HTTP_400_BAD_REQUEST)
            
            # Initialize the shipping service
            shipping_service = QuixGoShippingService()
            
            # Call the tracking API
            tracking_response = shipping_service.track_shipment(shipment.awb_number)
            
            if tracking_response.get('success'):
                # Extract status information from the response
                current_status = tracking_response.get('current_status', 'Unknown')
                status_history = tracking_response.get('status_history', [])
                
                # Map QuixGo status to our status
                status_mapping = {
                    'Manifested': 'BOOKED',
                    'Picked Up': 'PICKED_UP',
                    'In Transit': 'IN_TRANSIT',
                    'Out For Delivery': 'OUT_FOR_DELIVERY',
                    'Delivered': 'DELIVERED',
                    'Undelivered': 'FAILED_DELIVERY',
                    'RTO': 'RETURNED',
                    'Cancelled': 'CANCELLED'
                }
                
                # Update the shipment status if we have a mapping for it
                if current_status in status_mapping:
                    shipment.status = status_mapping[current_status]
                
                # Update shipment details with tracking information
                shipment.status_details = {
                    'last_updated': timezone.now().isoformat(),
                    'quixgo_status': current_status,
                    'history': status_history,
                    'raw_data': tracking_response.get('raw_data')
                }
                shipment.save()
                
                # Create status update entries for each status in the history
                for status_entry in status_history:
                    # Extract timestamp from QuixGo status entry
                    timestamp = timezone.now()
                    if 'updateDate' in status_entry and status_entry['updateDate']:
                        try:
                            # Handle different date formats
                            date_str = status_entry['updateDate']
                            if 'T' in date_str:
                                # ISO format
                                if date_str.endswith('Z'):
                                    from datetime import datetime
                                    timestamp = datetime.strptime(date_str, '%Y-%m-%dT%H:%M:%S.%fZ')
                                else:
                                    from datetime import datetime
                                    timestamp = datetime.fromisoformat(date_str)
                            else:
                                # Standard format
                                from datetime import datetime
                                timestamp = datetime.strptime(date_str, '%Y-%m-%d %H:%M:%S')
                        except (ValueError, AttributeError) as e:
                            logger.warning(f"Failed to parse date '{status_entry['updateDate']}': {str(e)}")
                            # Fall back to current time
                    
                    status_name = status_entry.get('statusName', 'Unknown')
                    status_comment = status_entry.get('comment', '')
                    status_location = status_entry.get('location', '')
                    
                    # Check if this status update already exists to avoid duplicates
                    existing = ShipmentStatusUpdate.objects.filter(
                        shipment=shipment,
                        status=status_name,
                        status_details=status_comment
                    ).exists()
                    
                    if not existing:
                        ShipmentStatusUpdate.objects.create(
                            shipment=shipment,
                            status=status_name,
                            status_details=status_comment,
                            location=status_location,
                            timestamp=timestamp
                        )
                
                # Update order status if needed
                self.update_order_status(shipment)
                
                # Format status history for frontend response
                formatted_history = []
                for item in status_history:
                    formatted_item = {
                        'status': item.get('statusName', 'Unknown'),
                        'details': item.get('comment', ''),
                        'location': item.get('location', ''),
                        'timestamp': item.get('updateDate', '')
                    }
                    formatted_history.append(formatted_item)
                
                # Return a well-structured response for the frontend
                return Response({
                    'success': True,
                    'message': 'Shipment status updated successfully',
                    'status': shipment.status,
                    'current_status': current_status,
                    'status_history': formatted_history,
                    'last_updated': timezone.now().isoformat(),
                    'tracking_link': self.get_tracking_link(shipment)
                })
            else:
                # Log the error
                logger.error(f"Failed to track shipment: {tracking_response.get('error')}")
                
                # Return the error to the frontend
                return Response({
                    'success': False,
                    'message': f"Failed to track shipment: {tracking_response.get('error')}"
                }, status=status.HTTP_400_BAD_REQUEST)
        
        except Exception as e:
            # Log any exceptions
            logger.error(f"Error in track shipment action: {str(e)}", exc_info=True)
            
            # Return the error to the frontend
            return Response({
                'success': False,
                'message': f"Error tracking shipment: {str(e)}"
            }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
    
    @action(detail=True, methods=['post'])
    def cancel(self, request, pk=None):
        """Cancel a shipment"""
        shipment = self.get_object()
        
        if not shipment.awb_number:
            return Response(
                {'error': 'No AWB number available for cancellation'},
                status=status.HTTP_400_BAD_REQUEST
            )
        
        reason = request.data.get('reason', 'Order cancelled')
        
        shipping_service = QuixGoShippingService()
        response = shipping_service.cancel_shipment(shipment.awb_number, reason)
        
        if response['success']:
            # Update shipment status
            shipment.status = 'CANCELLED'
            shipment.is_cancelled = True
            shipment.status_details = {
                **shipment.status_details,
                'cancelled_at': timezone.now().isoformat(),
                'reason': reason
            }
            shipment.save()
            
            # Create status update
            ShipmentStatusUpdate.objects.create(
                shipment=shipment,
                status='CANCELLED',
                status_details=reason,
                timestamp=timezone.now()
            )
            
            return Response({
                'status': 'success',
                'message': 'Shipment cancelled successfully'
            })
        else:
            return Response(
                {'error': 'Failed to cancel shipment', 'details': response['error']},
                status=status.HTTP_400_BAD_REQUEST
            )
    
    def update_order_status(self, shipment):
        """Update the order status based on shipment status"""
        order = shipment.order
        
        if shipment.status == 'DELIVERED':
            order.status = 'DELIVERED'
            order.save()
        elif shipment.status == 'RETURNED':
            order.status = 'RETURNED'
            order.save()
        elif shipment.status == 'CANCELLED' and order.status != 'DELIVERED':
            order.status = 'CANCELLED'
            order.save()

class MLMMemberReportsView(APIView):
    permission_classes = [IsAuthenticated]

    def get(self, request):
        try:
            # Ensure the user is an MLM member
            if request.user.role != 'MLM_MEMBER':
                return Response({
                    'error': 'Unauthorized access'
                }, status=403)

            # Get the MLM member profile
            mlm_member = MLMMember.objects.get(user=request.user)

            # Get report type and filters
            report_type = request.query_params.get('type', '')
            start_date = request.query_params.get('start_date')
            end_date = request.query_params.get('end_date')
            period = request.query_params.get('period', 'monthly')

            # Base date filtering
            if start_date:
                start_date = timezone.datetime.strptime(start_date, '%Y-%m-%d').date()
            else:
                start_date = timezone.now().date() - timezone.timedelta(days=180)

            if end_date:
                end_date = timezone.datetime.strptime(end_date, '%Y-%m-%d').date()
            else:
                end_date = timezone.now().date()

            # Dispatch to specific report generation method
            if report_type == 'commissions':
                return self.generate_commissions_report(mlm_member, start_date, end_date)
            
            elif report_type == 'sales':
                return self.generate_sales_report(mlm_member, start_date, end_date, period)
            
            elif report_type == 'team_performance':
                return self.generate_team_performance_report(mlm_member, start_date, end_date)
            
            elif report_type == 'network_growth':
                return self.generate_network_growth_report(mlm_member, start_date, end_date, period)
            
            else:
                return Response({
                    'error': 'Invalid report type'
                }, status=400)

        except Exception as e:
            logger.error(f"MLM Member Reports Error: {str(e)}")
            return Response({
                'error': 'Failed to generate report'
            }, status=500)

    def generate_commissions_report(self, mlm_member, start_date, end_date):
        """
        Generate detailed commissions report for the MLM member
        """
        # Filter commissions
        commissions = Commission.objects.filter(
            member=mlm_member,
            date__date__gte=start_date,
            date__date__lte=end_date
        ).select_related('from_member__user')

        # Prepare report data
        report_data = [
            {
                'date': commission.date,
                'from_member_name': commission.from_member.user.get_full_name(),
                'level': commission.level,
                'amount': float(commission.amount),
                'is_paid': commission.is_paid
            }
            for commission in commissions
        ]

        return Response({
            'report_type': 'commissions',
            'data': report_data
        })

    def generate_sales_report(self, mlm_member, start_date, end_date, period='monthly'):
        """
        Generate personal sales report
        """
        # Filter orders for the member
        orders = Order.objects.filter(
            user=mlm_member.user,
            order_date__date__gte=start_date,
            order_date__date__lte=end_date,
            status__in=['CONFIRMED', 'SHIPPED', 'DELIVERED']
        )

        # Group by period
        if period == 'daily':
            period_func = TruncDay('order_date')
        elif period == 'weekly':
            period_func = TruncWeek('order_date')
        else:  # monthly
            period_func = TruncMonth('order_date')

        # Aggregate sales data
        sales_report = orders.annotate(
            period=period_func
        ).values('period').annotate(
            total_orders=Count('id'),
            total_revenue=Sum('final_amount'),
            total_bp=Sum('total_bp'),
            avg_order_value=Avg('final_amount')
        ).order_by('period')

        # Convert to list and format periods
        report_data = []
        for item in sales_report:
            formatted_item = {
                'period': self.format_period(item['period'], period),
                'total_orders': item['total_orders'],
                'total_revenue': float(item['total_revenue']),
                'total_bp': item['total_bp'],
                'avg_order_value': float(item['avg_order_value'])
            }
            report_data.append(formatted_item)

        # Calculate summary
        summary = {
            'total_revenue': float(orders.aggregate(total=Sum('final_amount'))['total'] or 0),
            'total_orders': orders.count(),
            'total_bp': orders.aggregate(total=Sum('total_bp'))['total'] or 0,
            'avg_order_value': float(orders.aggregate(avg=Avg('final_amount'))['avg'] or 0)
        }

        return Response({
            'report_type': 'sales',
            'data': report_data,
            'summary': summary
        })

    def generate_team_performance_report(self, mlm_member, start_date, end_date):
        """
        Generate team performance report by network levels
        """
        # Recursive function to get all downline members
        def get_downline_members(current_member, max_level=5):
            downline = {}
            
            def traverse(member, current_level=1):
                if current_level > max_level:
                    return
                
                # Get direct referrals
                referrals = MLMMember.objects.filter(sponsor=member)
                
                if current_level not in downline:
                    downline[current_level] = []
                
                for referral in referrals:
                    downline[current_level].append(referral)
                    traverse(referral, current_level + 1)
            
            traverse(current_member)
            return downline

        # Get downline members
        downline_members = get_downline_members(mlm_member)

        # Prepare report data
        report_data = []
        for level, members in downline_members.items():
            # Collect user IDs for this level
            member_ids = [m.user.id for m in members]
            
            # Calculate sales and commissions
            level_orders = Order.objects.filter(
                user_id__in=member_ids,
                order_date__date__gte=start_date,
                order_date__date__lte=end_date,
                status__in=['CONFIRMED', 'SHIPPED', 'DELIVERED']
            )
            
            # Calculate metrics
            level_data = {
                'level': level,
                'total_members': len(members),
                'total_sales': float(level_orders.aggregate(total=Sum('final_amount'))['total'] or 0),
                'total_commissions': float(Commission.objects.filter(
                    from_member__in=members,
                    date__date__gte=start_date,
                    date__date__lte=end_date
                ).aggregate(total=Sum('amount'))['total'] or 0),
                'total_bp': level_orders.aggregate(total=Sum('total_bp'))['total'] or 0
            }
            
            report_data.append(level_data)

        return Response({
            'report_type': 'team_performance',
            'data': report_data
        })

    def generate_network_growth_report(self, mlm_member, start_date, end_date, period='monthly'):
        """
        Generate network growth report
        """
        # Determine period grouping function
        if period == 'daily':
            period_func = TruncDay('join_date')
        elif period == 'weekly':
            period_func = TruncWeek('join_date')
        elif period == 'yearly':
            period_func = TruncYear('join_date')
        else:  # monthly
            period_func = TruncMonth('join_date')

        # Get all downline members recursively
        def get_all_downline(current_member):
            downline = set()
            
            def traverse(member):
                referrals = MLMMember.objects.filter(sponsor=member)
                for referral in referrals:
                    downline.add(referral)
                    traverse(referral)
            
            traverse(current_member)
            return downline

        # Get all downline members
        downline_members = get_all_downline(mlm_member)

        # Calculate network growth
        network_growth = MLMMember.objects.filter(
            sponsor=mlm_member,
            join_date__date__gte=start_date,
            join_date__date__lte=end_date
        ).annotate(
            period=period_func
        ).values('period').annotate(
            new_members=Count('id'),
            total_network_size=Count('id'),  # This will need refinement
            total_bp=Sum('total_bp')
        ).order_by('period')

        # Prepare report data
        report_data = []
        for item in network_growth:
            # Calculate total sales for new members in this period
            period_members = MLMMember.objects.filter(
                sponsor=mlm_member,
                join_date__date__gte=start_date,
                join_date__date__lte=end_date,
                period=item['period']
            )
            
            period_sales = Order.objects.filter(
                user__in=[m.user for m in period_members],
                order_date__date__gte=start_date,
                order_date__date__lte=end_date,
                status__in=['CONFIRMED', 'SHIPPED', 'DELIVERED']
            )

            formatted_item = {
                'period': self.format_period(item['period'], period),
                'new_members': item['new_members'],
                'total_network_size': item['total_network_size'],
                'total_bp': item['total_bp'],
                'total_sales': float(period_sales.aggregate(total=Sum('final_amount'))['total'] or 0)
            }
            report_data.append(formatted_item)

        return Response({
            'report_type': 'network_growth',
            'data': report_data
        })

    def format_period(self, period, period_type):
        """
        Format period based on period type
        """
        if period_type == 'daily':
            return period.strftime('%Y-%m-%d')
        elif period_type == 'weekly':
            return f"Week {period.strftime('%U')}, {period.year}"
        elif period_type == 'monthly':
            return period.strftime('%B %Y')
        elif period_type == 'yearly':
            return str(period.year)
        return str(period)

class LiveCommissionDashboardView(APIView):
    """
    API endpoint to show real-time commission calculations and forecasts 
    for MLM members based on current month performance
    """
    authentication_classes = [JWTAuthentication]
    permission_classes = [IsAuthenticated]
    
    def get(self, request):
        try:

            logger.info(f"User: {request.user.username}, Role: {request.user.role}")
            logger.info(f"Has MLM profile: {hasattr(request.user, 'mlm_profile')}")
            # Check if a specific member_id is requested (for admin users)
            member_id = request.query_params.get('member_id')
            
            # Determine which member's data to fetch
            if request.user.role == 'ADMIN' and member_id:
                # Admin can view any member's commissions
                try:
                    member = MLMMember.objects.get(member_id=member_id)
                except MLMMember.DoesNotExist:
                    return Response({
                        'status': False,
                        'message': f'Member with ID {member_id} not found'
                    }, status=status.HTTP_404_NOT_FOUND)
            elif request.user.role == 'MLM_MEMBER':
                # Member views their own commissions
                member = request.user.mlm_profile
            else:
                return Response({
                    'status': False,
                    'message': 'Only MLM members and admins can access this dashboard'
                }, status=status.HTTP_403_FORBIDDEN)
                
            # Check if the member has an active position that can earn commissions
            if not member.position.can_earn_commission:
                return Response({
                    'status': True,
                    'message': 'Your current position cannot earn commissions. Please upgrade to a higher position.',
                    'commission_data': {
                        'current_month_estimate': "0.00",
                        'last_month_earned': "0.00",
                        'total_pending': "0.00",
                        'level_breakdown': [],
                        'top_performers': [],
                        'recent_transactions': []
                    }
                })
                
            # Calculate current month, last month periods
            today = timezone.now()
            first_day_current_month = today.replace(day=1, hour=0, minute=0, second=0, microsecond=0)
            last_month_end = first_day_current_month - timedelta(days=1)
            first_day_last_month = last_month_end.replace(day=1, hour=0, minute=0, second=0, microsecond=0)
            
            # 1. Calculate last month's earned commissions
            last_month_earned = Commission.objects.filter(
                member=member,
                is_paid=True,
                date__gte=first_day_last_month,
                date__lt=first_day_current_month
            ).aggregate(total=Sum('amount'))['total'] or Decimal('0.00')
            
            # 2. Calculate total pending commissions
            total_pending = Commission.objects.filter(
                member=member,
                is_paid=False
            ).aggregate(total=Sum('amount'))['total'] or Decimal('0.00')
            
            # 3. Get downline members by level
            downline_by_level = self.get_downline_by_level(member)
            
            # 4. Calculate level breakdown using pure differential model
            level_breakdown, current_month_estimate = self.calculate_level_commission_differential(
                member, 
                downline_by_level
            )
            
            # 5. Get top performers
            top_performers = self.get_top_performers_differential(member, downline_by_level)
            
            # 6. Get recent transactions
            recent_transactions = self.get_recent_transactions_differential(member, downline_by_level)
            
            # Prepare response
            commission_data = {
                'current_month_estimate': str(current_month_estimate),
                'last_month_earned': str(last_month_earned),
                'total_pending': str(total_pending),
                'level_breakdown': level_breakdown,
                'top_performers': top_performers,
                'recent_transactions': recent_transactions
            }
            
            return Response({
                'status': True,
                'message': 'Live commission data retrieved successfully',
                'commission_data': commission_data,
                'next_calculation_date': first_day_current_month.replace(month=first_day_current_month.month+1 if first_day_current_month.month < 12 else 1, year=first_day_current_month.year if first_day_current_month.month < 12 else first_day_current_month.year+1).strftime('%Y-%m-%d'),
                'current_month': first_day_current_month.strftime('%B %Y')
            })
            
        except Exception as e:
            logger.error(f"Error in LiveCommissionDashboardView: {str(e)}")
            return Response({
                'status': False,
                'message': f'An error occurred while loading the commission dashboard: {str(e)}'
            }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
    
    def get_downline_by_level(self, member, max_level=5):
        """Get all downline members organized by level"""
        result = {}
        
        def traverse(current_member, level=1):
            if level > max_level:
                return
                
            # Get direct downline
            downline = MLMMember.objects.filter(
                sponsor=current_member,
                is_active=True
            ).select_related('user', 'position')
            
            if downline.exists():
                if level not in result:
                    result[level] = []
                    
                for downline_member in downline:
                    result[level].append({
                        'id': downline_member.id,
                        'member_id': downline_member.member_id,
                        'user_id': downline_member.user.id,
                        'position': downline_member.position,
                        'position_percentage': downline_member.position.discount_percentage,
                        'position_name': downline_member.position.name
                    })
                    
                    # Recursively get next level
                    traverse(downline_member, level + 1)
        
        traverse(member)
        return result
    
    def calculate_level_commission_differential(self, member, downline_data):
        """
        Calculate commission breakdown by level using pure differential model
        Commission is based solely on position percentage difference
        """
        level_breakdown = []
        current_month_estimate = Decimal('0.00')
        
        # Get current month orders
        today = timezone.now()
        first_day_current_month = today.replace(day=1, hour=0, minute=0, second=0, microsecond=0)
        
        current_month_orders = Order.objects.filter(
            order_date__gte=first_day_current_month,
            status__in=['CONFIRMED', 'SHIPPED', 'DELIVERED']
        )
        
        # Member's position percentage
        member_percentage = member.position.discount_percentage
        
        # Calculate level breakdown
        for level, members in downline_data.items():
            level_total_purchases = Decimal('0.00')
            level_total_commission = Decimal('0.00')
            downline_count = 0
            
            for downline_info in members:
                # Only consider downline with lower position percentage
                downline_percentage = downline_info['position_percentage']
                
                if member_percentage > downline_percentage:
                    # Calculate percentage difference
                    difference_percentage = member_percentage - downline_percentage
                    
                    # Get user's purchases
                    user_id = downline_info['user_id']
                    user_purchases = current_month_orders.filter(
                        user_id=user_id
                    ).aggregate(total=Sum('final_amount'))['total'] or Decimal('0.00')
                    
                    if user_purchases > 0:
                        # Calculate commission based on differential model
                        commission = (user_purchases * difference_percentage) / 100
                        
                        # Add to totals
                        level_total_purchases += user_purchases
                        level_total_commission += commission
                        downline_count += 1
            
            # Add level breakdown if there were qualifying purchases
            if level_total_purchases > 0:
                # Calculate effective commission rate for this level
                # This is just for display purposes - the actual calculation uses individual differences
                effective_rate = (level_total_commission / level_total_purchases) * 100
                
                level_breakdown.append({
                    'level': level,
                    'member_count': downline_count,
                    'total_purchases': str(level_total_purchases),
                    'commission_rate': str(effective_rate),  # Average effective rate
                    'estimated_commission': str(level_total_commission)
                })
                
                current_month_estimate += level_total_commission
        
        # Sort breakdown by level
        level_breakdown.sort(key=lambda x: x['level'])
        
        return level_breakdown, current_month_estimate
    
    def calculate_commission_differential(self, member, downline_member, purchase_amount):
        """
        Calculate commission based purely on position percentage difference
        """
        member_percentage = member.position.discount_percentage
        downline_percentage = downline_member['position_percentage']
        
        # Only calculate if member's percentage is higher
        if member_percentage <= downline_percentage:
            return Decimal('0.00')
        
        # Calculate difference percentage
        difference_percentage = member_percentage - downline_percentage
        
        # Calculate commission amount based on differential model
        commission_amount = (purchase_amount * difference_percentage) / 100
        
        return commission_amount
    
    def get_top_performers_differential(self, member, downline_by_level, limit=5):
        """Get top performing downline members using differential model"""
        try:
            # Flatten downline data
            all_downline = []
            for level, members in downline_by_level.items():
                for m in members:
                    m['level'] = level
                    all_downline.append(m)
            
            # Get user IDs
            user_ids = [m['user_id'] for m in all_downline]
            
            if not user_ids:
                return []
            
            # Get current month
            today = timezone.now()
            first_day_current_month = today.replace(day=1, hour=0, minute=0, second=0, microsecond=0)
            
            # Calculate purchases for each downline member
            user_purchases = {}
            
            current_month_orders = Order.objects.filter(
                user_id__in=user_ids,
                order_date__gte=first_day_current_month,
                status__in=['CONFIRMED', 'SHIPPED', 'DELIVERED']
            )
            
            for order in current_month_orders:
                if order.user_id not in user_purchases:
                    user_purchases[order.user_id] = Decimal('0.00')
                user_purchases[order.user_id] += order.final_amount
            
            # Calculate commissions based on differential model
            user_commissions = {}
            for user_id, purchase_amount in user_purchases.items():
                downline_info = next((m for m in all_downline if m['user_id'] == user_id), None)
                if downline_info:
                    # Calculate commission using differential model
                    commission = self.calculate_commission_differential(
                        member, 
                        downline_info, 
                        purchase_amount
                    )
                    user_commissions[user_id] = {
                        'purchase_amount': purchase_amount,
                        'commission': commission,
                        'downline_info': downline_info
                    }
            
            # Sort by commission amount (highest first)
            sorted_users = sorted(
                user_commissions.items(),
                key=lambda x: x[1]['commission'],
                reverse=True
            )[:limit]
            
            top_performers = []
            for user_id, data in sorted_users:
                if data['commission'] > 0:
                    # Get MLM member object to access full details
                    downline_member = MLMMember.objects.select_related('user', 'position').get(
                        id=data['downline_info']['id']
                    )
                    
                    top_performers.append({
                        'member_id': downline_member.member_id,
                        'name': f"{downline_member.user.first_name} {downline_member.user.last_name}",
                        'level': data['downline_info']['level'],
                        'position': downline_member.position.name,
                        'position_percentage': str(downline_member.position.discount_percentage),
                        'your_percentage': str(member.position.discount_percentage),
                        'difference': str(member.position.discount_percentage - downline_member.position.discount_percentage),
                        'total_purchases': str(data['purchase_amount']),
                        'your_commission': str(data['commission'])
                    })
            
            return top_performers
            
        except Exception as e:
            logger.error(f"Error getting top performers: {str(e)}")
            return []
    
    def get_recent_transactions_differential(self, member, downline_by_level, limit=10):
        """Get recent transactions from downline members using differential model"""
        try:
            # Flatten downline data
            all_downline = []
            for level, members in downline_by_level.items():
                for m in members:
                    m['level'] = level
                    all_downline.append(m)
            
            # Get user IDs
            user_ids = [m['user_id'] for m in all_downline]
            
            if not user_ids:
                return []
            
            # Get current month
            today = timezone.now()
            first_day_current_month = today.replace(day=1, hour=0, minute=0, second=0, microsecond=0)
            
            # Get recent orders
            recent_orders = Order.objects.filter(
                user_id__in=user_ids,
                order_date__gte=first_day_current_month,
                status__in=['CONFIRMED', 'SHIPPED', 'DELIVERED']
            ).select_related('user').order_by('-order_date')[:limit]
            
            transactions = []
            for order in recent_orders:
                # Find member details
                downline_info = next((m for m in all_downline if m['user_id'] == order.user.id), None)
                
                if downline_info:
                    # Calculate commission using differential model
                    commission_amount = self.calculate_commission_differential(
                        member,
                        downline_info,
                        order.final_amount
                    )
                    
                    # Only include transactions that generate commission
                    if commission_amount > 0:
                        transactions.append({
                            'date': order.order_date.isoformat(),
                            'member_name': f"{order.user.first_name} {order.user.last_name}",
                            'level': downline_info['level'],
                            'order_id': order.order_number,
                            'amount': str(order.final_amount),
                            'your_percentage': str(member.position.discount_percentage),
                            'their_percentage': str(downline_info['position_percentage']),
                            'difference': str(member.position.discount_percentage - downline_info['position_percentage']),
                            'your_commission': str(commission_amount)
                        })
            
            return transactions
            
        except Exception as e:
            logger.error(f"Error getting recent transactions: {str(e)}")
            return []           

class CommissionHistoryView(APIView):
    """
    API endpoint to view commission history for MLM members
    """
    authentication_classes = [JWTAuthentication]
    permission_classes = [IsAuthenticated]
    
    def get(self, request):
        try:
            # Ensure the user is an MLM member or admin
            if request.user.role != 'MLM_MEMBER' and request.user.role != 'ADMIN':
                return Response({
                    'status': False,
                    'message': 'Only MLM members and admins can access commission history'
                }, status=status.HTTP_403_FORBIDDEN)
                
            # Get query parameters
            year = request.query_params.get('year')
            month = request.query_params.get('month')
            member_id = request.query_params.get('member_id')
            
            # Parse year and month if provided
            if year:
                try:
                    year = int(year)
                except ValueError:
                    return Response({
                        'status': False,
                        'message': 'Invalid year format'
                    }, status=status.HTTP_400_BAD_REQUEST)
            
            if month:
                try:
                    month = int(month)
                    if month < 1 or month > 12:
                        raise ValueError("Month must be between 1 and 12")
                except ValueError as e:
                    return Response({
                        'status': False,
                        'message': str(e)
                    }, status=status.HTTP_400_BAD_REQUEST)
            
            # Determine which member's commissions to show
            target_member = None
            
            if request.user.role == 'MLM_MEMBER':
                # Regular members can only see their own commissions
                target_member = request.user.mlm_profile
            else:
                # Admins can see any member's commissions
                if member_id:
                    try:
                        target_member = MLMMember.objects.get(member_id=member_id)
                    except MLMMember.DoesNotExist:
                        return Response({
                            'status': False,
                            'message': 'Member not found'
                        }, status=status.HTTP_404_NOT_FOUND)
                else:
                    return Response({
                        'status': False,
                        'message': 'member_id is required for admin users'
                    }, status=status.HTTP_400_BAD_REQUEST)
            
            # Get commission history
            queryset = Commission.objects.filter(member=target_member)
            
            # Apply year and month filters if provided
            if year and month:
                # Filter for specific month
                start_date = datetime(year, month, 1)
                if month == 12:
                    end_date = datetime(year + 1, 1, 1)
                else:
                    end_date = datetime(year, month + 1, 1)
                
                queryset = queryset.filter(date__gte=start_date, date__lt=end_date)
            elif year:
                # Filter for entire year
                start_date = datetime(year, 1, 1)
                end_date = datetime(year + 1, 1, 1)
                queryset = queryset.filter(date__gte=start_date, date__lt=end_date)
            
            # Get summary statistics
            summary = {
                'total_earned': Decimal('0.00'),
                'total_paid': Decimal('0.00'),
                'total_pending': Decimal('0.00')
            }
            
            summary_data = queryset.aggregate(
                total_earned=Sum('amount'),
                total_paid=Sum('amount', filter=Q(is_paid=True)),
                total_pending=Sum('amount', filter=Q(is_paid=False))
            )
            
            if summary_data['total_earned']:
                summary['total_earned'] = summary_data['total_earned']
            if summary_data['total_paid']:
                summary['total_paid'] = summary_data['total_paid']
            if summary_data['total_pending']:
                summary['total_pending'] = summary_data['total_pending']
            
            # Get detailed commission records
            commissions = queryset.select_related('from_member', 'from_member__user').order_by('-date')
            
            # Paginate results if needed
            page = int(request.query_params.get('page', 1))
            page_size = int(request.query_params.get('page_size', 20))
            start_idx = (page - 1) * page_size
            end_idx = start_idx + page_size
            
            # Prepare response data
            commission_data = []
            
            for commission in commissions[start_idx:end_idx]:
                from_member_name = f"{commission.from_member.user.first_name} {commission.from_member.user.last_name}"
                if not from_member_name.strip():
                    from_member_name = commission.from_member.member_id
                
                commission_data.append({
                    'id': commission.id,
                    'date': commission.date,
                    'amount': float(commission.amount),
                    'is_paid': commission.is_paid,
                    'payment_date': commission.payment_date,
                    'from_member': {
                        'member_id': commission.from_member.member_id,
                        'name': from_member_name
                    },
                    'commission_type': commission.commission_type if hasattr(commission, 'commission_type') else 'MONTHLY',
                    'level': commission.level,
                    'is_first_purchase_bonus': commission.is_first_purchase_bonus
                })
            
            response_data = {
                'status': True,
                'summary': {
                    'total_earned': float(summary['total_earned']),
                    'total_paid': float(summary['total_paid']),
                    'total_pending': float(summary['total_pending'])
                },
                'pagination': {
                    'page': page,
                    'page_size': page_size,
                    'total_records': commissions.count(),
                    'total_pages': (commissions.count() + page_size - 1) // page_size
                },
                'commissions': commission_data
            }
            
            return Response(response_data)
            
        except Exception as e:
            logger.error(f"Error in CommissionHistoryView: {str(e)}")
            return Response({
                'status': False,
                'message': 'An error occurred while retrieving commission history',
                'error': str(e)
            }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)


class CalculateCommissionsView(APIView):
    """
    API endpoint for admin to manually trigger commission calculations
    """
    authentication_classes = [JWTAuthentication]
    permission_classes = [IsAdminUser]
    
    def post(self, request):
        try:
            # Check if this is a forced calculation (override date check)
            force = request.data.get('force', False)
            
            # Get the target date for calculation (default to today)
            calculation_date_str = request.data.get('calculation_date')
            if calculation_date_str:
                try:
                    calculation_date = datetime.strptime(calculation_date_str, '%Y-%m-%d')
                except ValueError:
                    return Response({
                        'status': False,
                        'message': 'Invalid date format. Use YYYY-MM-DD'
                    }, status=status.HTTP_400_BAD_REQUEST)
            else:
                calculation_date = timezone.now()
            
            # Only allow calculation on the 1st of the month unless forced
            if not force and calculation_date.day != 1:
                return Response({
                    'status': False,
                    'message': f'Commission calculations should only be run on the 1st of the month. Today is the {calculation_date.day}rd. Use "force=true" to override.'
                }, status=status.HTTP_400_BAD_REQUEST)
            
            # Run the calculation
            result = calculate_monthly_commissions()
            
            if result:
                return Response({
                    'status': True,
                    'message': 'Monthly commission calculation completed successfully'
                })
            else:
                return Response({
                    'status': False,
                    'message': 'Monthly commission calculation failed or was skipped'
                }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
                
        except Exception as e:
            logger.error(f"Error in CalculateCommissionsView: {str(e)}")
            return Response({
                'status': False,
                'message': 'An error occurred while calculating commissions',
                'error': str(e)
            }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
        

class ShippingConfigView(APIView):
    permission_classes = [IsAdminUser]

    def post(self, request):
        """Save shipping configuration and attempt login"""
        serializer = ShippingConfigSerializer(data=request.data)
        
        if serializer.is_valid():
            try:
                # Attempt login to QuixGo
                response = requests.post(
                    'https://dev.api.quixgo.com/clientApi/login', 
                    json={
                        'email': serializer.validated_data['email'],
                        'password': serializer.validated_data['password']
                    }
                )
                
                if response.status_code == 200:
                    login_data = response.json()
                    
                    # Create or update shipping config
                    config, created = ShippingConfig.objects.update_or_create(
                        email=serializer.validated_data['email'],
                        defaults={
                            'password': serializer.validated_data['password'],
                            'customer_id': login_data.get('annotation_id'),
                            'access_token': login_data.get('token'),
                            'token_expiry': timezone.now() + timedelta(hours=10),
                            'first_name': login_data.get('firstName'),
                            'last_name': login_data.get('lastName'),
                            'mobile': login_data.get('mobile')
                        }
                    )
                    
                    return Response({
                        'success': True,
                        'message': 'Configuration saved and authenticated',
                        'customer_id': config.customer_id,
                        'config': config

                    })
                else:
                    return Response({
                        'success': False,
                        'message': 'Authentication failed'
                    }, status=status.HTTP_400_BAD_REQUEST)
            
            except Exception as e:
                return Response({
                    'success': False,
                    'message': str(e)
                }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
        
        return Response({
            'success': False,
            'errors': serializer.errors
        }, status=status.HTTP_400_BAD_REQUEST)

    def get(self, request):
        """Retrieve shipping configuration"""
        try:
            config = ShippingConfig.objects.get(email=request.user.email)
            serializer = ShippingConfigSerializer(config)
            return Response(serializer.data)
        except ShippingConfig.DoesNotExist:
            return Response({
                'success': False,
                'message': 'No shipping configuration found'
            }, status=status.HTTP_404_NOT_FOUND)

class PickupAddressListView(APIView):
    permission_classes = [IsAdminUser]
    
    def get(self, request):
        """Get all pickup addresses from QuixGo"""
        try:
            service = QuixGoShippingService()
            result = service.get_pickup_addresses()
            
            if result['success']:
                return Response({
                    'success': True,
                    'addresses': result['addresses']
                })
            else:
                return Response({
                    'success': False,
                    'message': 'Failed to fetch pickup addresses',
                    'error': result.get('error')
                }, status=status.HTTP_400_BAD_REQUEST)
                
        except Exception as e:
            logger.error(f"Error fetching pickup addresses: {str(e)}")
            return Response({
                'success': False,
                'message': 'An error occurred',
                'error': str(e)
            }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
        

# class ShipmentViewSet(viewsets.ModelViewSet):
#     queryset = Shipment.objects.all()
#     serializer_class = ShipmentSerializer
#     permission_classes = [IsAuthenticated]
    
#     def get_permissions(self):
#         """Set permissions based on action"""
#         if self.action in ['create', 'update', 'partial_update', 'destroy', 'cancel']:
#             return [IsAdminUser()]
#         return super().get_permissions()
    
#     def get_queryset(self):
#         """Filter shipments based on user role"""
#         user = self.request.user
#         if user.role == 'ADMIN':
#             queryset = Shipment.objects.all()
#         else:
#             queryset = Shipment.objects.filter(order__user=user)
            
#         # Apply filters
#         status_filter = self.request.query_params.get('status')
#         if status_filter:
#             queryset = queryset.filter(status=status_filter)
            
#         order_id = self.request.query_params.get('order_id')
#         if order_id:
#             queryset = queryset.filter(order_id=order_id)
            
#         return queryset.order_by('-created_at')

#     def create(self, request):
#         """Book a shipment"""
#         serializer = ShipmentSerializer(data=request.data)
        
#         if serializer.is_valid():
#             try:
#                 # Get shipping config
#                 config = ShippingConfig.objects.get(email=request.user.email)
                
#                 # Get order and pickup address
#                 order = serializer.validated_data.get('order')
#                 pickup_address = serializer.validated_data.get('pickup_address')
                
#                 # Prepare payload for QuixGo
#                 payload = [{
#                     "deliveryAddress": {
#                         "name": order.user.get_full_name(),
#                         "address1": order.shipping_address,
#                         "city": order.shipping_city,
#                         "state": order.shipping_state,
#                         "pincode": order.shipping_pincode,
#                         "mobile": order.user.phone_number,
#                         "addressType": "Home"
#                     },
#                     "pickupAddress": {
#                         "addressId": pickup_address.address_id,
#                         "customerId": config.customer_id,
#                         "addressType": pickup_address.address_type,
#                         "cpPerson": pickup_address.contact_person,
#                         "address1": pickup_address.address_line1,
#                         "city": pickup_address.city,
#                         "state": pickup_address.state,
#                         "pincode": pickup_address.pincode,
#                         "cpMobile": pickup_address.phone
#                     },
#                     "productDetails": {
#                         "weight": str(serializer.validated_data.get('weight', 1)),
#                         "invoice": str(int(order.final_amount)),
#                         "productName": "Order Products",
#                         "quantity": "1",
#                         "orderNumber": order.order_number
#                     },
#                     "serviceProvider": config.default_courier,
#                     "serviceType": config.default_service_type,
#                     "paymentMode": "COD" if order.orderType == "COD" else "Prepaid",
#                     "customerId": config.customer_id,
#                     "insuranceCharge": 0,
#                     "bookingChannel": "web"
#                 }]
                
#                 # Send request to QuixGo
#                 response = requests.post(
#                     'https://api.quixgo.com/clientApi/v2/bookShipment',
#                     headers={
#                         'Content-Type': 'application/json',
#                         'Authorization': config.access_token
#                     },
#                     json=payload
#                 )
                
#                 if response.status_code == 200:
#                     # Process response and save shipment
#                     quixgo_response = response.json()[0]
#                     shipment = serializer.save(
#                         awb_number=quixgo_response.get('awbNumber'),
#                         courier_name=quixgo_response.get('shipmentPartner'),
#                         shipping_charge=quixgo_response.get('finalCharge')
#                     )
                    
#                     return Response({
#                         'success': True,
#                         'data': ShipmentSerializer(shipment).data
#                     }, status=status.HTTP_201_CREATED)
#                 else:
#                     return Response({
#                         'success': False,
#                         'message': 'Failed to book shipment'
#                     }, status=status.HTTP_400_BAD_REQUEST)
            
#             except ShippingConfig.DoesNotExist:
#                 return Response({
#                     'success': False,
#                     'message': 'No shipping configuration found'
#                 }, status=status.HTTP_400_BAD_REQUEST)
        
#         return Response({
#             'success': False,
#             'errors': serializer.errors
#         }, status=status.HTTP_400_BAD_REQUEST)

#     @action(detail=True, methods=['post'])
#     def track(self, request, pk=None):
#         """Track a shipment and update its status"""
#         shipment = self.get_object()
        
#         if not shipment.awb_number:
#             return Response({
#                 'success': False,
#                 'message': 'No AWB number available for tracking'
#             }, status=status.HTTP_400_BAD_REQUEST)
        
#         shipping_service = QuixGoShippingService()
#         quixgo_response = shipping_service.track_shipment(shipment.awb_number)
        
#         if quixgo_response.get('success'):
#             # Update shipment status
#             current_status = quixgo_response.get('current_status')
            
#             # Map QuixGo status to our status
#             status_mapping = {
#                 'Booked': 'BOOKED',
#                 'Picked Up': 'PICKED_UP',
#                 'In Transit': 'IN_TRANSIT',
#                 'Out For Delivery': 'OUT_FOR_DELIVERY',
#                 'Delivered': 'DELIVERED',
#                 'Undelivered': 'FAILED_DELIVERY',
#                 'RTO': 'RETURNED',
#                 'Cancelled': 'CANCELLED'
#             }
            
#             # Update status if it exists in our mapping
#             if current_status in status_mapping:
#                 shipment.status = status_mapping[current_status]
            
#             # Update status details
#             shipment.status_details = {
#                 'last_updated': timezone.now().isoformat(),
#                 'quixgo_status': current_status,
#                 'history': quixgo_response.get('status_history', [])
#             }
#             shipment.save()
            
#             # Create status update entries for each new status
#             status_history = quixgo_response.get('status_history', [])
#             for status_entry in status_history:
#                 # Get status timestamp if available
#                 timestamp = timezone.now()
#                 if 'updateDate' in status_entry and status_entry['updateDate']:
#                     try:
#                         timestamp = datetime.fromisoformat(status_entry['updateDate'].replace('Z', '+00:00'))
#                     except (ValueError, AttributeError):
#                         pass
                
#                 # Create status update if it doesn't exist already
#                 status_name = status_entry.get('statusName', 'Unknown')
                
#                 # Skip if we already have this status update
#                 existing_status = ShipmentStatusUpdate.objects.filter(
#                     shipment=shipment,
#                     status=status_name,
#                     timestamp=timestamp
#                 ).exists()
                
#                 if not existing_status:
#                     ShipmentStatusUpdate.objects.create(
#                         shipment=shipment,
#                         status=status_name,
#                         status_details=status_entry.get('comment', ''),
#                         location=status_entry.get('location', ''),
#                         timestamp=timestamp
#                     )
            
#             # Update order status if needed
#             self.update_order_status(shipment)
            
#             return Response({
#                 'success': True,
#                 'message': 'Shipment status updated',
#                 'status': shipment.status,
#                 'status_history': quixgo_response.get('status_history', [])
#             })
#         else:
#             return Response({
#                 'success': False,
#                 'message': 'Failed to track shipment',
#                 'error': quixgo_response.get('error')
#             }, status=status.HTTP_400_BAD_REQUEST)
    
#     @action(detail=True, methods=['post'])
#     def cancel(self, request, pk=None):
#         """Cancel a shipment"""
#         shipment = self.get_object()
        
#         if not shipment.awb_number:
#             return Response({
#                 'success': False,
#                 'message': 'No AWB number available for cancellation'
#             }, status=status.HTTP_400_BAD_REQUEST)
        
#         reason = request.data.get('reason', 'Order cancelled')
        
#         shipping_service = QuixGoShippingService()
#         quixgo_response = shipping_service.cancel_shipment(shipment.awb_number, reason)
        
#         if quixgo_response.get('success'):
#             # Update shipment status
#             shipment.status = 'CANCELLED'
#             shipment.is_cancelled = True
#             shipment.status_details = {
#                 **shipment.status_details,
#                 'cancelled_at': timezone.now().isoformat(),
#                 'reason': reason
#             }
#             shipment.save()
            
#             # Create status update
#             ShipmentStatusUpdate.objects.create(
#                 shipment=shipment,
#                 status='CANCELLED',
#                 status_details=reason,
#                 timestamp=timezone.now()
#             )
            
#             # Update order status
#             order = shipment.order
#             if order.status not in ['DELIVERED', 'CANCELLED']:
#                 order.status = 'CANCELLED'
#                 order.save()
            
#             return Response({
#                 'success': True,
#                 'message': 'Shipment cancelled successfully'
#             })
#         else:
#             return Response({
#                 'success': False,
#                 'message': 'Failed to cancel shipment',
#                 'error': quixgo_response.get('error')
#             }, status=status.HTTP_400_BAD_REQUEST)
    
#     def update_order_status(self, shipment):
#         """Update the order status based on shipment status"""
#         order = shipment.order
        
#         if shipment.status == 'DELIVERED':
#             order.status = 'DELIVERED'
#             order.save()
#         elif shipment.status == 'RETURNED':
#             order.status = 'RETURNED'
#             order.save()
#         elif shipment.status == 'CANCELLED' and order.status != 'DELIVERED':
#             order.status = 'CANCELLED'
#             order.save()

class OrderShippingView(APIView):
    """
    API endpoint for customers to view their order's shipping details
    """
    permission_classes = [IsAuthenticated]
    
    def get(self, request, order_id):
        """Get shipping information for an order"""
        try:
            # Get the order (ensure it belongs to the current user unless admin)
            if request.user.role == 'ADMIN':
                order = get_object_or_404(Order, id=order_id)
            else:
                order = get_object_or_404(Order, id=order_id, user=request.user)
            
            # Get shipments for this order
            shipments = Shipment.objects.filter(order=order)
            
            if not shipments.exists():
                return Response({
                    'success': True,
                    'message': 'No shipping information available for this order',
                    'order_status': order.status,
                    'shipments': []
                })
            
            # Get detailed shipment information
            shipment_data = []
            for shipment in shipments:
                # Get status updates
                status_updates = ShipmentStatusUpdate.objects.filter(
                    shipment=shipment
                ).order_by('-timestamp')
                
                shipment_info = {
                    'id': shipment.id,
                    'shipment_id': shipment.shipment_id,
                    'awb_number': shipment.awb_number,
                    'courier': shipment.courier_name,
                    'status': shipment.status,
                    'tracking_url': shipment.tracking_url,
                    'created_at': shipment.created_at,
                    'status_updates': [
                        {
                            'status': update.status,
                            'details': update.status_details,
                            'location': update.location,
                            'timestamp': update.timestamp
                        }
                        for update in status_updates
                    ]
                }
                
                shipment_data.append(shipment_info)
            
            return Response({
                'success': True,
                'order_id': order.id,
                'order_number': order.order_number,
                'order_status': order.status,
                'shipments': shipment_data
            })
            
        except Exception as e:
            logger.error(f"Error getting order shipping details: {str(e)}")
            return Response({
                'success': False,
                'message': 'Error retrieving shipping information',
                'error': str(e)
            }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)


class ShippingDashboardView(APIView):
    """
    API endpoint for admins to get shipping dashboard statistics
    """
    permission_classes = [IsAdminUser]
    
    def get(self, request):
        """Get shipping statistics for the dashboard"""
        try:
            # Get counts by status
            status_counts = Shipment.objects.values('status').annotate(count=Count('id'))
            status_stats = {item['status']: item['count'] for item in status_counts}
            
            # Get courier distribution
            courier_counts = Shipment.objects.values('courier_name').annotate(count=Count('id'))
            courier_stats = {item['courier_name']: item['count'] for item in courier_counts}
            
            # Get recent shipments
            recent_shipments = Shipment.objects.select_related('order').order_by('-created_at')[:10]
            recent_data = []
            
            for shipment in recent_shipments:
                recent_data.append({
                    'id': shipment.id,
                    'awb_number': shipment.awb_number,
                    'order_number': shipment.order.order_number,
                    'courier': shipment.courier_name,
                    'status': shipment.status,
                    'created_at': shipment.created_at
                })
            
            # Get pending shipment orders (orders that are confirmed but not shipped yet)
            pending_orders = Order.objects.filter(
                status='CONFIRMED'
            ).exclude(
                id__in=Shipment.objects.values('order_id')
            ).order_by('-order_date')[:10]
            
            pending_data = []
            # for order in pending_orders:
            #     pending_data.append({
            #         'id': order.id,
            #         'order_number': order.order_number,
            #         'order_date': order.order_date,
            #         'user_name': order.user.get_full_name(),
            #         'amount': float(order.final_amount),
                    
            #     })
            for order in pending_orders:
                # Collect order items details
                items_data = []
                for item in order.items.all():
                    items_data.append({
                        'id': item.id,
                        'product_id': item.product.id,
                        'product_name': item.product.name,
                        'quantity': item.quantity,
                        'price': float(item.price),
                        'discount_percentage': float(item.discount_percentage),
                        'discount_amount': float(item.discount_amount),
                        'final_price': float(item.final_price),
                        'gst_amount': float(item.gst_amount),
                        'bp_points': item.bp_points
                    })
                
                # Build full order details
                pending_data.append({
                    'id': order.id,
                    'order_number': order.order_number,
                    'order_date': order.order_date,
                    'status': order.status,
                    'user': {
                        'id': order.user.id,
                        'name': order.user.get_full_name(),
                        'email': order.user.email,
                        'phone_number': order.user.phone_number
                    },
                    'financial_details': {
                        'total_amount': float(order.total_amount),
                        'discount_amount': float(order.discount_amount),
                        'final_amount': float(order.final_amount),
                        'discount_percentage': float(order.discount_percentage)
                    },
                    'shipping_details': {
                        'shipping_address': order.shipping_address,
                        'billing_address': order.billing_address
                    },
                    'bp_details': {
                        'total_bp': order.total_bp,
                        'bp_processed': order.bp_processed
                    },
                    'payment_details': {
                        'razorpay_order_id': order.razorpay_order_id,
                        'payment_id': order.payment_id,
                        'order_type': order.orderType
                    },
                    'items': items_data
                })
            
            return Response({
                'success': True,
                'status_stats': status_stats,
                'courier_stats': courier_stats,
                'recent_shipments': recent_data,
                'pending_orders': pending_data
            })
            
        except Exception as e:
            logger.error(f"Error getting shipping dashboard stats: {str(e)}")
            return Response({
                'success': False,
                'message': 'Error retrieving shipping statistics',
                'error': str(e)
            }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)


@api_view(['POST'])
@permission_classes([IsAdminUser])
def test_shipping_connection(request):
    """Test connection to QuixGo API"""
    try:
        # Try to login with provided credentials
        shipping_service = QuixGoShippingService()
        result = shipping_service.login()

        if result:
            return Response({
                'success': True,
                'message': 'Successfully connected to QuixGo API',
                'customer_id': shipping_service.customer_id
            })
        else:
            return Response({
                'success': False,
                'error': 'Authentication failed'
            }, status=status.HTTP_400_BAD_REQUEST)
    
    except Exception as e:
        logger.error(f"Connection test error: {str(e)}")
        return Response({
            'success': False,
            'error': str(e)
        }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)



class CheckQuixGoTokenView(APIView):
    """Check if the QuixGo token is valid and not expired"""
    permission_classes = [IsAdminUser]
    
    def get(self, request):
        try:
            shipping_service = QuixGoShippingService()
            is_valid = not shipping_service.is_token_expired()
            
            return Response({
                'valid': is_valid
            })
        except Exception as e:
            logger.error(f"Error checking token validity: {str(e)}")
            return Response({
                'valid': False,
                'error': str(e)
            }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)


class RefreshQuixGoTokenView(APIView):
    """Force refresh of the QuixGo token"""
    permission_classes = [IsAdminUser]
    
    def post(self, request):
        try:
            shipping_service = QuixGoShippingService()
            success = shipping_service.login()
            
            if success:
                return Response({
                    'success': True,
                    'message': 'Token refreshed successfully'
                })
            else:
                return Response({
                    'success': False,
                    'message': 'Failed to refresh token'
                }, status=status.HTTP_400_BAD_REQUEST)
        except Exception as e:
            logger.error(f"Error refreshing token: {str(e)}")
            return Response({
                'success': False,
                'message': f'Error refreshing token: {str(e)}'
            }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)