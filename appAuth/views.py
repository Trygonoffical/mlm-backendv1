import requests
import logging
import uuid
from rest_framework import serializers
from rest_framework import status
from rest_framework.views import APIView
from rest_framework.response import Response
from django.conf import settings
from home.models import PhoneOTP, User , HomeSlider , Category , Product , ProductImage , Position , MLMMember , Commission , WalletTransaction , Testimonial , Advertisement , SuccessStory , CustomerPickReview , CompanyInfo , About , HomeSection , HomeSectionType , Menu , CustomPage , KYCDocument , Blog , Address , Order , OrderItem ,  Wallet, WalletTransaction, WithdrawalRequest, BankDetails , Notification , Contact , Newsletter
from django.shortcuts import get_object_or_404
import random
from django.views.decorators.csrf import csrf_exempt
from django.utils.decorators import method_decorator
from rest_framework.permissions import AllowAny , IsAdminUser
from django.utils import timezone
from datetime import timedelta
from .serializers import UserSerializer 
from home.serializers import CategorySerializer , ProductSerializer , PositionSerializer  , MLMMemberSerializer , MLMMemberListSerializer , TestimonialSerializer , AdvertisementSerializer , SuccessStorySerializer , CustomerPickSerializer , CompanyInfoSerializer , AboutSerializer , HomeSectionSerializer , MenuSerializer , CustomPageSerializer , KYCDocumentSerializer , BlogSerializer , AddressSerializer , CustomerProfileSerializer , OrderSerializer , WithdrawalRequestSerializer , WalletTransactionSerializer , WalletSerializer , BankDetailsSerializer , BankDetailsSerializerNew , NotificationSerializer , MLMMemberRegistrationSerializer , ContactSerializer , NewsletterSerializer
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

            # Generate 6 digit OTP
            otp = str(random.randint(100000, 999999))

            # Save or update OTP
            phone_otp, created = PhoneOTP.objects.get_or_create(
                phone_number=phone_number,
                defaults={'otp': otp}
            )

            if not created:
                # Check if blocked period has expired
                phone_otp.reset_if_expired()
                
                # Check if still blocked
                if phone_otp.is_blocked():
                    minutes_left = 30 - ((timezone.now() - phone_otp.last_attempt).seconds // 60)
                    return Response({
                        'status': False,
                        'message': f'Maximum OTP attempts reached. Please try again after {minutes_left} minutes.'
                    }, status=status.HTTP_400_BAD_REQUEST)

                phone_otp.otp = otp
                phone_otp.is_verified = False
                phone_otp.count += 1
                phone_otp.save()

            # Send OTP via SMS
            success, message = send_otp_sms(phone_number, otp)

            if success:
                return Response({
                    'status': True,
                    'message': 'OTP sent successfully',
                    'attempts_left': 5 - phone_otp.count,
                    'otp': otp  # Remove in production
                })
            else:
                return Response({
                    'status': False,
                    'message': f'Failed to send OTP: {message}'
                }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

        except Exception as e:
            logger.error(f"Error in GenerateOTP: {str(e)}")
            return Response({
                'status': False,
                'message': 'Internal server error'
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
        refresh_token = request.data.get('refresh')
        
        if not refresh_token:
            return Response({
                'status': False,
                'message': 'Refresh token is required'
            }, status=status.HTTP_400_BAD_REQUEST)
            
        try:
            refresh = RefreshToken(refresh_token)
            
            return Response({
                'status': True,
                'message': 'Token refreshed successfully',
                'token': str(refresh.access_token)
            })
            
        except Exception as e:
            return Response({
                'status': False,
                'message': 'Invalid refresh token'
            }, status=status.HTTP_401_UNAUTHORIZED)
        

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

    def get_queryset(self):
        return MLMMember.objects.select_related(
            'user', 
            'position', 
            'sponsor', 
            'sponsor__user'
        ).prefetch_related(
            'earned_commissions',
            'generated_commissions',
            'user__wallet__transactions'
        ).all()

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
    

# class HomeSectionViewSet(viewsets.ModelViewSet):
#     queryset = HomeSection.objects.all()
#     serializer_class = HomeSectionSerializer
#     authentication_classes = [JWTAuthentication]
#     permission_classes = [IsAuthenticated]

#     def get_permissions(self):
#         if self.request.method == 'GET':
#             return [AllowAny()]
#         return [IsAdminUser()]

#     def get_queryset(self):
#         queryset = HomeSection.objects.all()
#         section_type = self.request.query_params.get('section_type', None)
#         if section_type:
#             queryset = queryset.filter(section_type=section_type)
#         return queryset.order_by('display_order')

#     @action(detail=True, methods=['post'])
#     def toggle_status(self, request, pk=None):
#         section = self.get_object()
#         section.is_active = not section.is_active
#         section.save()
#         serializer = self.get_serializer(section)
#         return Response(serializer.data)

#     @action(detail=True, methods=['post'])
#     def update_display_order(self, request, pk=None):
#         section = self.get_object()
#         new_order = request.data.get('display_order')
        
#         if new_order is None:
#             return Response(
#                 {'detail': 'display_order is required'},
#                 status=status.HTTP_400_BAD_REQUEST
#             )

#         try:
#             new_order = int(new_order)
#         except (TypeError, ValueError):
#             return Response(
#                 {'detail': 'display_order must be a valid integer'},
#                 status=status.HTTP_400_BAD_REQUEST
#             )

#         section.display_order = new_order
#         section.save()
#         serializer = self.get_serializer(section)
#         return Response(serializer.data)

#     @action(detail=False, methods=['get'])
#     def section_types(self, request):
#         return Response({
#             'types': [
#                 {'value': choice[0], 'label': choice[1]}
#                 for choice in HomeSectionType.choices
#             ]
#         })

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
        
    # def perform_create(self, serializer):
    #     if self.request.user.role == 'MLM_MEMBER':
    #         # Set the MLM member to the current user's MLM profile
    #         serializer.save(mlm_member=self.request.user.mlm_profile)
    #     else:
    #         serializer.save()

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
                    {"error": "Invalid status"},
                    status=status.HTTP_400_BAD_REQUEST
                )

            document.status = verification_status
            document.verified_by = request.user
            document.verification_date = timezone.now()

            if verification_status == 'REJECTED':
                if not rejection_reason:
                    return Response(
                        {"error": "Rejection reason is required"},
                        status=status.HTTP_400_BAD_REQUEST
                    )
                document.rejection_reason = rejection_reason

            document.save()
            
            # Send notification to MLM member about the verification
            # You can implement this part based on your notification system
            
            return Response(self.get_serializer(document).data)
            
        except Exception as e:
            return Response(
                {"error": str(e)},
                status=status.HTTP_400_BAD_REQUEST
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
        

class VerifyPaymentView(APIView):
    authentication_classes = [JWTAuthentication]
    permission_classes = [IsAuthenticated]

    def post(self, request):
        try:
            # Get payment details
            payment_id = request.data.get('razorpay_payment_id')
            order_id = request.data.get('razorpay_order_id')
            signature = request.data.get('razorpay_signature')

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
                
                # Update order status
                order.status = 'CONFIRMED'
                order.payment_id = payment_id
                order.save()

                # If user is MLM member, update BP points
                if request.user.role == 'MLM_MEMBER':
                    mlm_member = request.user.mlm_profile
                    mlm_member.total_bp += order.total_bp
                    mlm_member.current_month_purchase += order.final_amount
                    mlm_member.save()

                    # Check for position upgrade
                    mlm_member.check_position_upgrade()

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
            return Response({
                'status': 'error',
                'message': str(e)
            }, status=status.HTTP_400_BAD_REQUEST)
        

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
            if request.user.role == 'MLM_MEMBER':
                mlm_member = request.user.mlm_profile
                mlm_member.total_bp += total_bp_points
                mlm_member.current_month_purchase += final_total
                mlm_member.save()
                
                # Check for position upgrade
                # mlm_member.check_position_upgrade()
                self.check_position_upgrade(mlm_member)

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

        return Response(WithdrawalRequestSerializer(withdrawal).data)



# ------------------ Notification -----------------------
class NotificationViewSet(viewsets.ModelViewSet):
    serializer_class = NotificationSerializer
    permission_classes = [IsAuthenticated]

    def get_queryset(self):
        user = self.request.user
        if user.role == 'ADMIN':
            return Notification.objects.all().order_by('-created_at')
        else:
            # Get the MLM member ID for the current user
            mlm_member = user.mlm_profile  # Assuming you have this related_name set up

            return Notification.objects.filter(
                Q(recipient=mlm_member.id) | Q(notification_type='GENERAL', recipient__isnull=True)
            ).order_by('-created_at')

    def perform_create(self, serializer):
        logger.info(f"Creating notification: {serializer.validated_data}")
        if self.request.user.role != 'ADMIN':
            raise PermissionError("Only admin can create notifications")
            
        notification_type = serializer.validated_data.get('notification_type')
        recipient = serializer.validated_data.get('recipient')
        
        # For individual notifications, ensure recipient is set
        if notification_type == 'INDIVIDUAL' and not recipient:
            raise serializers.ValidationError({
                'recipient': 'Recipient is required for individual notifications'
            })
        
        # For general notifications, ensure recipient is None
        if notification_type == 'GENERAL':
            serializer.validated_data['recipient'] = None
            
        serializer.save()

    @action(detail=True, methods=['POST'])
    def mark_read(self, request, pk=None):
        notification = self.get_object()
        # Allow marking as read if it's a general notification or if user is the recipient
        if notification.notification_type != 'GENERAL' and notification.recipient != request.user:
            return Response(
                {"error": "Cannot mark other user's notification as read"},
                status=status.HTTP_403_FORBIDDEN
            )
        
        notification.mark_as_read()
        return Response({"status": "success"})

    @action(detail=False, methods=['POST'])
    def mark_all_read(self, request):
        user = request.user
        notifications = Notification.objects.filter(
            Q(recipient=user) | Q(notification_type='GENERAL', recipient__isnull=True),
            is_read=False
        )
        notifications.update(is_read=True, read_at=timezone.now())
        return Response({"status": "success"})

    @action(detail=False, methods=['GET'])
    def unread_count(self, request):
        user = request.user
        count = Notification.objects.filter(
            Q(recipient=user) | Q(notification_type='GENERAL', recipient__isnull=True),
            is_read=False
        ).count()
        return Response({"count": count})
    



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
            
            # Validate status
            valid_statuses = [choice[0] for choice in Order.OrderStatus.choices]
            if new_status not in valid_statuses:
                return Response(
                    {'error': f'Invalid status. Must be one of: {", ".join(valid_statuses)}'},
                    status=status.HTTP_400_BAD_REQUEST
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
    permission_classes = [IsAuthenticated]

    def get(self, request):
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

        # If no base member found, return empty tree
        if not base_member:
            return Response({
                'message': 'No member tree available',
                'tree': []
            })

        # Recursive function to build member tree
        def build_member_tree(member):
            # Get direct referrals
            referrals = MLMMember.objects.filter(sponsor=member)
            
            member_data = {
                'id': member.id,
                'member_id': member.member_id,
                'name': member.user.get_full_name() or member.user.username,
                'email': member.user.email,
                'phone_number': member.user.phone_number,
                'position_name': member.position.name if member.position else None,
                'is_active': member.is_active,
                'total_earnings': float(member.total_earnings),
                'total_bp': member.total_bp,
                'referral_count': referrals.count(),
                'children': [build_member_tree(referral) for referral in referrals]
            }
            
            return member_data

        # Build and return the tree
        tree = build_member_tree(base_member)
        
        return Response({
            'tree': tree
        })

class MLMMemberDetailsView(APIView):
    permission_classes = [IsAuthenticated]

    def get(self, request, member_id):
        try:
            # Determine if the user has permission to view the member
            if request.user.role == 'ADMIN':
                member = get_object_or_404(MLMMember, member_id=member_id)
            elif request.user.role == 'MLM_MEMBER':
                # MLM member can only view their direct and indirect downline
                current_member = request.user.mlm_profile
                
                # Check if the requested member is in the current member's downline
                def is_in_downline(current, target):
                    if current == target:
                        return False
                    
                    referrals = MLMMember.objects.filter(sponsor=current)
                    for referral in referrals:
                        if referral == target or is_in_downline(referral, target):
                            return True
                    return False

                member = get_object_or_404(MLMMember, member_id=member_id)
                
                if not is_in_downline(current_member, member):
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



class MLMDashboardView(APIView):
    permission_classes = [IsAuthenticated]

    def get(self, request):
        try:
            # Ensure the user is an MLM member
            if request.user.role != 'MLM_MEMBER':
                return Response({
                    'error': 'Unauthorized access'
                }, status=status.HTTP_403_FORBIDDEN)

            # Get the MLM member profile
            member = self.get_mlm_member(request.user)
            if not member:
                return Response({
                    'error': 'MLM member profile not found'
                }, status=status.HTTP_404_NOT_FOUND)

            # Prepare dashboard data
            dashboard_data = {
                # Income Details
                'total_income': self.safe_calculate_total_income(member),
                'current_month_income': self.safe_calculate_current_month_income(member),
                'self_income': self.safe_calculate_self_income(member),
                'team_income': self.safe_calculate_team_income(member),
                'bonus_income': self.safe_calculate_bonus_income(member),

                # Team Details
                'total_team_members': self.safe_get_total_team_members(member),
                'total_team_commission': self.safe_calculate_total_team_commission(member),

                # Rank Details
                'current_rank': member.position.name if member.position else 'N/A',
                'rank_target': float(member.current_month_purchase) if member else 0,  # Replaced sales_target

                # Performance Data
                'monthly_performance': self.safe_get_monthly_performance(member),

                # Featured Products
                'featured_products': self.safe_get_featured_products(),

                # Recent Orders
                'recent_orders': self.safe_get_recent_orders(member)
            }

            return Response(dashboard_data)

        except Exception as e:
            logger.error(f"MLM Dashboard error: {str(e)}", exc_info=True)
            return Response({
                'error': 'Failed to load dashboard',
                'details': str(e)
            }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

    def safe_calculate_bonus_income(self, member):
        """
        Calculate bonus income
        """
        try:
            from home.models import Commission
            bonus_commissions = Commission.objects.filter(
                member=member,
                is_paid=True
            ).aggregate(total=Sum('amount'))['total'] or Decimal('0.00')

            return float(bonus_commissions)
        except Exception as e:
            logger.error(f"Error calculating bonus income: {str(e)}")
            return 0.00

    def safe_calculate_total_team_commission(self, member):
        """
        Calculate total team commission
        """
        try:
            from home.models import Commission
            total_commission = Commission.objects.filter(
                member=member,
                is_paid=True
            ).aggregate(total=Sum('amount'))['total'] or Decimal('0.00')

            return float(total_commission)
        except Exception as e:
            logger.error(f"Error calculating total team commission: {str(e)}")
            return 0.00

    def get_mlm_member(self, user):
        """
        Safely retrieve MLM member profile
        """
        try:
            from home.models import MLMMember
            return MLMMember.objects.select_related('user', 'position').get(user=user)
        except Exception as e:
            logger.error(f"Error retrieving MLM member: {str(e)}")
            return None

    def safe_calculate_total_income(self, member):
        """
        Calculate total income from all sources
        """
        try:
            from home.models import Commission, WalletTransaction

            # Calculate commissions
            total_commissions = Commission.objects.filter(
                member=member, 
                is_paid=True
            ).aggregate(total=Sum('amount'))['total'] or Decimal('0.00')

            # Calculate wallet income from commissions
            wallet_income = WalletTransaction.objects.filter(
                wallet__user=member.user,
                transaction_type='COMMISSION'
            ).aggregate(total=Sum('amount'))['total'] or Decimal('0.00')

            return float(total_commissions + wallet_income)
        except Exception as e:
            logger.error(f"Error calculating total income: {str(e)}")
            return 0.00

    def safe_calculate_current_month_income(self, member):
        """
        Calculate current month's income
        """
        try:
            from home.models import Commission
            current_month = timezone.now().replace(day=1, hour=0, minute=0, second=0, microsecond=0)
            
            current_month_commissions = Commission.objects.filter(
                member=member,
                is_paid=True,
                date__gte=current_month
            ).aggregate(total=Sum('amount'))['total'] or Decimal('0.00')

            return float(current_month_commissions)
        except Exception as e:
            logger.error(f"Error calculating current month income: {str(e)}")
            return 0.00

    def safe_calculate_self_income(self, member):
        """
        Calculate personal sales income
        """
        try:
            from home.models import Order
            self_sales = Order.objects.filter(
                user=member.user, 
                status='DELIVERED'
            ).aggregate(total=Sum('final_amount'))['total'] or Decimal('0.00')

            return float(self_sales)
        except Exception as e:
            logger.error(f"Error calculating self income: {str(e)}")
            return 0.00

    def safe_calculate_team_income(self, member):
        """
        Calculate team income from downline
        """
        try:
            from home.models import Commission
            team_income = Commission.objects.filter(
                from_member__sponsor=member
            ).aggregate(total=Sum('amount'))['total'] or Decimal('0.00')

            return float(team_income)
        except Exception as e:
            logger.error(f"Error calculating team income: {str(e)}")
            return 0.00


    def safe_get_total_team_members(self, member):
        """
        Get total team members recursively
        """
        try:
            from home.models import MLMMember

            def count_total_network(current_member):
                referrals = MLMMember.objects.filter(sponsor=current_member)
                total = referrals.count()
                for referral in referrals:
                    total += count_total_network(referral)
                return total

            return count_total_network(member)
        except Exception as e:
            logger.error(f"Error getting total team members: {str(e)}")
            return 0


    def safe_get_monthly_performance(self, member):
        """
        Get monthly performance data
        """
        try:
            from home.models import Order
            current_year = timezone.now().year
            monthly_performance = []

            for month in range(1, 13):
                start_date = timezone.datetime(current_year, month, 1)
                end_date = (start_date + timezone.timedelta(days=32)).replace(day=1) - timezone.timedelta(days=1)

                monthly_sales = Order.objects.filter(
                    user=member.user,
                    order_date__range=[start_date, end_date],
                    status='DELIVERED'
                ).aggregate(total_sales=Sum('final_amount'))['total_sales'] or Decimal('0.00')

                monthly_performance.append({
                    'month': start_date.strftime('%b'),
                    'performance': float(monthly_sales)
                })

            return monthly_performance
        except Exception as e:
            logger.error(f"Error getting monthly performance: {str(e)}")
            return []

    def safe_get_featured_products(self):
        """
        Get featured products
        """
        try:
            from home.models import Product
            featured_products = Product.objects.filter(
                is_featured=True, 
                is_active=True
            )[:4]  # Top 4 featured products

            return [{
                'id': product.id,
                'name': product.name,
                'price': float(product.selling_price),
                'image': product.images.first().image.url if product.images.exists() else None
            } for product in featured_products]
        except Exception as e:
            logger.error(f"Error getting featured products: {str(e)}")
            return []

    def safe_get_recent_orders(self, member):
        """
        Get recent orders for the member
        """
        try:
            from home.models import Order
            recent_orders = Order.objects.filter(
                user=member.user
            ).order_by('-order_date')[:5]  # Last 5 orders

            return [{
                'id': order.id,
                'order_number': order.order_number,
                'order_date': order.order_date,
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
            # Validate current user is an MLM member
            if request.user.role != 'MLM_MEMBER':
                return Response({
                    'error': 'Only MLM members can register new members'
                }, status=status.HTTP_403_FORBIDDEN)

            # Get current MLM member (sponsor)
            current_member = MLMMember.objects.get(user=request.user)

            # Extract document related data
            documents = request.FILES.getlist('document_file')
            document_types = request.POST.getlist('document_types[]')
            document_numbers = {}
            
            # Process document numbers from the request
            for doc_type in ['AADHAR', 'PAN', 'BANK_STATEMENT', 'CANCELLED_CHEQUE']:
                if doc_type in request.POST:
                    document_numbers[doc_type] = request.POST.get(doc_type)

            # Create context with document data
            serializer_context = {
                'document_types': document_types,
                'document_numbers': document_numbers
            }

            # Validate input data
            serializer = MLMMemberRegistrationSerializer(
                data=request.POST,
                context=serializer_context
            )

            if not serializer.is_valid():
                return Response({
                    'error': 'Invalid registration data',
                    'details': serializer.errors
                }, status=status.HTTP_400_BAD_REQUEST)

            # Create new user
            new_user = User.objects.create_user(
                username=self.generate_unique_username(serializer.validated_data['phone_number']),
                password=serializer.validated_data['password'],
                phone_number=serializer.validated_data['phone_number'],
                first_name=serializer.validated_data['first_name'],
                last_name=serializer.validated_data.get('last_name', ''),
                email=serializer.validated_data.get('email', ''),
                role='MLM_MEMBER'
            )

            try:
                # Create MLM Member
                new_mlm_member = MLMMember.objects.create(
                    user=new_user,
                    sponsor=current_member,
                    position=self.determine_position(current_member),
                    member_id=self.generate_member_id(),
                    is_active=True,
                    join_date=timezone.now()
                )

                # Process KYC Documents
                kyc_docs_list = []
                for doc, doc_type in zip(documents, document_types):
                    try:
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
                        # Cleanup
                        new_user.delete()
                        new_mlm_member.delete()
                        for doc in kyc_docs_list:
                            doc.delete()
                        raise Exception(f"Failed to create KYC document: {str(doc_error)}")

                # Create notification
                Notification.objects.create(
                    title='New MLM Member Registration',
                    message=f'New member {new_user.get_full_name()} registered by {current_member.user.get_full_name()}',
                    notification_type='SYSTEM'
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
                        'position': new_mlm_member.position.name
                    }
                })

            except Exception as e:
                logger.error(f"Error in member creation: {str(e)}")
                if 'new_user' in locals():
                    new_user.delete()
                raise

        except Exception as e:
            logger.error(f"MLM Member Registration Error: {str(e)}")
            return Response({
                'error': str(e)
            }, status=status.HTTP_400_BAD_REQUEST)

    def generate_unique_username(self, phone_number):
        base_username = f"MLM_{phone_number}"
        unique_suffix = str(uuid.uuid4())[:8]
        return f"{base_username}_{unique_suffix}"

    def generate_member_id(self):
        while True:
            member_id = f"MLM{random.randint(10000, 99999)}"
            if not MLMMember.objects.filter(member_id=member_id).exists():
                return member_id

    def determine_position(self, sponsor):
        return sponsor.position
        



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