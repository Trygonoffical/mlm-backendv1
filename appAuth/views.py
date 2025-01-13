import requests
import logging
from rest_framework import status
from rest_framework.views import APIView
from rest_framework.response import Response
from django.conf import settings
from home.models import PhoneOTP, User
import random
from django.views.decorators.csrf import csrf_exempt
from django.utils.decorators import method_decorator
from rest_framework.permissions import AllowAny
from django.utils import timezone
from datetime import timedelta
from .serializers import UserSerializer

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
            
            from rest_framework_simplejwt.tokens import RefreshToken
            # refresh = RefreshToken.for_user(user)
            # Serialize user data
            user_data = UserSerializer(user).data
            
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