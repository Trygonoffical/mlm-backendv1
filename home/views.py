from rest_framework.decorators import api_view, permission_classes
from rest_framework.permissions import AllowAny
from rest_framework.response import Response

# Create your views here.
from rest_framework import status, views
from rest_framework.response import Response
from rest_framework.permissions import AllowAny
from django.contrib.auth import authenticate
from rest_framework_simplejwt.tokens import RefreshToken
import random
from .models import PhoneOTP , User
# Create your views here.

@api_view(['GET'])
@permission_classes([AllowAny])
def config(request):
    if request.method == 'POST':
        return Response(request.data)
    return Response({"message": "Hello, vikas!"})






class UserLoginView(views.APIView):
    permission_classes = [AllowAny]

    def post(self, request):
        login_type = 'credentials'
        
        if login_type == 'credentials':
            return self.handle_credential_login(request)
        
        return Response({
            'status': False,
            'message': 'Invalid login type'
        }, status=status.HTTP_400_BAD_REQUEST)

    def handle_credential_login(self, request):
        user_id = request.data.get('user_id')
        password = request.data.get('password')

        if not user_id or not password:
            return Response({
                'status': False,
                'message': 'Both user ID and password are required'
            }, status=status.HTTP_400_BAD_REQUEST)

        user = authenticate(user_id=user_id, password=password)

        if not user:
            return Response({
                'status': False,
                'message': 'Invalid credentials'
            }, status=status.HTTP_401_UNAUTHORIZED)

        if user.role not in ['MEMBER', 'ASSOCIATE']:
            return Response({
                'status': False,
                'message': 'Invalid user type for credential login'
            }, status=status.HTTP_401_UNAUTHORIZED)

        return self.get_login_success_response(user)

    def get_login_success_response(self, user):
        refresh = RefreshToken.for_user(user)
        return Response({
            'status': True,
            'message': 'Login successful',
            'token': str(refresh.access_token),
            'refresh': str(refresh),
            'role': user.role,
            'user_id': user.user_id,
            'phone_number': user.phone_number,
            'dashboard_url': self.get_dashboard_url(user.role)
        })

    def get_dashboard_url(self, role):
        dashboard_urls = {
            'CUSTOMER': '/account',
            'MEMBER': '/member/dashboard',
            'ASSOCIATE': '/associate/dashboard',
            'ADMIN': '/admin/dashboard'
        }
        return dashboard_urls.get(role, '/account')
