from django.http import JsonResponse
from django.views.decorators.csrf import csrf_exempt
from django.views.decorators.http import require_POST
import json
import logging
from django.conf import settings
from utils.msg91_email_utils import MSG91EmailService

logger = logging.getLogger(__name__)

@csrf_exempt
@require_POST
def test_email_api(request):
    """
    Test endpoint for sending emails via MSG91
    
    Expected POST data:
    {
        "email": "recipient@example.com",
        "name": "Recipient Name",
        "template_id": "your_template_id",
        "variables": {
            "var1": "Value 1",
            "var2": "Value 2"
        }
    }
    """
    try:
        # Parse request data
        try:
            data = json.loads(request.body)
        except json.JSONDecodeError:
            return JsonResponse({
                'success': False,
                'message': 'Invalid JSON in request body'
            }, status=400)
        
        # Extract parameters
        email = data.get('email')
        name = data.get('name')
        template_id = data.get('template_id')
        variables = data.get('variables', {})
        
        # Validate required parameters
        if not email or not name or not template_id:
            return JsonResponse({
                'success': False,
                'message': 'Email, name, and template_id are required'
            }, status=400)
        
        # Initialize email service
        email_service = MSG91EmailService()
        
        # Send the email
        result = email_service.send_email(
            to_email=email,
            to_name=name,
            template_id=template_id,
            variables=variables
        )
        
        # Return the result
        return JsonResponse(result)
        
    except Exception as e:
        logger.error(f"Error in test_email_api: {str(e)}")
        return JsonResponse({
            'success': False,
            'message': f'An error occurred: {str(e)}'
        }, status=500)

@csrf_exempt
@require_POST
def test_welcome_email(request):
    """
    Test endpoint for sending welcome emails
    
    Expected POST data:
    {
        "email": "recipient@example.com",
        "name": "Recipient Name",
        "username": "user123",
        "password": "test_password"
    }
    """
    try:
        # Parse request data
        try:
            data = json.loads(request.body)
        except json.JSONDecodeError:
            return JsonResponse({
                'success': False,
                'message': 'Invalid JSON in request body'
            }, status=400)
        
        # Extract parameters
        email = data.get('email')
        name = data.get('name', '')
        username = data.get('username', '')
        password = data.get('password', '')
        
        # Validate required parameters
        if not email or not password:
            return JsonResponse({
                'success': False,
                'message': 'Email and password are required'
            }, status=400)
        
        # Create a mock user object
        class MockUser:
            def __init__(self, email, name, username):
                self.email = email
                self.first_name = name.split(' ')[0] if ' ' in name else name
                self.last_name = ' '.join(name.split(' ')[1:]) if ' ' in name else ''
                self.username = username
            
            def get_full_name(self):
                return f"{self.first_name} {self.last_name}".strip()
        
        user = MockUser(email, name, username)
        
        # Initialize email service
        email_service = MSG91EmailService()
        
        # Send the welcome email
        result = email_service.send_welcome_email(
            user=user,
            password=password
        )
        
        # Return the result
        return JsonResponse(result)
        
    except Exception as e:
        logger.error(f"Error in test_welcome_email: {str(e)}")
        return JsonResponse({
            'success': False,
            'message': f'An error occurred: {str(e)}'
        }, status=500)

@csrf_exempt
@require_POST
def test_order_confirmation_email(request):
    """
    Test endpoint for sending order confirmation emails
    
    Expected POST data:
    {
        "email": "recipient@example.com",
        "name": "Recipient Name",
        "order_number": "ORD12345",
        "date": "2023-05-15"
    }
    """
    try:
        # Parse request data
        try:
            data = json.loads(request.body)
        except json.JSONDecodeError:
            return JsonResponse({
                'success': False,
                'message': 'Invalid JSON in request body'
            }, status=400)
        
        # Extract parameters
        email = data.get('email')
        name = data.get('name', '')
        order_number = data.get('order_number', 'TEST123')
        date = data.get('date', '2023-05-15')
        
        # Validate required parameters
        if not email:
            return JsonResponse({
                'success': False,
                'message': 'Email is required'
            }, status=400)
        
        # Create mock objects
        class MockUser:
            def __init__(self, email, name):
                self.email = email
                self.first_name = name.split(' ')[0] if ' ' in name else name
                self.last_name = ' '.join(name.split(' ')[1:]) if ' ' in name else ''
            
            def get_full_name(self):
                return f"{self.first_name} {self.last_name}".strip()
        
        class MockOrder:
            def __init__(self, order_number, user):
                self.order_number = order_number
                self.user = user
        
        user = MockUser(email, name)
        order = MockOrder(order_number, user)
        
        # Initialize email service
        email_service = MSG91EmailService()
        
        # Send the order confirmation email
        result = email_service.send_order_confirmation_email(
            order=order,
            date=date
        )
        
        # Return the result
        return JsonResponse(result)
        
    except Exception as e:
        logger.error(f"Error in test_order_confirmation_email: {str(e)}")
        return JsonResponse({
            'success': False,
            'message': f'An error occurred: {str(e)}'
        }, status=500)