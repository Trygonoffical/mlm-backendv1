# utils/msg91_utils.py
import requests
import logging
from django.conf import settings

logger = logging.getLogger(__name__)

class MSG91Service:
    BASE_URL = "https://control.msg91.com/api/v5"
    
    def __init__(self, auth_key):
        self.auth_key = auth_key
    
    def send_otp(self, phone_number, otp, template_id='1007222030162030703'):
        """
        Send OTP via MSG91
        
        Args:
            phone_number (str): Mobile number to send OTP
            otp (str): OTP to be sent
            template_id (str, optional): OTP template ID
        
        Returns:
            dict: Response from MSG91
        """
        try:
            url = f"{self.BASE_URL}/otp"
            payload = {
                "template_id": template_id,
                "mobile": phone_number,
                "authkey": self.auth_key,
                "otp": otp,
                "message": f"{otp} is OTP to authenticate login credential. Do not share with anyone.",
                "otp_expiry": 30  # OTP valid for 30 minutes
            }
            
            headers = {
                'Content-Type': 'application/json'
            }
            
            response = requests.post(url, json=payload, headers=headers)
            response_data = response.json()
            
            logger.info(f"OTP Send Response: {response_data}")
            
            return {
                'success': response.status_code == 200,
                'message': response_data.get('message', 'Unknown response'),
                'details': response_data
            }
        
        except Exception as e:
            logger.error(f"Error sending OTP: {str(e)}")
            return {
                'success': False,
                'message': str(e),
                'details': None
            }
    
    def verify_otp(self, phone_number, otp):
        """
        Verify OTP sent via MSG91
        
        Args:
            phone_number (str): Mobile number
            otp (str): OTP to verify
        
        Returns:
            dict: Verification response
        """
        try:
            url = f"{self.BASE_URL}/otp/verify"
            payload = {
                "mobile": phone_number,
                "otp": otp,
                "authkey": self.auth_key
            }
            
            headers = {
                'Content-Type': 'application/json'
            }
            
            response = requests.post(url, json=payload, headers=headers)
            response_data = response.json()
            
            logger.info(f"OTP Verify Response: {response_data}")
            
            return {
                'success': response.status_code == 200,
                'message': response_data.get('message', 'Unknown response'),
                'details': response_data
            }
        
        except Exception as e:
            logger.error(f"Error verifying OTP: {str(e)}")
            return {
                'success': False,
                'message': str(e),
                'details': None
            }
    
    def send_transactional_sms(self, phone_number, message, template_id='1007359457599426993'):
        """
        Send transactional SMS via MSG91
        
        Args:
            phone_number (str): Mobile number
            message (str): Message content
            template_id (str, optional): SMS template ID
        
        Returns:
            dict: SMS send response
        """
        try:
            url = f"{self.BASE_URL}/notifications/send"
            payload = {
                "template_id": template_id,
                "sender": "HERBPW",
                "short_url": 0,  # Disable URL shortening
                "mobiles": phone_number,
                "entity_id": "1001766978661064894",  # Entity ID from credentials
                "message": message
            }
            
            headers = {
                'Content-Type': 'application/json',
                'authkey': self.auth_key
            }
            
            response = requests.post(url, json=payload, headers=headers)
            response_data = response.json()
            
            logger.info(f"SMS Send Response: {response_data}")
            
            return {
                'success': response.status_code == 200,
                'message': response_data.get('message', 'Unknown response'),
                'details': response_data
            }
        
        except Exception as e:
            logger.error(f"Error sending SMS: {str(e)}")
            return {
                'success': False,
                'message': str(e),
                'details': None
            }

# def send_order_confirmation_sms(order):
#     msg91_service = MSG91Service(settings.MSG91_AUTH_KEY)
#     message = f"Dear User, your order {order.order_number} has been confirmed. Delivery by {order.expected_delivery_date}. For details, visit https://www.yourwebsite.com/OrderTracking"
    
#     result = msg91_service.send_transactional_sms(
#         order.user.phone_number, 
#         message
#     )
    
#     if not result['success']:
#         logger.error(f"Failed to send order confirmation SMS: {result['message']}")