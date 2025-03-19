import requests
import json
import logging
from django.conf import settings

logger = logging.getLogger(__name__)

class MSG91EmailService:
    """
    Service class for sending emails using MSG91 API
    """
    
    def __init__(self, auth_key=None):
        """
        Initialize with the AUTH key for MSG91
        """
        # self.auth_key = auth_key or settings.MSG91_EMAIL_AUTH_KEY
        # self.base_url = "https://control.msg91.com/api/v5/email/send"
        # self.headers = {
        #     'accept': 'application/json',
        #     'authkey': self.auth_key,
        #     'content-type': 'application/json'
        # }
        self.auth_key = auth_key or settings.MSG91_EMAIL_AUTH_KEY
        self.base_url = "control.msg91.com"
        self.api_endpoint = "/api/v5/email/send"
        self.domain = settings.MSG91_EMAIL_DOMAIN or "mail.herbalpowerindia.com"
        self.from_email = settings.MSG91_FROM_EMAIL or "noreply@mail.herbalpowerindia.com"
        self.from_name = settings.MSG91_FROM_NAME or "Herbal Power Marketing Private Limited"
        
    def send_email(self, to_email, to_name, template_id, variables):
        """
        Send an email using MSG91 Email API
        
        Args:
            to_email (str): Recipient email address
            to_name (str): Recipient name
            template_id (str): MSG91 email template ID
            variables (dict): Variables to be replaced in the template
            
        Returns:
            dict: Response with success status and message
        """
        try:
            # Create connection
            import http.client
            conn = http.client.HTTPSConnection(self.base_url)
            
            # Prepare request payload according to MSG91 Email API documentation
            payload = {
                "recipients": [
                    {
                        "to": [
                            {
                                "name": to_name,
                                "email": to_email
                            }
                        ],
                        "variables": variables
                    }
                ],
                "from": {
                    "name": self.from_name,
                    "email": self.from_email
                },
                "domain": self.domain,
                "template_id": template_id
            }
            
            # Set headers
            headers = {
                'authkey': self.auth_key,
                'accept': "application/json",
                'content-type': "application/json"
            }
            
            # Make the request
            conn.request("POST", self.api_endpoint, json.dumps(payload), headers)
            
            # Get response
            response = conn.getresponse()
            data = response.read().decode("utf-8")
            
            # Log response
            logger.info(f"Email Send Response: {data}")
            
            # Parse response
            response_data = json.loads(data)
            
            if response.status == 200 and response_data.get('status') == 'success':
                return {
                    'success': True,
                    'message': 'Email sent successfully',
                    'response': response_data
                }
            else:
                error_msg = response_data.get('message', 'Unknown error')
                logger.error(f"MSG91 Email API Error: {error_msg}")
                return {
                    'success': False,
                    'message': f'Failed to send email: {error_msg}',
                    'response': response_data
                }
                
        except Exception as e:
            logger.error(f"Error sending email: {str(e)}")
            return {
                'success': False,
                'message': f'Error sending email: {str(e)}'
            }
            

    def send_welcome_email(self, user, password ):
        """
        Send welcome email to a new MLM member
        
        Args:
            user (User): User object for the new member
            password (str): Plain text password for the new member
            sponsor (MLMMember, optional): Sponsor MLM member object
            
        Returns:
            dict: Response with success status and message
        """
        try:
            # Get user details
            full_name = user.get_full_name() or user.username
            user_id = user.username
            
            # Prepare variables for the template
            variables = {
                "var1": full_name,
                "var2": user_id,
                "var3": password,
            }
            
            # Send the welcome email
            return self.send_email(
                to_email=user.email,
                to_name=full_name,
                template_id="onboarding_2",  # Replace with your actual template ID
                variables=variables
            )
            
        except Exception as e:
            logger.error(f"Error sending welcome email: {str(e)}")
            return {
                'success': False,
                'message': f'Error sending welcome email: {str(e)}'
            }
        

    def send_kyc_approved_email(self, member):
        """
        Send KYC approval notification email to MLM member
        
        Args:
            member (MLMMember): The MLM member whose KYC was approved
            
        Returns:
            dict: Response with success status and message
        """
        try:
            user = member.user
            if not user.email:
                logger.warning(f"Cannot send KYC approval email: No email for member {member.member_id}")
                return {
                    'success': False,
                    'message': 'Member has no email address'
                }
                
            variables = {
                "var1": user.get_full_name() or user.username
            }
            
            return self.send_email(
                to_email=user.email,
                to_name=user.get_full_name() or user.username,
                template_id="kyc_approved_3",
                variables=variables
            )
            
        except Exception as e:
            logger.error(f"Error sending KYC approval email: {str(e)}")
            return {
                'success': False,
                'message': f"Error sending KYC approval email: {str(e)}"
            }
        
    def send_order_confirmation_email(self, order , date):
        """
        Send KYC approval notification email to MLM member
        
        Args:
            member (MLMMember): The MLM member whose KYC was approved
            
        Returns:
            dict: Response with success status and message
        """
        try:
            user = order.user
            if not user.email:
                logger.warning(f"Cannot send Order Conformation email: No email for User {user}")
                return {
                    'success': False,
                    'message': 'Order has no email address'
                }
                
            variables = {
                # "var1": user.get_full_name() or user.username
                "VAR1" : order.order_number,  #Order ID
                "var2" : user.get_full_name() or user.username ,#username
                "var3" : order.order_number, #Order ID
                "var4"  : date #Expected Delivery Date:
            }
            
            return self.send_email(
                to_email=user.email,
                to_name=user.get_full_name() or user.username,
                template_id="order_confirmation_24",
                variables=variables
            )
            
        except Exception as e:
            logger.error(f"Error sending KYC approval email: {str(e)}")
            return {
                'success': False,
                'message': f"Error sending KYC approval email: {str(e)}"
            }