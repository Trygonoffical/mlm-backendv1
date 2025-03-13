# shipping/services.py

import requests
import json
import logging
from django.conf import settings
from datetime import datetime
from home.models import ShippingConfig
from django.utils import timezone


logger = logging.getLogger(__name__)

class QuixGoShippingService:
    """Service class to interact with QuixGo shipping API"""
    
    def __init__(self):
        # Get credentials from settings or database
        # self.api_base_url = settings.QUIXGO_API_BASE_URL  # e.g., 'https://dev.api.quixgo.com/clientApi'
        # self.email = settings.QUIXGO_EMAIL
        # self.password = settings.QUIXGO_PASSWORD
        # self.token = None
        # self.customer_id = settings.QUIXGO_CUSTOMER_ID  # Save this after first login
        self.api_base_url = settings.QUIXGO_API_BASE_URL
        self.email = settings.QUIXGO_EMAIL
        self.password = settings.QUIXGO_PASSWORD
        self.customer_id = settings.QUIXGO_CUSTOMER_ID
        self.token = None

        # Check if token exists in database and is valid
        try:
            config = ShippingConfig.objects.filter(
                email=self.email
            ).first()
            
            if config and config.access_token and not self.is_token_expired():
                self.token = config.access_token
            else:
                # Token doesn't exist or is expired, get a new one
                self.login()
        except Exception as e:
            logger.error(f"Error loading shipping config: {str(e)}")
            self.token = None
    
    def login(self):
        """Log in to QuixGo API and get authentication token"""
        try:
            url = f"{self.api_base_url}/login"
            payload = {
                "email": self.email,
                "password": self.password
            }
            headers = {
                'Content-Type': 'application/json'
            }
            
            response = requests.post(url, headers=headers, json=payload)
            
            if response.status_code == 200:
                data = response.json()
                self.token = data.get('token')
                
                # Save customer ID if not already saved
                if not self.customer_id:
                    self.customer_id = data.get('annotation_id')
                
                # Save token to database with expiry time (15 minutes from now)
                expiry_time = timezone.now() + timezone.timedelta(minutes=15)
                
                ShippingConfig.objects.update_or_create(
                    email=self.email,
                    defaults={
                        'access_token': self.token,
                        'token_expiry': expiry_time,
                        'customer_id': self.customer_id,
                        'first_name': data.get('firstName'),
                        'last_name': data.get('lastName'),
                        'mobile': data.get('mobile')
                    }
                )
                
                return True
            else:
                logger.error(f"QuixGo login failed: {response.text}")
                return False
                    
        except Exception as e:
            logger.error(f"Error logging in to QuixGo: {str(e)}")
            return False
    
    def test_connection(self):
        """
        Test connection to QuixGo API
        
        Returns:
            dict: A dictionary with connection status and message
        """
        try:
            # Attempt to log in
            login_success = self.login()
            
            if login_success:
                return {
                    'success': True,
                    'message': 'Successfully connected to QuixGo API'
                }
            else:
                return {
                    'success': False,
                    'error': 'Authentication failed'
                }
        
        except Exception as e:
            logger.error(f"Connection test error: {str(e)}")
            return {
                'success': False,
                'error': str(e)
            }
    def get_auth_header(self):
        """Return authorization header with token"""
        if not self.token:
            self.login()
        
        return {
            'Authorization': self.token,
            'Content-Type': 'application/json'
        }
    
    def is_token_expired(self):
        """Check if the QuixGo token is expired or about to expire"""
        try:
            # Get the latest config
            config = ShippingConfig.objects.filter(
                email=self.email
            ).first()
            
            if not config or not config.token_expiry:
                return True
                
            # Consider token expired if less than 1 minute remaining
            return config.token_expiry - timezone.now() < timezone.timedelta(minutes=1)
            
        except Exception as e:
            logger.error(f"Error checking token expiry: {str(e)}")
            return True  # Assume expired on error
        
    def create_pickup_address(self, address_data):
        """Create a pickup address in QuixGo"""
        try:
            if not self.token:
                self.login()
                
            url = f"{self.api_base_url}/addPickupPoint"
            
            payload = {
                "customerId": self.customer_id,
                "pickupName": address_data.get('name'),
                "cpPerson": address_data.get('contact_person'),
                "address1": address_data.get('address_line1'),
                "address2": address_data.get('address_line2', ''),
                "city": address_data.get('city'),
                "state": address_data.get('state'),
                "country": address_data.get('country', 'India'),
                "addressType": address_data.get('address_type', 'Office'),
                "pincode": address_data.get('pincode'),
                "cpMobile": address_data.get('phone'),
                "alternateNumber": address_data.get('alternate_phone', ''),
                "email": address_data.get('email', ''),
                "landmark": address_data.get('landmark', '')
            }
            
            response = requests.post(url, headers=self.get_auth_header(), json=payload)
            
            if response.status_code == 200:
                data = response.json()
                return {
                    'success': True,
                    'address_id': data.get('addressId'),
                    'data': data
                }
            else:
                logger.error(f"Failed to create pickup address: {response.text}")
                return {
                    'success': False,
                    'error': response.text
                }
                
        except Exception as e:
            logger.error(f"Error creating pickup address: {str(e)}")
            return {
                'success': False,
                'error': str(e)
            }
    
    def book_shipment(self, shipment_data, pickup_address, delivery_address):
        """Book a shipment with QuixGo"""
        try:
            if not self.token:
                self.login()
                
            url = f"{self.api_base_url}/v2/bookShipment"
            
            # Format the delivery address
            delivery_addr = {
                "name": delivery_address.get('name'),
                "address1": delivery_address.get('address1'),
                "address2": delivery_address.get('address2', ''),
                "landmark": delivery_address.get('landmark', ''),
                "city": delivery_address.get('city'),
                "state": delivery_address.get('state'),
                "pincode": delivery_address.get('pincode'),
                "mobile": delivery_address.get('mobile'),
                "alternateNumber": delivery_address.get('alternateNumber', ''),
                "email": delivery_address.get('email', ''),
                "addressType": delivery_address.get('addressType', 'Home')
            }
            
            # Structure payload according to QuixGo API
            payload = [{
                "deliveryAddress": delivery_addr,
                "pickupAddress": pickup_address,
                "returnAddress": pickup_address,  # Using same as pickup for simplicity
                "customerType": "Business",
                "productDetails": {
                    "weight": f"{float(shipment_data.get('weight', 1.0)):.2f}",
                    "height": str(shipment_data.get('height', '10')),
                    "width": str(shipment_data.get('width', '10')),
                    "length": str(shipment_data.get('length', '10')),
                    "invoice": str(shipment_data.get('invoice_value', '0')),
                    "productName": shipment_data.get('product_name', 'Product'),
                    "productType": shipment_data.get('product_type', 'Merchandise'),
                    "quantity": str(shipment_data.get('quantity', '1')),
                    "skuNumber": shipment_data.get('sku', ''),
                    "orderNumber": shipment_data.get('order_number', '')
                },
                "serviceProvider": shipment_data.get('courier', 'DTC'),  # Default to DTDC
                "serviceType": shipment_data.get('service_type', 'SF'),  # Default to Surface
                "paymentMode": "COD" if shipment_data.get('is_cod', False) else "Prepaid",
                "codAmount": shipment_data.get('cod_amount', 0) if shipment_data.get('is_cod', False) else 0,
                "insuranceCharge": shipment_data.get('insurance_charge', 0),
                "customerId": self.customer_id,
                "serviceMode": "FW" , # Forward shipment
                "bookingChannel": "web"
            }]
            
            logger.info(f"Shipment booking Payload : {payload}")
            response = requests.post(url, headers=self.get_auth_header(), json=payload)
            if response.status_code == 200:
                data = response.json()
                if isinstance(data, list) and len(data) > 0:
                    shipment_response = data[0]
                    if shipment_response.get('success'):
                        shipment_details = shipment_response.get('data', {})
                        return {
                            'success': True,
                            'awb_number': shipment_details.get('awbNumber'),
                            'shipment_id': shipment_details.get('shipmentId'),
                            'courier': shipment_details.get('shipmentPartner'),
                            'charge': shipment_details.get('finalCharge'),
                            'status': shipment_details.get('currentStatus'),
                            'data': shipment_details
                        }
                
                logger.error(f"Shipment booking response not in expected format: {data}")
                return {
                    'success': False,
                    'error': 'Unexpected response format'
                }
            else:
                logger.error(f"Failed to book shipment: {response.text}")
                return {
                    'success': False,
                    'error': response.text
                }
                
        except Exception as e:
            logger.error(f"Error booking shipment: {str(e)}")
            return {
                'success': False,
                'error': str(e)
            }
    
    def track_shipment(self, awb_number):
        """Track a shipment using AWB number with the correct QuixGo API endpoint and response handling"""
        try:
            if not self.token:
                self.login()
                
            # Use the correct QuixGo tracking endpoint from the curl example
            url = "https://api.quixgo.com/web/shipmentStatus/getStatus"
            
            # Format payload according to the curl example
            payload = {
                "awbNumber": awb_number,
                "serviceProvider": "QUIXGO"  # This appears to be a fixed value in the example
            }
            
            headers = {
                'Content-Type': 'application/json',
                'Accept': 'application/json, text/plain, */*',
            }
            
            # Log the request for debugging
            logger.info(f"Sending tracking request for AWB {awb_number} to QuixGo API")
            logger.debug(f"Tracking request payload: {payload}")
            
            response = requests.post(url, headers=headers, json=payload)
            
            # Log the response status
            logger.debug(f"QuixGo tracking response status: {response.status_code}")
            
            # Handle non-200 responses
            if response.status_code != 200:
                logger.error(f"QuixGo tracking API error: {response.text}")
                return {
                    'success': False,
                    'error': f"API returned status code {response.status_code}: {response.text}"
                }
            
            try:
                # Parse the JSON response
                response_data = response.json()
                
                # Log the full response for debugging
                logger.debug(f"QuixGo tracking response: {response_data}")
                
                # Extract shipment info from the response - matching the exact structure you shared
                shipment_info = response_data.get('shipmentInfo', {})
                status_info = response_data.get('status', {}).get('data', {})
                
                # Combine status history from both locations in the response if they exist
                status_history = []
                if 'statusHistory' in shipment_info:
                    status_history.extend(shipment_info['statusHistory'])
                
                # Also check if there's status history in the status.data section
                if 'statusHistory' in status_info:
                    # Check for duplicates before adding
                    existing_updates = set((item.get('statusName', ''), item.get('updateDate', '')) 
                                        for item in status_history)
                    
                    for update in status_info['statusHistory']:
                        update_key = (update.get('statusName', ''), update.get('updateDate', ''))
                        if update_key not in existing_updates:
                            status_history.append(update)
                            existing_updates.add(update_key)
                
                # Get the current status from either location
                current_status = shipment_info.get('currentStatus') or status_info.get('currentStatus', 'Unknown')
                
                # Return success with all the extracted data
                return {
                    'success': True,
                    'current_status': current_status,
                    'status_history': status_history,
                    'raw_data': response_data,
                    'shipment_info': shipment_info,
                    'order_id': shipment_info.get('orderId'),
                    'shipment_id': shipment_info.get('shipmentId'),
                    'courier': shipment_info.get('shipmentPartner'),
                    'booking_date': shipment_info.get('bookingDate'),
                    'service_type': shipment_info.get('serviceTypes')
                }
                    
            except ValueError as json_error:
                # Handle JSON parsing errors
                logger.error(f"Error parsing QuixGo tracking response: {str(json_error)}")
                logger.error(f"Raw response: {response.text}")
                return {
                    'success': False,
                    'error': 'Invalid response format from tracking API'
                }
                    
        except Exception as e:
            # Handle any other exceptions
            logger.error(f"Error tracking shipment: {str(e)}")
            return {
                'success': False,
                'error': str(e)
            }
    
    def cancel_shipment(self, awb_number, reason="Order cancelled"):
        """Cancel a shipment with proper handling for QuixGo's response format"""
        try:
            if not self.token:
                self.login()
                    
            url = f"{self.api_base_url}/v2/cancelShipment"
            
            # Format the payload according to QuixGo's expected format
            payload = [{
                "msg": reason,
                "awbNumber": awb_number,
                "customerId": self.customer_id
            }]
            
            logger.info(f"Cancelling shipment with AWB {awb_number}. Reason: {reason}")
            logger.debug(f"Cancel shipment payload: {payload}")
            
            response = requests.post(url, headers=self.get_auth_header(), json=payload)
            
            # Log the raw response for debugging
            logger.debug(f"Cancel shipment response HTTP status: {response.status_code}")
            logger.debug(f"Cancel shipment response body: {response.text}")
            
            # Try to parse the response body regardless of HTTP status code
            response_data = {}
            try:
                if response.text and response.text.strip():
                    response_data = response.json()
                    logger.debug(f"Parsed response data: {response_data}")
            except ValueError as json_error:
                logger.warning(f"Failed to parse response as JSON: {str(json_error)}")
            
            # Check for the cancellation success case in the response data
            is_cancelled = False
            
            # Check the specific response structure you shared - where status is in the JSON body
            if (isinstance(response_data, dict) and 
                (response_data.get('status') == 200 or response.status_code == 200) and 
                isinstance(response_data.get('message'), dict) and
                response_data['message'].get('statusName') == 'Cancelled'):
                
                is_cancelled = True
                return {
                    'success': True,
                    'message': 'Shipment cancelled successfully',
                    'status_name': 'Cancelled',
                    'update_date': response_data['message'].get('updateDate'),
                    'comment': response_data['message'].get('comment', reason),
                    'data': response_data
                }
            
            # Also check for list-based responses (used in a previous version)
            elif isinstance(response_data, list) and len(response_data) > 0:
                first_item = response_data[0]
                # Check for success field or message structure
                if first_item.get('success', False):
                    is_cancelled = True
                    return {
                        'success': True,
                        'message': 'Shipment cancelled successfully',
                        'data': response_data
                    }
                elif isinstance(first_item.get('message'), dict):
                    message_data = first_item['message']
                    if message_data.get('statusName') == 'Cancelled':
                        is_cancelled = True
                        return {
                            'success': True,
                            'message': 'Shipment cancelled successfully',
                            'status_name': 'Cancelled',
                            'update_date': message_data.get('updateDate'),
                            'comment': message_data.get('comment', reason),
                            'data': response_data
                        }
            
            # Check for direct message object response
            elif isinstance(response_data, dict) and response_data.get('statusName') == 'Cancelled':
                is_cancelled = True
                return {
                    'success': True,
                    'message': 'Shipment cancelled successfully',
                    'status_name': 'Cancelled',
                    'update_date': response_data.get('updateDate'),
                    'comment': response_data.get('comment', reason),
                    'data': response_data
                }
            
            # If HTTP status is 200 but none of the above conditions are met
            elif response.status_code == 200:
                # We got a 200 HTTP status but couldn't determine specific success
                # from the response body - still assume success
                logger.info(f"Received 200 HTTP status with non-standard body. Assuming success.")
                return {
                    'success': True,
                    'message': 'Cancellation request processed',
                    'data': response_data
                }
                
            # Handle error responses - extract as much information as possible
            error_message = "Failed to cancel shipment"
            
            # Try to extract error message from response data
            if isinstance(response_data, dict):
                # First check if there's an error message in a field like 'message', 'error', etc.
                for error_field in ['message', 'error', 'errorMessage', 'description']:
                    if error_field in response_data:
                        # If the message field is another dict, look deeper
                        if isinstance(response_data[error_field], dict):
                            # If there's a statusName that's not 'Cancelled', use that
                            if 'statusName' in response_data[error_field] and response_data[error_field]['statusName'] != 'Cancelled':
                                error_message = f"Status: {response_data[error_field]['statusName']}"
                            # Or use a comment if available
                            elif 'comment' in response_data[error_field]:
                                error_message = response_data[error_field]['comment']
                        else:
                            error_message = str(response_data[error_field])
                        break
            elif isinstance(response_data, list) and len(response_data) > 0:
                first_item = response_data[0]
                for error_field in ['message', 'error', 'errorMessage', 'description']:
                    if error_field in first_item:
                        error_message = str(first_item[error_field])
                        break
                        
            # Check if error message indicates shipment is already cancelled
            if ('already cancelled' in error_message.lower() or 
                'already canceled' in error_message.lower() or
                'cannot cancel' in error_message.lower()):
                return {
                    'success': True,
                    'message': 'Shipment appears to be already cancelled',
                    'was_already_cancelled': True
                }
                
            # Check if status code is ok but error parsed from body
            if response.status_code == 200:
                # Even with an error message, if HTTP status is 200, 
                # we might want to consider it a success
                logger.warning(f"Got success HTTP code (200) but error message: {error_message}")
                return {
                    'success': True,
                    'message': 'Request processed but returned unexpected response',
                    'warning': error_message,
                    'data': response_data
                }
            
            # General error case
            logger.error(f"Failed to cancel shipment: {error_message}")
            return {
                'success': False,
                'error': error_message,
                'http_status': response.status_code
            }
                
        except Exception as e:
            error_message = f"Error cancelling shipment: {str(e)}"
            logger.error(error_message)
            return {
                'success': False,
                'error': error_message
            }
        

    def get_pickup_addresses(self):
        """Fetch all pickup addresses for the customer from QuixGo"""
        if not self.token:
            self.login()
                
        # Use the full URL directly to debug the issue
        url = "https://api.quixgo.com/v1/address/getByCustomerId/B2C"
        
        logger.info(f"Making request to URL: {url}")
        
        payload = {
            "limit": 10,
            "page": 1,
            "filter": {
                "customerId": self.customer_id,
                "addressCategory": "pickup"
            },
            "sortBy": "createdAt",
            "order": "desc"
        }
        
        headers = self.get_auth_header()
        headers['Content-Type'] = 'application/json'
        
        logger.info(f"Request payload: {payload}")
        
        response = requests.post(
            url, 
            headers=headers,
            json=payload
        )
        
        if response.status_code == 200:
            data = response.json()
            logger.info(f"QuixGo API Response: {data}")
            return {
                'success': True,
                'addresses': data.get('rows', [])
            }
        else:
            logger.error(f"Failed to fetch pickup addresses: {response.status_code} - {response.text}")
            return {
                'success': False,
                'error': response.text
            }
    # def get_pickup_addresses(self):
    #     """Fetch all pickup addresses for the customer from QuixGo"""
    #     if not self.token:
    #         self.login()
            
    #     url = f"{self.api_base_url}/v1/address/getByCustomerId/B2C"
        
    #     # Create payload matching the curl command
    #     payload = {
    #         "limit": 10,
    #         "page": 1,
    #         "filter": {
    #             "customerId": self.customer_id,
    #             "addressCategory": "pickup"
    #         },
    #         "sortBy": "createdAt",
    #         "order": "desc"
    #     }
        
    #     # Send a POST request, not GET
    #     response = requests.post(
    #         url, 
    #         headers=self.get_auth_header(),
    #         json=payload
    #     )
        
    #     if response.status_code == 200:
    #         data = response.json()
            
    #         return {
    #             'success': True,
    #             'addresses': data.get('addresses', [])
    #         }
    #     else:
    #         logger.error(f"Failed to fetch pickup addresses: {response.text}")
    #         return {
    #             'success': False,
    #             'error': response.text
    #         }
    # def get_pickup_addresses(self):
    #     """Fetch all pickup addresses for the customer from QuixGo"""
    #     if not self.token:
    #         self.login()
            
    #     url = f"{self.api_base_url}/address/getByCustomerId/B2C"
        
    #     response = requests.get(
    #         url, 
    #         headers=self.get_auth_header()
    #     )
        
    #     if response.status_code == 200:
    #         data = response.json()
    #         return {
    #             'success': True,
    #             'addresses': data.get('addresses', [])
    #         }
    #     else:
    #         logger.error(f"Failed to fetch pickup addresses: {response.text}")
    #         return {
    #             'success': False,
    #             'error': response.text
    #         }