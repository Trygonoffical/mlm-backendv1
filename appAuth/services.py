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
                    "weight": str(shipment_data.get('weight', '1')),
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
                "serviceMode": "FW"  # Forward shipment
            }]
            
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
        """Track a shipment using AWB number"""
        try:
            if not self.token:
                self.login()
                
            url = f"{self.api_base_url}/trackStatus"
            
            payload = {
                "awbNumber": awb_number
            }
            
            response = requests.post(url, headers=self.get_auth_header(), json=payload)
            
            if response.status_code == 200:
                data = response.json()
                shipment_info = data.get('shipmentInfo', {})
                return {
                    'success': True,
                    'current_status': shipment_info.get('currentStatus'),
                    'status_history': shipment_info.get('statusHistory', []),
                    'data': shipment_info
                }
            else:
                logger.error(f"Failed to track shipment: {response.text}")
                return {
                    'success': False,
                    'error': response.text
                }
                
        except Exception as e:
            logger.error(f"Error tracking shipment: {str(e)}")
            return {
                'success': False,
                'error': str(e)
            }
    
    def cancel_shipment(self, awb_number, reason="Order cancelled"):
        """Cancel a shipment"""
        try:
            if not self.token:
                self.login()
                
            url = f"{self.api_base_url}/v2/cancelShipment"
            
            payload = [{
                "msg": reason,
                "awbNumber": awb_number,
                "customerId": self.customer_id
            }]
            
            response = requests.post(url, headers=self.get_auth_header(), json=payload)
            
            if response.status_code == 200:
                data = response.json()
                return {
                    'success': True,
                    'status': data.get('message', {}).get('statusName'),
                    'data': data
                }
            else:
                logger.error(f"Failed to cancel shipment: {response.text}")
                return {
                    'success': False,
                    'error': response.text
                }
                
        except Exception as e:
            logger.error(f"Error cancelling shipment: {str(e)}")
            return {
                'success': False,
                'error': str(e)
            }
        

    def get_pickup_addresses(self):
        """Fetch all pickup addresses for the customer from QuixGo"""
        if not self.token:
            self.login()
            
        url = f"{self.api_base_url}/address/getByCustomerId/B2C"
        
        response = requests.get(
            url, 
            headers=self.get_auth_header()
        )
        
        if response.status_code == 200:
            data = response.json()
            return {
                'success': True,
                'addresses': data.get('addresses', [])
            }
        else:
            logger.error(f"Failed to fetch pickup addresses: {response.text}")
            return {
                'success': False,
                'error': response.text
            }