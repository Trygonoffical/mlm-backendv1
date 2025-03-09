# shipping/services.py

import requests
import json
import logging
from django.conf import settings
from datetime import datetime, timedelta
from django.utils import timezone


from .models import ShippingConfig
logger = logging.getLogger(__name__)

class QuixGoShippingService:
    """
    Service class to interact with QuixGo Shipping API
    """
    BASE_URL = "https://dev.api.quixgo.com/clientApi"
    # "https://api.quixgo.com/clientApi"  # Production URL
    # Use "https://dev.api.quixgo.com/clientApi" for testing

    def __init__(self, email=None, password=None):
        """
        Initialize with credentials.
        If not provided, will try to fetch from database.
        """
        from home.models import ShippingConfig
        self.config = ShippingConfig.get_config()
        self.email = email or self.config.quixgo_email
        self.password = password or self.config.quixgo_password
        self.customer_id = self.config.quixgo_customer_id
        self.token = self._get_auth_token()

    def _get_auth_token(self):
        """Get authentication token, refreshing if necessary"""
        if self.is_token_valid():
            return self.config.auth_token
        
        try:
            response = self.login()
            if response and 'token' in response:
                # Save token to config
                self.config.auth_token = response['token']
                self.config.token_expiry = timezone.now() + timedelta(hours=10)
                self.config.save()
                return self.config.auth_token
        except Exception as e:
            logger.error(f"Error getting auth token: {str(e)}")
        
        return None

    def is_token_valid(self):
        """Check if current token is valid"""
        if not self.config.auth_token or not self.config.token_expiry:
            return False
        
        # Add a buffer of 5 minutes
        buffer_time = timezone.now() + timedelta(minutes=5)
        return buffer_time < self.config.token_expiry

    def login(self):
        """
        Log in to QuixGo API and get authentication token
        Returns the full response data including:
        - annotation_id (customer_id)
        - token
        """
        try:
            url = f"{self.BASE_URL}/login"
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
                
                # Update instance variables
                self.token = data.get('token')
                self.customer_id = data.get('annotation_id')
                
                # Update the database configuration
                self.config.quixgo_customer_id = self.customer_id
                self.config.auth_token = self.token
                self.config.token_expiry = timezone.now() + timedelta(hours=10)
                self.config.save()
                
                logger.info(f"Successfully logged in to QuixGo API as {self.email}")
                return data
            else:
                logger.error(f"QuixGo login failed: {response.text}")
                return None
                
        except Exception as e:
            logger.error(f"Error logging in to QuixGo: {str(e)}")
            return None

    def test_connection(self):
        """Test connection to QuixGo API"""
        token = self._get_auth_token()
        if not token:
            return {
                'success': False,
                'error': 'Authentication failed'
            }
        
        return {
            'success': True,
            'message': 'Successfully connected to QuixGo API'
        }
    
    def create_pickup_address(self, address_data):
        """
        Create a pickup address in QuixGo
        
        Parameters:
        address_data (dict): Dictionary containing address details including:
            - name: Pickup point name
            - contact_person: Contact person name
            - address_line1: Address line 1
            - address_line2: Address line 2 (optional)
            - city: City
            - state: State
            - country: Country (default 'India')
            - pincode: PIN code
            - phone: Contact phone
            - alternate_phone: Alternate phone (optional)
            - email: Email (optional)
            - landmark: Landmark (optional)
            - address_type: Address type (Home/Office/Warehouse)
        
        Returns:
        dict: Response including success status and address ID if successful
        """
        token = self._get_auth_token()
        if not token:
            return {
                'success': False,
                'error': 'Authentication failed'
            }
        
        try:
            pickup_url = f"{self.BASE_URL}/addPickupPoint"
            
            # Convert our field names to QuixGo field names
            payload = {
                "pickupName": address_data.get('name', ''),
                "customerId": self.customer_id,
                "cpPerson": address_data.get('contact_person', ''),
                "address1": address_data.get('address_line1', ''),
                "address2": address_data.get('address_line2', ''),
                "city": address_data.get('city', ''),
                "state": address_data.get('state', ''),
                "country": address_data.get('country', 'India'),
                "addressType": address_data.get('address_type', 'Office'),
                "pincode": address_data.get('pincode', ''),
                "cpMobile": address_data.get('phone', ''),
                "alternateNumber": address_data.get('alternate_phone', ''),
                "email": address_data.get('email', ''),
                "landmark": address_data.get('landmark', '')
            }
            
            headers = {
                "Content-Type": "application/json",
                "Authorization": token
            }
            
            response = requests.post(pickup_url, json=payload, headers=headers)
            
            if response.status_code != 200:
                logger.error(f"QuixGo pickup address creation failed: {response.text}")
                return {
                    'success': False,
                    'error': response.text
                }
                
            data = response.json()
            return {
                'success': True,
                'address_id': data.get('addressId'),
                'data': data
            }
            
        except Exception as e:
            logger.error(f"Error creating pickup address: {str(e)}")
            return {
                'success': False,
                'error': str(e)
            }

    def book_shipment(self, order, pickup_address_id, delivery_address):
        """
        Book a shipment with QuixGo
        
        Parameters:
        order (Order): The order object containing items and details
        pickup_address_id (str): The QuixGo address ID for pickup
        delivery_address (dict): Delivery address details
        
        Returns:
        dict: Response including success status and shipment details if successful
        """
        token = self._get_auth_token()
        if not token:
            return {
                'success': False,
                'error': 'Authentication failed'
            }
        
        try:
            booking_url = f"{self.BASE_URL}/v2/bookShipment"
            
            # Get pickup address details from database
            from home.models import PickupAddress
            pickup_address = PickupAddress.objects.get(address_id=pickup_address_id)
            
            # Prepare payload for QuixGo
            payload = [{
                "deliveryAddress": {
                    "name": delivery_address.get('name', ''),
                    "address1": delivery_address.get('address1', ''),
                    "address2": delivery_address.get('address2', ''),
                    "landmark": delivery_address.get('landmark', ''),
                    "city": delivery_address.get('city', ''),
                    "state": delivery_address.get('state', ''),
                    "pincode": delivery_address.get('pincode', ''),
                    "mobile": delivery_address.get('mobile', ''),
                    "alternateNumber": delivery_address.get('alternateNumber', ''),
                    "email": delivery_address.get('email', ''),
                    "addressType": delivery_address.get('addressType', 'Home')
                },
                "pickupAddress": {
                    "addressId": pickup_address.address_id,
                    "customerId": self.customer_id,
                    "pickupName": pickup_address.name,
                    "addressCategory": "pickup",
                    "addressType": pickup_address.address_type,
                    "shipmentType": "B2C",
                    "cpPerson": pickup_address.contact_person,
                    "address1": pickup_address.address_line1,
                    "address2": pickup_address.address_line2,
                    "city": pickup_address.city,
                    "state": pickup_address.state,
                    "country": pickup_address.country,
                    "landmark": pickup_address.landmark,
                    "pincode": pickup_address.pincode,
                    "cpMobile": pickup_address.phone,
                    "alternateNumber": pickup_address.alternate_phone,
                    "email": pickup_address.email,
                    "isActive": True,
                    "isDeleted": False,
                    "addName": pickup_address.name
                },
                # Use the same pickup address as return address
                "returnAddress": {
                    "addressId": pickup_address.address_id,
                    "customerId": self.customer_id,
                    "pickupName": pickup_address.name,
                    "addressCategory": "pickup",
                    "addressType": pickup_address.address_type,
                    "shipmentType": "B2C",
                    "cpPerson": pickup_address.contact_person,
                    "address1": pickup_address.address_line1,
                    "address2": pickup_address.address_line2,
                    "city": pickup_address.city,
                    "state": pickup_address.state,
                    "country": pickup_address.country,
                    "landmark": pickup_address.landmark,
                    "pincode": pickup_address.pincode,
                    "cpMobile": pickup_address.phone,
                    "alternateNumber": pickup_address.alternate_phone,
                    "email": pickup_address.email,
                    "isActive": True,
                    "isDeleted": False,
                    "addName": pickup_address.name
                },
                "customerType": "Normal",
                "productDetails": {
                    "weight": "1",  # Default weight 1 kg
                    "height": "10",  # Default height 10 cm
                    "width": "10",   # Default width 10 cm
                    "length": "10",  # Default length 10 cm
                    "invoice": str(int(order.final_amount)),  # Invoice value - convert to whole number
                    "productName": "Order Products",
                    "productType": "Merchandise",
                    "quantity": "1",  # Treating the entire order as one package
                    "orderNumber": order.order_number
                },
                "serviceProvider": "DTC",  # Default to DTDC
                "serviceType": "SF",       # Default to Surface shipping
                "paymentMode": "COD" if order.orderType == "COD" else "Prepaid",
                "customerId": self.customer_id,
                "serviceMode": "FW",       # Forward shipment
                "bookingChannel": "web"    # Web booking
            }]
            
            # Add COD amount if applicable
            if order.orderType == "COD":
                payload[0]['productDetails']['codAmount'] = str(int(order.final_amount))
            
            headers = {
                "Content-Type": "application/json",
                "Authorization": token
            }
            
            response = requests.post(booking_url, json=payload, headers=headers)
            
            if response.status_code != 200:
                logger.error(f"QuixGo shipment booking failed: {response.text}")
                return {
                    'success': False,
                    'error': response.text
                }
                
            data = response.json()
            
            # Check if shipment was created successfully
            if data and len(data) > 0 and data[0].get('success'):
                shipment_data = data[0].get('data', {})
                return {
                    'success': True,
                    'shipment_id': shipment_data.get('shipmentId'),
                    'awb_number': shipment_data.get('awbNumber'),
                    'courier': shipment_data.get('shipmentPartner'),
                    'charge': shipment_data.get('finalCharge'),
                    'data': shipment_data
                }
            else:
                error_message = data[0].get('message', 'Unknown error') if data and len(data) > 0 else 'Unknown error'
                logger.error(f"QuixGo shipment booking error: {error_message}")
                return {
                    'success': False,
                    'error': error_message
                }
            
        except Exception as e:
            logger.error(f"Error booking shipment: {str(e)}")
            return {
                'success': False,
                'error': str(e)
            }

    def track_shipment(self, awb_number):
        """
        Track a shipment with QuixGo
        
        Parameters:
        awb_number (str): The AWB number to track
        
        Returns:
        dict: Response including tracking data
        """
        token = self._get_auth_token()
        if not token:
            return {
                'success': False,
                'error': 'Authentication failed'
            }
        
        try:
            tracking_url = f"{self.BASE_URL}/trackStatus"
            
            payload = {
                "awbNumber": awb_number
            }
            
            headers = {
                "Content-Type": "application/json",
                "Authorization": token
            }
            
            response = requests.post(tracking_url, json=payload, headers=headers)
            
            if response.status_code != 200:
                logger.error(f"QuixGo tracking failed: {response.text}")
                return {
                    'success': False,
                    'error': response.text
                }
                
            data = response.json()
            
            # Extract shipping info from response
            shipment_info = data.get('shipmentInfo', {})
            current_status = shipment_info.get('currentStatus', 'Unknown')
            status_history = shipment_info.get('statusHistory', [])
            
            return {
                'success': True,
                'current_status': current_status,
                'status_history': status_history,
                'data': shipment_info
            }
            
        except Exception as e:
            logger.error(f"Error tracking shipment: {str(e)}")
            return {
                'success': False,
                'error': str(e)
            }

    def cancel_shipment(self, awb_number, reason="Cancelled by customer"):
        """
        Cancel a shipment with QuixGo
        
        Parameters:
        awb_number (str): The AWB number to cancel
        reason (str): Reason for cancellation
        
        Returns:
        dict: Response including cancellation status
        """
        token = self._get_auth_token()
        if not token:
            return {
                'success': False,
                'error': 'Authentication failed'
            }
        
        try:
            cancel_url = f"{self.BASE_URL}/v2/cancelShipment"
            
            payload = [{
                "msg": reason,
                "awbNumber": awb_number,
                "customerId": self.customer_id
            }]
            
            headers = {
                "Content-Type": "application/json",
                "Authorization": token
            }
            
            response = requests.post(cancel_url, json=payload, headers=headers)
            
            if response.status_code != 200:
                logger.error(f"QuixGo shipment cancellation failed: {response.text}")
                return {
                    'success': False,
                    'error': response.text
                }
                
            data = response.json()
            
            return {
                'success': True,
                'status': data.get('status'),
                'message': data.get('message', {}),
                'data': data
            }
            
        except Exception as e:
            logger.error(f"Error cancelling shipment: {str(e)}")
            return {
                'success': False,
                'error': str(e)
            }