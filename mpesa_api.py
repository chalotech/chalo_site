import requests
import json
import base64
from datetime import datetime
import os
from dotenv import load_dotenv
import qrcode
import base64
from io import BytesIO

load_dotenv()

class MpesaAPI:
    def __init__(self):
        self.business_shortcode = os.getenv('MPESA_BUSINESS_SHORTCODE')
        self.consumer_key = os.getenv('MPESA_CONSUMER_KEY')
        self.consumer_secret = os.getenv('MPESA_CONSUMER_SECRET')
        self.passkey = os.getenv('MPESA_PASSKEY')
        self.callback_url = os.getenv('MPESA_CALLBACK_URL')
        
        # API endpoints
        self.auth_url = "https://api.safaricom.co.ke/oauth/v1/generate?grant_type=client_credentials"
        self.stk_push_url = "https://api.safaricom.co.ke/mpesa/stkpush/v1/processrequest"
        
    def get_auth_token(self):
        """Get OAuth token from Safaricom"""
        try:
            auth_string = base64.b64encode(
                f"{self.consumer_key}:{self.consumer_secret}".encode()
            ).decode()
            
            headers = {
                "Authorization": f"Basic {auth_string}"
            }
            
            response = requests.get(self.auth_url, headers=headers)
            response.raise_for_status()
            
            result = response.json()
            return result.get('access_token')
            
        except requests.exceptions.RequestException as e:
            print(f"Error getting auth token: {str(e)}")
            return None
            
    def generate_password(self):
        """Generate password for STK push"""
        timestamp = datetime.now().strftime('%Y%m%d%H%M%S')
        password_str = f"{self.business_shortcode}{self.passkey}{timestamp}"
        return base64.b64encode(password_str.encode()).decode(), timestamp
        
    def initiate_stk_push(self, phone_number, amount, reference):
        """Initiate STK push to customer's phone"""
        try:
            access_token = self.get_auth_token()
            if not access_token:
                return {
                    'success': False,
                    'message': 'Unable to authenticate with M-Pesa. Please try again later.'
                }
                
            # Format phone number
            phone_number = phone_number.replace("+", "").strip()
            if not phone_number.startswith("254"):
                if phone_number.startswith("0"):
                    phone_number = "254" + phone_number[1:]
                elif phone_number.startswith("7") or phone_number.startswith("1"):
                    phone_number = "254" + phone_number
                    
            if not phone_number.isdigit() or len(phone_number) != 12:
                return {
                    'success': False,
                    'message': 'Invalid phone number format. Please use format: 254XXXXXXXXX'
                }
                
            password, timestamp = self.generate_password()
            
            headers = {
                "Authorization": f"Bearer {access_token}",
                "Content-Type": "application/json"
            }
            
            payload = {
                "BusinessShortCode": self.business_shortcode,
                "Password": password,
                "Timestamp": timestamp,
                "TransactionType": "CustomerPayBillOnline",
                "Amount": int(amount),
                "PartyA": phone_number,
                "PartyB": self.business_shortcode,
                "PhoneNumber": phone_number,
                "CallBackURL": self.callback_url,
                "AccountReference": reference[:20],  # M-Pesa limits this to 20 chars
                "TransactionDesc": f"Payment for {reference[:20]}"
            }
            
            response = requests.post(
                self.stk_push_url,
                headers=headers,
                json=payload,
                timeout=30  # Add timeout
            )
            response.raise_for_status()
            
            result = response.json()
            
            if result.get('ResponseCode') == '0':
                return {
                    'success': True,
                    'message': 'Please check your phone for the STK push prompt',
                    'checkout_request_id': result.get('CheckoutRequestID')
                }
            else:
                return {
                    'success': False,
                    'message': result.get('ResponseDescription', 'Failed to initiate payment. Please try again.')
                }
                
        except requests.exceptions.RequestException as e:
            print(f"Error initiating STK push: {str(e)}")
            return {
                'success': False,
                'message': 'Failed to connect to M-Pesa. Please try again later.'
            }
        except Exception as e:
            print(f"Unexpected error during STK push: {str(e)}")
            return {
                'success': False,
                'message': 'An unexpected error occurred. Please try again later.'
            }

    def verify_transaction(self, checkout_request_id):
        """Verify transaction status"""
        try:
            access_token = self.get_auth_token()
            if not access_token:
                return {
                    'success': False,
                    'message': 'Failed to get access token'
                }
                
            headers = {
                "Authorization": f"Bearer {access_token}",
                "Content-Type": "application/json"
            }
            
            query_url = "https://api.safaricom.co.ke/mpesa/stkpushquery/v1/query"
            password, timestamp = self.generate_password()
            
            payload = {
                "BusinessShortCode": self.business_shortcode,
                "Password": password,
                "Timestamp": timestamp,
                "CheckoutRequestID": checkout_request_id
            }
            
            response = requests.post(
                query_url,
                headers=headers,
                json=payload
            )
            response.raise_for_status()
            
            result = response.json()
            return {
                'success': True,
                'result': result
            }
            
        except requests.exceptions.RequestException as e:
            return {
                'success': False,
                'message': f'Error verifying transaction: {str(e)}'
            }

    def generate_mpesa_qr(self, phone_number, amount, reference):
        """Generate M-Pesa QR code that opens SIM toolkit with pre-filled details."""
        # Format phone number (remove + and spaces)
        phone_number = phone_number.replace("+", "").replace(" ", "")
        
        # Format amount to whole number (M-Pesa doesn't use decimals)
        amount = str(int(round(float(amount))))
        
        # Create STK URL scheme
        # Format: mpesa://send?phone=[number]&amount=[amount]&reference=[ref]
        stk_url = f"mpesa://send?phone={phone_number}&amount={amount}&reference={reference}"
        
        qr = qrcode.QRCode(
            version=1,
            error_correction=qrcode.constants.ERROR_CORRECT_H,  # Higher error correction for better scanning
            box_size=10,
            border=4,
        )
        qr.add_data(stk_url)
        qr.make(fit=True)

        img = qr.make_image(fill_color="black", back_color="white")
        buffered = BytesIO()
        img.save(buffered, format="PNG")
        img_str = base64.b64encode(buffered.getvalue()).decode()
        return f"data:image/png;base64,{img_str}"
