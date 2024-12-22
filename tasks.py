from celery_app import celery
from flask import current_app
from flask_mail import Message
from app import mail, db, Purchase, File, User
import africastalking
import paypalrestsdk
import os
from datetime import datetime

@celery.task
def send_async_email(subject, recipients, body, html=None):
    """Send email asynchronously"""
    with current_app.app_context():
        msg = Message(subject, recipients=recipients, body=body, html=html)
        mail.send(msg)

@celery.task
def process_mpesa_payment(purchase_id, phone_number):
    """Process M-Pesa payment asynchronously"""
    with current_app.app_context():
        try:
            purchase = Purchase.query.get(purchase_id)
            if not purchase:
                return {'success': False, 'message': 'Purchase not found'}

            # Configure Africa's Talking
            africastalking.initialize(
                username=os.getenv('AT_USERNAME'),
                api_key=os.getenv('AT_API_KEY')
            )
            payments = africastalking.Payment

            # Prepare payment data
            payment_data = {
                "productName": "Chalo Site Download",
                "phoneNumber": phone_number,
                "currencyCode": "KES",
                "amount": float(purchase.amount) * 100,  # Convert to KES
                "metadata": {
                    "purchase_id": purchase_id,
                    "file_name": purchase.file.name
                }
            }

            # Initialize payment
            try:
                response = payments.mobile_checkout(**payment_data)
                purchase.transaction_id = response.get('transactionId')
                db.session.commit()
                return {
                    'success': True,
                    'message': 'Payment initiated successfully',
                    'transaction_id': response.get('transactionId')
                }
            except Exception as e:
                return {'success': False, 'message': str(e)}

        except Exception as e:
            return {'success': False, 'message': f'Error processing payment: {str(e)}'}

@celery.task
def check_payment_status(purchase_id):
    """Check payment status asynchronously"""
    with current_app.app_context():
        try:
            purchase = Purchase.query.get(purchase_id)
            if not purchase:
                return {'success': False, 'message': 'Purchase not found'}

            if purchase.payment_status == 'completed':
                return {
                    'success': True,
                    'status': 'completed',
                    'redirect': '/dashboard'
                }
            elif purchase.payment_status == 'failed':
                return {
                    'success': False,
                    'status': 'failed',
                    'message': 'Payment failed'
                }
            else:
                return {
                    'success': True,
                    'status': 'pending',
                    'message': 'Payment is still processing'
                }

        except Exception as e:
            return {
                'success': False,
                'status': 'error',
                'message': f'Error checking payment status: {str(e)}'
            }

@celery.task
def cleanup_expired_purchases():
    """Clean up expired purchases and temporary files"""
    with current_app.app_context():
        try:
            # Find expired purchases (older than 24 hours and still pending)
            expired_purchases = Purchase.query.filter(
                Purchase.payment_status == 'pending',
                Purchase.purchase_date < datetime.utcnow() - timedelta(hours=24)
            ).all()

            for purchase in expired_purchases:
                # Delete the purchase
                db.session.delete(purchase)

            db.session.commit()
            return {'success': True, 'message': f'Cleaned up {len(expired_purchases)} expired purchases'}

        except Exception as e:
            return {'success': False, 'message': f'Error cleaning up expired purchases: {str(e)}'}

@celery.task
def process_file_upload(file_id):
    """Process uploaded file asynchronously (e.g., generate preview, validate file)"""
    with current_app.app_context():
        try:
            file = File.query.get(file_id)
            if not file:
                return {'success': False, 'message': 'File not found'}

            # TODO: Add file processing logic here
            # - Generate preview images
            # - Scan for viruses
            # - Generate metadata
            # - etc.

            return {'success': True, 'message': 'File processed successfully'}

        except Exception as e:
            return {'success': False, 'message': f'Error processing file: {str(e)}'}
