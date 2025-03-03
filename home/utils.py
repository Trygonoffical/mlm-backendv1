from django.db import transaction
from decimal import Decimal
from django.utils import timezone
from datetime import datetime, timedelta
import logging
from home.models import Commission, Notification, MLMMember

logger = logging.getLogger(__name__)

def update_bp_points_on_order(order):
    """
    Update BP points when an order is placed and confirmed
    """
    try:
        # Only process confirmed/completed orders
        if order.status not in ['CONFIRMED', 'SHIPPED', 'DELIVERED']:
            logger.info(f"Order {order.id} status is {order.status}, not updating BP")
            return False
            
        # Get member if user is MLM member
        if order.user.role != 'MLM_MEMBER':
            logger.info(f"User {order.user.id} is not MLM_MEMBER, not updating BP")
            return False
            
        member = order.user.mlm_profile
        logger.info(f"Processing BP update for member {member.member_id} from order {order.id}")
        
        with transaction.atomic():
            # Add BP points from order to member
            old_bp = member.total_bp
            member.total_bp += order.total_bp
            
            # Update monthly purchase amount
            member.current_month_purchase += order.final_amount
            member.save()
            
            logger.info(f"Updated BP for {member.member_id}: {old_bp} → {member.total_bp}")
            
            # Check for position upgrade
            if member.check_position_upgrade():
                logger.info(f"Member {member.member_id} upgraded position to {member.position.name}")
                
            return True
            
    except Exception as e:
        logger.error(f"Error updating BP points on order {order.id}: {str(e)}")
        return False


def calculate_monthly_commissions():
    """
    Calculate monthly commissions for all MLM members
    This should be run on the 1st of each month
    """
    try:
        today = timezone.now()
        # Only run on the 1st of the month
        if today.day != 1:
            logger.info(f"Today is not the 1st of the month, skipping commission calculation")
            return False
            
        # Define the date range for last month
        first_day_current_month = today.replace(day=1, hour=0, minute=0, second=0, microsecond=0)
        last_day_previous_month = first_day_current_month - timedelta(days=1)
        first_day_previous_month = last_day_previous_month.replace(day=1)
        
        logger.info(f"Calculating commissions for period: {first_day_previous_month} to {last_day_previous_month}")
        
        # Get all active MLM members who meet the monthly quota
        from home.models import MLMMember, Order, Commission
        
        # Get active members
        active_members = MLMMember.objects.filter(is_active=True)
        logger.info(f"Found {active_members.count()} active members")
        
        # Commission tracking
        commissions_created = 0
        bp_updates = 0
        
        for member in active_members:
            # Check if member meets the monthly quota
            meets_quota = member.check_monthly_quota_maintenance(first_day_current_month)
            if not meets_quota:
                logger.info(f"Member {member.member_id} does not meet monthly quota, skipping")
                continue
                
            logger.info(f"Processing commissions for member {member.member_id}")
            
            # Get all direct downline members
            downline_members = MLMMember.objects.filter(sponsor=member)
            
            # Track total BP to add to this member
            total_bp_to_add = 0
            
            # Process each downline member
            for downline in downline_members:
                # Skip inactive downline members
                if not downline.is_active:
                    logger.info(f"Downline {downline.member_id} is inactive, skipping")
                    continue
                    
                # Calculate position difference percentage
                member_percentage = member.position.discount_percentage
                downline_percentage = downline.position.discount_percentage
                
                # Skip if downline has equal or higher position
                if downline_percentage >= member_percentage:
                    logger.info(f"Downline {downline.member_id} (at {downline_percentage}%) has equal or higher position than member {member.member_id} (at {member_percentage}%), skipping")
                    continue
                    
                difference_percentage = member_percentage - downline_percentage
                
                # Get downline's orders for the previous month
                downline_orders = Order.objects.filter(
                    user=downline.user,
                    order_date__gte=first_day_previous_month,
                    order_date__lt=first_day_current_month,
                    status__in=['CONFIRMED', 'SHIPPED', 'DELIVERED']
                )
                
                # Calculate total business done by downline
                total_business = sum(order.final_amount for order in downline_orders)
                if total_business <= 0:
                    logger.info(f"Downline {downline.member_id} had no business last month, skipping")
                    continue
                
                # Calculate commission amount
                commission_amount = (total_business * Decimal(difference_percentage)) / Decimal('100')
                
                if commission_amount > 0:
                    # Create commission record
                    Commission.objects.create(
                        member=member,
                        from_member=downline,
                        order=None,  # This is a monthly calculated commission, not tied to a specific order
                        amount=commission_amount,
                        date=first_day_current_month,
                        is_paid=False,  # Will be paid after withdrawal approval
                        level=1,  # Direct downline
                        is_first_purchase_bonus=False
                    )
                    commissions_created += 1
                    logger.info(f"Created commission of {commission_amount} for {member.member_id} from {downline.member_id}")
                
                # Add downline's BP to sponsor
                total_bp_to_add += downline.total_bp
                logger.info(f"Will add {downline.total_bp} BP from {downline.member_id} to {member.member_id}")
            
            # Update member's BP with downline BP
            if total_bp_to_add > 0:
                old_bp = member.total_bp
                member.total_bp += total_bp_to_add
                member.save()
                bp_updates += 1
                logger.info(f"Updated BP for {member.member_id}: {old_bp} → {member.total_bp}")
        
        logger.info(f"Commission calculation completed. Created {commissions_created} commissions and {bp_updates} BP updates.")
        return True
            
    except Exception as e:
        logger.error(f"Error calculating monthly commissions: {str(e)}")
        return False


def update_withdrawal_request_status():
    """
    Update withdrawal request status to allow processing after the 15th of the month
    """
    try:
        today = timezone.now()
        
        # If it's after the 15th, update pending withdrawal requests to be ready for processing
        if today.day >= 15:
            from home.models import WithdrawalRequest
            
            # Get all pending withdrawal requests
            pending_requests = WithdrawalRequest.objects.filter(status='PENDING')
            
            # Update the requests to indicate they're ready for processing
            for request in pending_requests:
                # You could add a custom field like 'is_ready_for_processing' or use a different status
                # For now, just logging that they're ready
                logger.info(f"Withdrawal request {request.id} for {request.wallet.user.username} is ready for processing")
            
            return True
        
        return False
    
    except Exception as e:
        logger.error(f"Error updating withdrawal request status: {str(e)}")
        return False


def get_live_commission_data(member):
    """
    Get live commission data for a member to show current month's progress
    """
    try:
        from home.models import MLMMember, Order, Commission
        from decimal import Decimal
        
        # Return data structure
        result = {
            'current_month_estimate': Decimal('0.00'),
            'last_month_earned': Decimal('0.00'),
            'pending_withdrawals': Decimal('0.00'),
            'downline_performance': []
        }
        
        # Get current month start date
        today = timezone.now()
        first_day_current_month = today.replace(day=1, hour=0, minute=0, second=0, microsecond=0)
        
        # Get last month start and end dates
        last_month_end = first_day_current_month - timedelta(days=1)
        first_day_last_month = last_month_end.replace(day=1)
        
        # Get all direct downline members
        downline_members = MLMMember.objects.filter(sponsor=member)
        
        # Get last month's earned commissions (already processed)
        last_month_commissions = Commission.objects.filter(
            member=member,
            date__gte=first_day_last_month,
            date__lt=first_day_current_month
        )
        result['last_month_earned'] = sum(comm.amount for comm in last_month_commissions)
        
        # Get pending withdrawals
        from home.models import WithdrawalRequest
        pending_withdrawals = WithdrawalRequest.objects.filter(
            wallet__user=member.user,
            status='PENDING'
        )
        result['pending_withdrawals'] = sum(withdrawal.amount for withdrawal in pending_withdrawals)
        
        # Calculate current month's estimate from downline performance
        for downline in downline_members:
            # Skip inactive downline members
            if not downline.is_active:
                continue
                
            # Calculate position difference percentage
            member_percentage = member.position.discount_percentage
            downline_percentage = downline.position.discount_percentage
            
            # Skip if downline has equal or higher position
            if downline_percentage >= member_percentage:
                continue
                
            difference_percentage = member_percentage - downline_percentage
            
            # Get downline's orders for current month
            downline_orders = Order.objects.filter(
                user=downline.user,
                order_date__gte=first_day_current_month,
                status__in=['CONFIRMED', 'SHIPPED', 'DELIVERED']
            )
            
            # Calculate total business done by downline this month
            total_business = sum(order.final_amount for order in downline_orders)
            
            # Calculate estimated commission amount
            estimated_commission = (total_business * Decimal(difference_percentage)) / Decimal('100')
            result['current_month_estimate'] += estimated_commission
            
            # Add downline performance data
            result['downline_performance'].append({
                'member_id': downline.member_id,
                'name': f"{downline.user.first_name} {downline.user.last_name}",
                'position': downline.position.name,
                'position_percentage': float(downline_percentage),
                'total_business': float(total_business),
                'commission_percentage': float(difference_percentage),
                'estimated_commission': float(estimated_commission),
                'bp_points': downline.total_bp
            })
        
        # Convert decimal values to float for JSON serialization
        result['current_month_estimate'] = float(result['current_month_estimate'])
        result['last_month_earned'] = float(result['last_month_earned'])
        result['pending_withdrawals'] = float(result['pending_withdrawals'])
        
        return result
        
    except Exception as e:
        logger.error(f"Error getting live commission data for member {member.member_id}: {str(e)}")
        return {
            'error': str(e),
            'current_month_estimate': 0,
            'last_month_earned': 0,
            'pending_withdrawals': 0,
            'downline_performance': []
        }
    


def process_first_payment(order):
    """
    Process first payment for a new MLM member.
    Checks if the payment meets the monthly quota requirement and
    awards a 1000 rupee bonus to the sponsor if requirements are met.
    
    Args:
        order (Order): The completed order
    
    Returns:
        bool: Whether first payment was processed successfully
    """
    try:
        # Get the member who made the order
        user = order.user
        
        # Check if user is an MLM member
        if not hasattr(user, 'mlm_profile'):
            logger.info(f"User {user.id} is not an MLM member, skipping first payment processing")
            return False
            
        member = user.mlm_profile
        
        # Check if first payment is already processed
        if member.first_payment_complete:
            logger.info(f"First payment already processed for member {member.member_id}, skipping")
            return False
            
        # Get the monthly quota requirement from position
        monthly_quota = member.position.monthly_quota
        
        # Check if order amount meets the requirement
        if order.final_amount >= monthly_quota:
            # Mark first payment as complete
            member.first_payment_complete = True
            member.first_payment_amount = order.final_amount
            member.save(update_fields=['first_payment_complete', 'first_payment_amount'])
            
            logger.info(f"First payment completed for member {member.member_id}: {order.final_amount} ≥ {monthly_quota}")
            
            # Check if member has a sponsor to award bonus
            if member.sponsor:
                # Create a bonus commission of 1000 rupees for the sponsor
                
                logger.info(f"Creating 1000 rupee bonus for sponsor {member.sponsor.member_id}")
                
                Commission.objects.create(
                    member=member.sponsor,
                    from_member=member,
                    order=order,
                    amount=Decimal('1000.00'),  # 1000 rupees bonus
                    level=1,  # Direct sponsor
                    is_paid=True,  # Mark as paid immediately
                    payment_date=timezone.now(),
                    commission_type='BONUS',
                    details={
                        'bonus_type': 'first_payment',
                        'payment_amount': float(order.final_amount),
                        'quota_requirement': float(monthly_quota)
                    }
                )
                
                # Update sponsor's total earnings
                member.sponsor.total_earnings += Decimal('1000.00')
                member.sponsor.save(update_fields=['total_earnings'])
                
                # Create notification for sponsor
                Notification.objects.create(
                    title='First Payment Bonus',
                    message=f'You have received a bonus of ₹1000 for {member.user.get_full_name()}\'s first payment.',
                    notification_type='COMMISSION',
                    recipient=member.sponsor
                )
                
            return True
        else:
            logger.info(f"Payment amount {order.final_amount} does not meet quota {monthly_quota} for first payment")
            
        return False
        
    except Exception as e:
        logger.error(f"Error processing first payment bonus: {str(e)}")
        return False