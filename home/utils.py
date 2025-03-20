from django.db import transaction
from decimal import Decimal
from django.utils import timezone
from datetime import datetime, timedelta
import logging
from django.db.models import Sum, F, Q
from home.models import Commission, Notification, MLMMember , Order , Position , Wallet , WalletTransaction

logger = logging.getLogger(__name__)

def update_bp_points_on_order(order):
    """
    Update BP points when an order is placed and confirmed
    """
    try:
        # Check if order is in a valid status
        if order.status not in ['CONFIRMED', 'SHIPPED', 'DELIVERED']:
            logger.warning(f"Cannot update BP for order {order.id} with status {order.status}")
            return False
            
        # Check if BP was already processed
        if order.bp_processed:
            logger.info(f"BP already processed for order {order.id}")
            return False
            
        # Check if user is an MLM member
        user = order.user
        if user.role != 'MLM_MEMBER' or not hasattr(user, 'mlm_profile'):
            logger.info(f"User {user.id} is not an MLM member, skipping BP update")
            return False
            
        mlm_member = user.mlm_profile
        
        # Get total BP for this order
        total_bp = order.total_bp
        
        with transaction.atomic():
            # Add BP points with capping for Level 1
            actual_bp_added = mlm_member.add_bp(total_bp)
            
            # Update current month purchase
            mlm_member.current_month_purchase += order.final_amount
            mlm_member.save(update_fields=['current_month_purchase'])
            
            # Mark BP as processed
            order.bp_processed = True
            order.save(update_fields=['bp_processed'])
            
            # Log the actual BP added
            logger.info(f"Added {actual_bp_added} BP to member {mlm_member.member_id} (capped from {total_bp})")
            
            # Check for position upgrade (won't affect Level 1)
            mlm_member.check_position_upgrade()
            
            return True
            
    except Exception as e:
        logger.error(f"Error updating BP points for order {order.id}: {str(e)}")
        return False
    # try:
    #     # Only process confirmed/completed orders
    #     if order.status not in ['CONFIRMED', 'SHIPPED', 'DELIVERED']:
    #         logger.info(f"Order {order.id} status is {order.status}, not updating BP")
    #         return False
            
    #     # Get member if user is MLM member
    #     if order.user.role != 'MLM_MEMBER':
    #         logger.info(f"User {order.user.id} is not MLM_MEMBER, not updating BP")
    #         return False
            
    #     member = order.user.mlm_profile
    #     logger.info(f"Processing BP update for member {member.member_id} from order {order.id}")
        
    #     with transaction.atomic():

    #         if hasattr(order, 'bp_processed') and order.bp_processed:
    #             logger.info(f"Order {order.id} already processed for BP, skipping")
    #             return False
    #         # Add BP points from order to member
    #         old_bp = member.total_bp
            
    #         member.total_bp += order.total_bp
            
    #         # Update monthly purchase amount
    #         member.current_month_purchase += order.final_amount
    #         member.save()
            
    #         # Mark order as processed for BP
    #         order.bp_processed = True
    #         order.save(update_fields=['bp_processed'])

    #         logger.info(f"Updated BP for {member.member_id}: {old_bp} → {member.total_bp}")
            
    #         # Check for position upgrade
    #         if member.check_position_upgrade():
    #             logger.info(f"Member {member.member_id} upgraded position to {member.position.name}")
                
    #         return True
            
    # except Exception as e:
    #     logger.error(f"Error updating BP points on order {order.id}: {str(e)}")
    #     return False

def process_bp_monthly_update():
    """
    Process monthly BP updates
    This should run on the 1st of each month
    
    BP points from downline members are added to their sponsors
    """
    try:
        logger.info("Starting monthly BP update")
        
        # Get current date
        now = timezone.now()
        
        # Only run on 1st of the month
        if now.day != 1:
            logger.info(f"Skipping BP update: not 1st of month (date: {now})")
            return False
            
        # Get all active MLM members
        mlm_members = MLMMember.objects.filter(is_active=True)
        
        # Process downline BP for each member
        for sponsor in mlm_members:
            # Get direct downline members
            downline_members = MLMMember.objects.filter(sponsor=sponsor)
            
            for downline in downline_members:
                # Get downline BP
                downline_bp = downline.total_bp
                
                if downline_bp > 0:
                    # Add downline BP to sponsor
                    sponsor.add_bp(downline_bp)
                    logger.info(f"Added {downline_bp} BP from {downline.member_id} to {sponsor.member_id}")
            
            # Check for position upgrade
            sponsor.check_position_upgrade()
            
        logger.info("Monthly BP update complete")
        return True
        
    except Exception as e:
        logger.error(f"Error in monthly BP update: {str(e)}")
        return False
    
def reverse_bp_points_on_order_cancellation(order):
    """
    Reverse BP points and purchase amount when an order is cancelled
    """
    try:
        # Only process cancelled orders
        if order.status != 'CANCELLED':
            return False
            
        # Get member if user is MLM member
        if order.user.role != 'MLM_MEMBER':
            return False
            
        member = order.user.mlm_profile
        logger.info(f"Reversing BP update for member {member.member_id} from cancelled order {order.id}")
        
        with transaction.atomic():
            # Check if order was processed for BP
            if not hasattr(order, 'bp_processed') or not order.bp_processed:
                logger.info(f"Order {order.id} was not processed for BP, skipping reversal")
                return False

            # Subtract BP points from order
            old_bp = member.total_bp
            member.total_bp -= order.total_bp
            
            # Subtract from monthly purchase amount
            member.current_month_purchase -= order.final_amount
            member.save()
            
            # Mark order as not processed for BP
            order.bp_processed = False
            order.save(update_fields=['bp_processed'])
            
            logger.info(f"Reversed BP for {member.member_id}: {old_bp} → {member.total_bp}")
            
            return True
            
    except Exception as e:
        logger.error(f"Error reversing BP points on order cancellation {order.id}: {str(e)}")
        return False

def calculate_monthly_commissions(force_calculate=False):
    """
    Calculate monthly commissions for all MLM members based on the differential model.
    This function should be scheduled to run on the 1st of each month.
    
    The process:
    1. For each active MLM member, check if they maintained their monthly quota
    2. Calculate commissions from their downline based on position percentage differences
    3. Sum up BP points from downline members and add to the member's total
    4. Check for position upgrades based on new BP totals
    
    Args:
        force_calculate (bool): If True, will run regardless of the day of month
        
    Returns:
        bool: True if calculation was successful, False otherwise
    """
    try:
        today = timezone.now()
        
        # Only run on the 1st day of the month unless forced
        if today.day != 1 and not force_calculate:
            logger.info(f"Skipping monthly commission calculation - today is day {today.day}, not 1st of month")
            return False
            
        logger.info("Starting monthly commission calculation")
        
        # Get the previous month's date range
        first_day_current_month = today.replace(day=1, hour=0, minute=0, second=0, microsecond=0)
        last_month = (first_day_current_month - timedelta(days=1))
        first_day_last_month = last_month.replace(day=1, hour=0, minute=0, second=0, microsecond=0)
        
        logger.info(f"Calculating commissions for period: {first_day_last_month.date()} to {last_month.date()}")
        
        # Get all active MLM members
        active_members = MLMMember.objects.filter(is_active=True).select_related('position', 'sponsor', 'user')
        logger.info(f"Found {active_members.count()} active members")
        
        # Track processed members and their commissions
        processed_count = 0
        commissions_created = 0
        bp_updates = 0
        position_upgrades = 0
        
        # Use transaction to ensure all changes are atomic
        with transaction.atomic():
            # Process each member from highest position to lowest
            # This ensures parent members receive BP from downline correctly
            for member in active_members.order_by('-position__level_order'):
                try:
                    # Skip members whose positions can't earn commissions
                    if not member.position.can_earn_commission:
                        logger.info(f"Member {member.member_id} position doesn't allow earning commissions, skipping")
                        continue
                    
                    # Check if the member has maintained their monthly quota
                    quota_maintained = member.check_monthly_quota_maintenance(last_month)
                    
                    if not quota_maintained:
                        logger.info(f"Member {member.member_id} did not maintain monthly quota, skipping commission")
                        
                        # Send notification about failing to meet quota
                        Notification.objects.create(
                            title="Monthly Quota Not Met",
                            message=f"You didn't meet your monthly quota of ₹{member.position.monthly_quota} for last month. You won't earn commissions from your downline this month.",
                            notification_type="INDIVIDUAL",
                            recipient=member
                        )
                        continue
                        
                    # Member maintained quota, process their commissions
                    logger.info(f"Processing member {member.member_id} (position: {member.position.name})")
                    
                    # Track total BP to add from downline
                    total_bp_from_downline = 0
                    total_commission = Decimal('0.00')
                    downline_details = []
                    
                    # Process downline members for commissions and BP
                    downline_members = MLMMember.objects.filter(
                        sponsor=member, 
                        is_active=True
                    ).select_related('position', 'user')
                    
                    for downline in downline_members:
                        # Calculate position difference percentage
                        member_percentage = member.position.discount_percentage
                        downline_percentage = downline.position.discount_percentage
                        
                        # Add BP from downline to member's total
                        total_bp_from_downline += downline.total_bp
                        
                        # Skip if downline's position percentage is equal or higher
                        if downline_percentage >= member_percentage:
                            logger.info(f"Downline {downline.member_id} has equal or higher position percentage ({downline_percentage}% >= {member_percentage}%), skipping commission")
                            continue
                        
                        # Calculate percentage difference for commission calculation
                        difference_percentage = member_percentage - downline_percentage
                        
                        # Get downline's purchases for last month
                        downline_purchases = get_monthly_purchases(downline, first_day_last_month, last_month)
                        
                        if downline_purchases <= 0:
                            logger.info(f"Downline {downline.member_id} had no purchases last month, skipping commission")
                            continue
                        
                        # Calculate commission based on position percentage difference
                        commission_amount = (downline_purchases * Decimal(str(difference_percentage))) / Decimal('100.0')
                        
                        if commission_amount > 0:
                            # Create commission record
                            Commission.objects.create(
                                member=member,
                                from_member=downline,
                                amount=commission_amount,
                                is_paid=True,  # Commissions are paid immediately on calculation
                                payment_date=today,
                                level=1,  # Direct downline level
                                date=today,
                                commission_type='MONTHLY',
                                calculation_month=first_day_last_month.date(),
                                details={
                                    'month': first_day_last_month.strftime('%Y-%m'),
                                    'downline_purchases': float(downline_purchases),
                                    'member_percentage': float(member_percentage),
                                    'downline_percentage': float(downline_percentage),
                                    'difference_percentage': float(difference_percentage)
                                }
                            )
                            
                            commissions_created += 1
                            total_commission += commission_amount
                            
                            # Store downline details for notification
                            downline_details.append({
                                'name': downline.user.get_full_name() or downline.member_id,
                                'purchases': float(downline_purchases),
                                'commission': float(commission_amount),
                                'difference': float(difference_percentage)
                            })
                            
                            logger.info(f"Created commission of {commission_amount} for {member.member_id} from {downline.member_id} (difference: {difference_percentage}%)")
                    
                    # Update member's total BP with downline BP
                    if total_bp_from_downline > 0:
                        logger.info(f"Adding {total_bp_from_downline} BP from downline to member {member.member_id}")
                        
                        old_bp = member.total_bp
                        member.total_bp += total_bp_from_downline
                        
                        # Update member's total earnings
                        if total_commission > 0:
                            member.total_earnings += total_commission
                        
                        # Save the changes
                        member.save(update_fields=['total_bp', 'total_earnings'])
                        bp_updates += 1
                        
                        logger.info(f"Updated BP for {member.member_id}: {old_bp} → {member.total_bp}")
                        
                        # Check if member qualifies for position upgrade
                        old_position = member.position
                        member.check_position_upgrade()
                        
                        if member.position.id != old_position.id:
                            position_upgrades += 1
                            logger.info(f"Upgraded member {member.member_id} from {old_position.name} to {member.position.name}")
                            
                            # Create notification for position upgrade
                            Notification.objects.create(
                                title="Position Upgraded!",
                                message=f"Congratulations! You've been upgraded from {old_position.name} (at {old_position.discount_percentage}%) to {member.position.name} (at {member.position.discount_percentage}%).",
                                notification_type="INDIVIDUAL",
                                recipient=member
                            )
                    
                    # Create notification about earned commission
                    if total_commission > 0:
                        # Create detailed message with breakdown by downline
                        message = f"You've earned ₹{total_commission} in commissions from your downline for last month.\n\n"
                        
                        if downline_details:
                            message += "Commission breakdown:\n"
                            for detail in downline_details:
                                message += f"- {detail['name']}: ₹{detail['commission']} ({detail['difference']}% of ₹{detail['purchases']})\n"
                        
                        Notification.objects.create(
                            title="Monthly Commission Processed",
                            message=message,
                            notification_type="INDIVIDUAL",
                            recipient=member
                        )
                        
                    processed_count += 1
                    
                except Exception as e:
                    logger.error(f"Error processing member {member.member_id}: {str(e)}", exc_info=True)
                    # Continue with next member
                    continue
            
            # Reset current_month_purchase for all members
            MLMMember.objects.all().update(current_month_purchase=0)
            logger.info("Reset current_month_purchase for all members to 0")
            
            # Create system notification about completed calculation
            Notification.objects.create(
                title="Monthly Commission Calculation Complete",
                message=f"Monthly commission calculation completed: {processed_count} members processed, {commissions_created} commissions created, {bp_updates} BP updates, {position_upgrades} position upgrades",
                notification_type="SYSTEM"
            )
            
        # Log summary
        logger.info(f"Monthly commission calculation completed: {processed_count} members processed, {commissions_created} commissions created, {bp_updates} BP updates, {position_upgrades} position upgrades")
        
        return True
        
    except Exception as e:
        logger.error(f"Error in monthly commission calculation: {str(e)}", exc_info=True)
        return False

def get_monthly_purchases(member, start_date, end_date):
    """
    Get total purchase amount for a member within a date range
    
    Args:
        member (MLMMember): The member to get purchases for
        start_date (datetime): Start date (inclusive)
        end_date (datetime): End date (inclusive)
        
    Returns:
        Decimal: Total purchase amount
    """
    return Order.objects.filter(
        user=member.user,
        order_date__gte=start_date,
        order_date__lte=end_date,
        status__in=['CONFIRMED', 'SHIPPED', 'DELIVERED']
    ).aggregate(
        total=Sum('final_amount')
    )['total'] or Decimal('0.00')

def get_member_monthly_purchases(member, start_date, end_date):
    """Get total purchases for a member in the given date range"""
    try:
        total_purchases = Order.objects.filter(
            user=member.user,
            order_date__gte=start_date,
            order_date__lte=end_date,
            status__in=['CONFIRMED', 'SHIPPED', 'DELIVERED']
        ).aggregate(total=Sum('final_amount'))['total'] or Decimal('0.00')
        
        return total_purchases
        
    except Exception as e:
        logger.error(f"Error getting monthly purchases for member {member.member_id}: {str(e)}")
        return Decimal('0.00')

def upgrade_position(member):
    """Check and upgrade member's position based on BP points"""
    try:

        if member.position.level_order == 1:
            return False
        
        # Find the highest position the member qualifies for based on BP points
        eligible_position = Position.objects.filter(
            bp_required_min__lte=member.total_bp,
            bp_required_max__gte=member.total_bp,
            level_order__gt=member.position.level_order,
            is_active=True
        ).order_by('-level_order').first()
        
        # If no higher position found, keep current position
        if not eligible_position:
            return False
            
        # Update member's position
        member.position = eligible_position
        member.save(update_fields=['position'])
        
        return True
        
    except Exception as e:
        logger.error(f"Error upgrading position for member {member.member_id}: {str(e)}")
        return False

def process_first_payment_bonus(order):
    """
    Process first payment bonus when a new MLM member makes their first qualifying purchase
    
    This should be called when an order is confirmed for an MLM member
    """
    try:
        # Get the member who made the order
        user = order.user
        
        # Check if user is an MLM member
        if not hasattr(user, 'mlm_profile'):
            logger.info(f"User {user.id} is not an MLM member, skipping first payment bonus")
            return False
            
        member = user.mlm_profile
        
        # Check if first payment is already processed
        if member.first_payment_complete:
            logger.info(f"First payment already processed for member {member.member_id}, skipping bonus")
            return False
            
        # Get the monthly quota requirement from position
        monthly_quota = member.position.monthly_quota
        
        # Check if order amount meets the requirement
        if order.final_amount >= monthly_quota:
            # Mark first payment as complete
            member.first_payment_complete = True
            member.first_payment_amount = order.final_amount
            member.save(update_fields=['first_payment_complete', 'first_payment_amount'])
            
            logger.info(f"First payment completed for member {member.member_id}: {order.final_amount} >= {monthly_quota}")
            
            # Check if member has a sponsor to award bonus
            if member.sponsor:
                # Create a bonus commission of 1000 rupees for the sponsor
                logger.info(f"Creating ₹1000 bonus for sponsor {member.sponsor.member_id}")
                
                Commission.objects.create(
                    member=member.sponsor,
                    from_member=member,
                    order=order,
                    amount=Decimal('1000.00'),  # 1000 rupees bonus
                    level=1,  # Direct sponsor
                    is_paid=True,  # Mark as paid immediately
                    payment_date=timezone.now(),
                    date=timezone.now(),
                    commission_type='BONUS',
                    is_first_purchase_bonus=True,
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
                    title='First Purchase Bonus',
                    message=f'You have received a bonus of ₹1000 for {member.user.get_full_name()}\'s first qualifying purchase.',
                    notification_type='COMMISSION',
                    recipient=member.sponsor
                )
                
                # Create notification for member
                Notification.objects.create(
                    title='First Purchase Complete',
                    message=f'Congratulations! You have completed your first qualifying purchase. Your account is now fully active.',
                    notification_type='INDIVIDUAL',
                    recipient=member
                )
                
            return True
        else:
            logger.info(f"Payment amount {order.final_amount} does not meet quota {monthly_quota} for first payment")
            
        return False
        
    except Exception as e:
        logger.error(f"Error processing first payment bonus: {str(e)}")
        return False

def check_monthly_quota_maintenance(member, month_end_date):
    """
    Check if a member maintained their monthly quota
    
    Args:
        member (MLMMember): The MLM member to check
        month_end_date (datetime): The end date of the month to check
    
    Returns:
        bool: Whether the member maintained their quota
    """
    # Get the month start date
    month_start_date = month_end_date.replace(day=1)
    
    # Get total purchases for the month
    monthly_purchases = get_member_monthly_purchases(member, month_start_date, month_end_date)
    
    # Compare with position's monthly quota
    return monthly_purchases >= member.position.monthly_quota


def get_member_monthly_bp(member, start_date, end_date):
    """
    Get the total BP points earned by a member in a month
    
    Args:
        member (MLMMember): The MLM member
        start_date (datetime): Start date of the month
        end_date (datetime): End date of the month
    
    Returns:
        int: Total BP points
    """
    total_bp = Order.objects.filter(
        user=member.user,
        order_date__gte=start_date,
        order_date__lte=end_date,
        status__in=['CONFIRMED', 'SHIPPED', 'DELIVERED']
    ).aggregate(
        total=Sum('total_bp')
    )['total'] or 0
    
    return total_bp

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
    Calculate real-time commission data for an MLM member based on current downline activity
    
    Args:
        member (MLMMember): The MLM member to calculate commissions for
        
    Returns:
        dict: Dictionary containing live commission data
    """
    try:
        # Check if member's position allows earning commissions
        if not member.position.can_earn_commission:
            return {
                'current_month_estimate': "0.00",
                'last_month_earned': "0.00",
                'total_pending': "0.00",
                'level_breakdown': [],
                'top_performers': [],
                'recent_transactions': []
            }
        
        # Get dates for calculations
        today = timezone.now()
        first_day_current_month = today.replace(day=1, hour=0, minute=0, second=0, microsecond=0)
        last_month = (today.replace(day=1) - datetime.timedelta(days=1))
        first_day_last_month = last_month.replace(day=1, hour=0, minute=0, second=0, microsecond=0)
        
        # Calculate last month's earned commissions
        last_month_earned = Commission.objects.filter(
            member=member,
            is_paid=True,
            date__gte=first_day_last_month,
            date__lt=first_day_current_month
        ).aggregate(total=Sum('amount'))['total'] or Decimal('0.00')
        
        # Calculate total pending commissions
        total_pending = Commission.objects.filter(
            member=member,
            is_paid=False
        ).aggregate(total=Sum('amount'))['total'] or Decimal('0.00')
        
        # Calculate commission breakdown by downline level
        downline_data = get_downline_by_level(member)
        level_breakdown, current_month_estimate = calculate_level_commission(member, downline_data)
        
        # Get top performing members
        top_performers = get_top_performers(member, downline_data)
        
        # Get recent transactions that generate commission
        recent_transactions = get_recent_transactions(member, downline_data)
        
        # Get pending first purchase bonuses
        pending_bonuses = get_pending_first_purchase_bonuses(member)
        
        # Calculate real-time daily commission if needed
        daily_commission = calculate_daily_commission(member)
        
        return {
            'current_month_estimate': str(current_month_estimate),
            'last_month_earned': str(last_month_earned),
            'total_pending': str(total_pending),
            'level_breakdown': level_breakdown,
            'top_performers': top_performers,
            'recent_transactions': recent_transactions,
            'pending_bonuses': pending_bonuses,
            'daily_commission': daily_commission,
            'quota_maintained': check_monthly_quota_maintenance(member),
            'next_calculation_date': get_next_calculation_date()
        }
        
    except Exception as e:
        logger.error(f"Error calculating live commission data: {str(e)}", exc_info=True)
        # Return empty data structure in case of error
        return {
            'current_month_estimate': "0.00",
            'last_month_earned': "0.00",
            'total_pending': "0.00",
            'level_breakdown': [],
            'top_performers': [],
            'recent_transactions': [],
            'pending_bonuses': [],
            'daily_commission': {
                'today': "0.00",
                'yesterday': "0.00",
                'week_to_date': "0.00"
            },
            'quota_maintained': False,
            'next_calculation_date': get_next_calculation_date()
        }

def get_downline_by_level(member, max_level=5):
    """
    Get all downline members organized by level
    
    Args:
        member (MLMMember): The MLM member
        max_level (int): Maximum downline level to retrieve
        
    Returns:
        dict: Dictionary of downline members by level
    """
    result = {}
    
    def traverse(current_member, level=1):
        if level > max_level:
            return
            
        # Get direct downline
        downline = MLMMember.objects.filter(
            sponsor=current_member,
            is_active=True
        ).select_related('user', 'position')
        
        if downline.exists():
            if level not in result:
                result[level] = []
                
            for downline_member in downline:
                result[level].append({
                    'id': downline_member.id,
                    'member_id': downline_member.member_id,
                    'user_id': downline_member.user.id,
                    'name': downline_member.user.get_full_name() or downline_member.user.username,
                    'position': downline_member.position,
                    'position_name': downline_member.position.name,
                    'position_percentage': downline_member.position.discount_percentage
                })
                
                # Recursively get next level
                traverse(downline_member, level + 1)
    
    traverse(member)
    return result

def calculate_level_commission(member, downline_data):
    """
    Calculate commission breakdown by level
    
    Args:
        member (MLMMember): The MLM member
        downline_data (dict): Downline members by level
        
    Returns:
        tuple: (level_breakdown list, total estimate amount)
    """
    level_breakdown = []
    current_month_estimate = Decimal('0.00')
    
    # Get current month orders
    today = timezone.now()
    first_day_current_month = today.replace(day=1, hour=0, minute=0, second=0, microsecond=0)
    
    current_month_orders = Order.objects.filter(
        order_date__gte=first_day_current_month,
        status__in=['CONFIRMED', 'SHIPPED', 'DELIVERED']
    )
    
    # Calculate level breakdown
    for level, members in downline_data.items():
        member_ids = [m['user_id'] for m in members]
        if member_ids:
            level_purchases = current_month_orders.filter(
                user_id__in=member_ids
            ).aggregate(total=Sum('final_amount'))['total'] or Decimal('0.00')
            
            commission_rate = get_commission_rate(member.position, level)
            level_commission = (level_purchases * commission_rate) / 100
            current_month_estimate += level_commission
            
            # Get member count at this level with higher, equal, and lower positions
            position_counts = {
                'higher': 0,
                'equal': 0,
                'lower': 0
            }
            
            for m in members:
                if m['position_percentage'] > member.position.discount_percentage:
                    position_counts['higher'] += 1
                elif m['position_percentage'] == member.position.discount_percentage:
                    position_counts['equal'] += 1
                else:
                    position_counts['lower'] += 1
            
            level_breakdown.append({
                'level': level,
                'member_count': len(member_ids),
                'total_purchases': str(level_purchases),
                'commission_rate': str(commission_rate),
                'estimated_commission': str(level_commission),
                'position_counts': position_counts
            })
    
    return level_breakdown, current_month_estimate

def get_commission_rate(position, level):
    """
    Calculate commission rate based on position and level
    
    Args:
        position (Position): Member's position
        level (int): Downline level
        
    Returns:
        Decimal: Commission rate percentage
    """
    base_rate = position.commission_percentage
    
    # Level-based reduction factors
    level_multipliers = {
        1: Decimal('1.0'),    # 100% of base rate for direct downline
        2: Decimal('0.5'),    # 50% of base rate
        3: Decimal('0.25'),   # 25% of base rate
        4: Decimal('0.125'),  # 12.5% of base rate
        5: Decimal('0.0625')  # 6.25% of base rate
    }
    
    multiplier = level_multipliers.get(level, Decimal('0.03125'))  # Default for higher levels
    return base_rate * multiplier

def get_top_performers(member, downline_data, limit=5):
    """
    Get top performing downline members
    
    Args:
        member (MLMMember): The MLM member
        downline_data (dict): Downline members by level
        limit (int): Maximum number of top performers to return
        
    Returns:
        list: List of top performers with their purchase data
    """
    try:
        # Get current month orders
        today = timezone.now()
        first_day_current_month = today.replace(day=1, hour=0, minute=0, second=0, microsecond=0)
        
        # Flatten downline data
        all_downline = []
        for level, members in downline_data.items():
            for m in members:
                m['level'] = level
                all_downline.append(m)
        
        # Get user IDs
        user_ids = [m['user_id'] for m in all_downline]
        
        if not user_ids:
            return []
        
        # Get orders for all downline
        month_orders = Order.objects.filter(
            user_id__in=user_ids,
            order_date__gte=first_day_current_month,
            status__in=['CONFIRMED', 'SHIPPED', 'DELIVERED']
        )
        
        # Calculate total purchases per user
        user_purchases = {}
        for order in month_orders:
            if order.user_id not in user_purchases:
                user_purchases[order.user_id] = Decimal('0.00')
            user_purchases[order.user_id] += order.final_amount
        
        # Sort users by purchase amount
        sorted_users = sorted(
            user_purchases.items(), 
            key=lambda x: x[1], 
            reverse=True
        )[:limit]
        
        # Format top performers data
        top_performers = []
        for user_id, purchase_amount in sorted_users:
            downline_info = next((m for m in all_downline if m['user_id'] == user_id), None)
            
            if downline_info:
                # Calculate commission if position allows
                commission_amount = Decimal('0.00')
                if member.position.discount_percentage > downline_info['position_percentage']:
                    # Commission based on position difference
                    percentage_diff = member.position.discount_percentage - downline_info['position_percentage']
                    commission_amount = (purchase_amount * Decimal(str(percentage_diff)) / 100)
                
                top_performers.append({
                    'member_id': downline_info['member_id'],
                    'name': downline_info['name'],
                    'level': downline_info['level'],
                    'position': downline_info['position_name'],
                    'total_purchases': str(purchase_amount),
                    'your_commission': str(commission_amount),
                    'earns_commission': commission_amount > 0
                })
        
        return top_performers
        
    except Exception as e:
        logger.error(f"Error getting top performers: {str(e)}")
        return []

def get_recent_transactions(member, downline_data, limit=10):
    """
    Get recent transactions from downline members
    
    Args:
        member (MLMMember): The MLM member
        downline_data (dict): Downline members by level
        limit (int): Maximum number of transactions to return
        
    Returns:
        list: List of recent transactions
    """
    try:
        # Get current month
        today = timezone.now()
        first_day_current_month = today.replace(day=1, hour=0, minute=0, second=0, microsecond=0)
        
        # Flatten downline data
        all_downline = []
        for level, members in downline_data.items():
            for m in members:
                m['level'] = level
                all_downline.append(m)
        
        # Get user IDs
        user_ids = [m['user_id'] for m in all_downline]
        
        if not user_ids:
            return []
        
        # Get recent orders
        recent_orders = Order.objects.filter(
            user_id__in=user_ids,
            order_date__gte=first_day_current_month,
            status__in=['CONFIRMED', 'SHIPPED', 'DELIVERED']
        ).select_related('user').order_by('-order_date')[:limit]
        
        # Format transactions data
        transactions = []
        for order in recent_orders:
            downline_info = next((m for m in all_downline if m['user_id'] == order.user.id), None)
            
            if downline_info:
                # Calculate commission if position allows
                commission_amount = Decimal('0.00')
                if member.position.discount_percentage > downline_info['position_percentage']:
                    # Commission based on position difference
                    percentage_diff = member.position.discount_percentage - downline_info['position_percentage']
                    commission_amount = (order.final_amount * Decimal(str(percentage_diff)) / 100)
                
                transactions.append({
                    'date': order.order_date,
                    'member_name': downline_info['name'],
                    'level': downline_info['level'],
                    'order_id': order.order_number,
                    'amount': str(order.final_amount),
                    'your_commission': str(commission_amount),
                    'earns_commission': commission_amount > 0
                })
        
        return transactions
        
    except Exception as e:
        logger.error(f"Error getting recent transactions: {str(e)}")
        return []

def get_pending_first_purchase_bonuses(member):
    """
    Get pending first purchase bonuses for direct downline
    
    Args:
        member (MLMMember): The MLM member
        
    Returns:
        list: List of pending first purchase bonus information
    """
    try:
        # Get direct downline who haven't made their first purchase yet
        direct_downline = MLMMember.objects.filter(
            sponsor=member, 
            is_active=True,
            first_payment_complete=False
        ).select_related('user', 'position')
        
        if not direct_downline.exists():
            return []
        
        pending_bonuses = []
        for downline in direct_downline:
            # Calculate how much they need to purchase to meet first payment requirement
            monthly_quota = downline.position.monthly_quota
            
            pending_bonuses.append({
                'member_id': downline.member_id,
                'name': downline.user.get_full_name() or downline.user.username,
                'join_date': downline.join_date,
                'quota_required': str(monthly_quota),
                'bonus_amount': '1000.00'  # Fixed bonus amount for first purchase
            })
        
        return pending_bonuses
        
    except Exception as e:
        logger.error(f"Error getting pending first purchase bonuses: {str(e)}")
        return []

def calculate_daily_commission(member):
    """
    Calculate commission earned in the current day/week
    
    Args:
        member (MLMMember): The MLM member
        
    Returns:
        dict: Daily commission statistics
    """
    try:
        today = timezone.now()
        today_start = today.replace(hour=0, minute=0, second=0, microsecond=0)
        yesterday_start = today_start - datetime.timedelta(days=1)
        
        # Get week start (Monday)
        days_since_monday = today.weekday()
        week_start = today_start - datetime.timedelta(days=days_since_monday)
        
        # Today's commission
        today_commission = Commission.objects.filter(
            member=member,
            date__gte=today_start,
            date__lt=today_start + datetime.timedelta(days=1)
        ).aggregate(total=Sum('amount'))['total'] or Decimal('0.00')
        
        # Yesterday's commission
        yesterday_commission = Commission.objects.filter(
            member=member,
            date__gte=yesterday_start,
            date__lt=today_start
        ).aggregate(total=Sum('amount'))['total'] or Decimal('0.00')
        
        # Week-to-date commission
        week_commission = Commission.objects.filter(
            member=member,
            date__gte=week_start,
            date__lt=today_start + datetime.timedelta(days=1)
        ).aggregate(total=Sum('amount'))['total'] or Decimal('0.00')
        
        return {
            'today': str(today_commission),
            'yesterday': str(yesterday_commission),
            'week_to_date': str(week_commission)
        }
        
    except Exception as e:
        logger.error(f"Error calculating daily commission: {str(e)}")
        return {
            'today': "0.00",
            'yesterday': "0.00",
            'week_to_date': "0.00"
        }

def get_next_calculation_date():
    """
    Get the date of the next commission calculation
    
    Returns:
        str: Next calculation date (1st of next month)
    """
    today = timezone.now()
    
    # If today is the 1st, then calculation is today
    if today.day == 1:
        return today.strftime('%Y-%m-%d')
    
    # Otherwise, it's the 1st of next month
    if today.month == 12:
        next_calc_date = datetime.date(today.year + 1, 1, 1)
    else:
        next_calc_date = datetime.date(today.year, today.month + 1, 1)
    
    return next_calc_date.strftime('%Y-%m-%d')

def check_monthly_quota_maintenance(member):
    """
    Check if member is currently maintaining their monthly quota
    
    Args:
        member (MLMMember): The MLM member
        
    Returns:
        bool: Whether the member is maintaining their quota
    """
    try:
        # Get current month's purchases
        today = timezone.now()
        first_day_of_month = today.replace(day=1, hour=0, minute=0, second=0, microsecond=0)
        
        month_purchases = Order.objects.filter(
            user=member.user,
            order_date__gte=first_day_of_month,
            status__in=['CONFIRMED', 'SHIPPED', 'DELIVERED']
        ).aggregate(total=Sum('final_amount'))['total'] or Decimal('0.00')
        
        # Compare with required quota
        return month_purchases >= member.position.monthly_quota
        
    except Exception as e:
        logger.error(f"Error checking quota maintenance: {str(e)}")
        return False

def process_first_payment(order):
    """
    Process first payment bonus when a new MLM member makes their first qualifying purchase
    """
    try:
        # Get the member who made the order
        user = order.user
        
        # Check if user is an MLM member
        if not hasattr(user, 'mlm_profile'):
            logger.info(f"User {user.id} is not an MLM member, skipping first payment bonus")
            return False
            
        member = user.mlm_profile
        
        # Very important: Use a database transaction to prevent race conditions
        with transaction.atomic():
            # Check if first payment is already processed on the member
            if member.first_payment_complete:
                logger.info(f"First payment already processed for member {member.member_id}, skipping bonus")
                return False
                
            # Check if a bonus commission already exists for this member (regardless of order)
            existing_bonus = Commission.objects.filter(
                from_member=member,
                is_first_purchase_bonus=True
            ).exists()
            
            if existing_bonus:
                logger.info(f"First purchase bonus already exists for member {member.member_id}, skipping")
                # Make sure the member's first_payment_complete flag is updated
                if not member.first_payment_complete:
                    member.first_payment_complete = True
                    member.first_payment_amount = order.final_amount
                    member.save(update_fields=['first_payment_complete', 'first_payment_amount'])
                return True
            
            # Get the monthly quota requirement from position
            monthly_quota = member.position.monthly_quota
            
            # Check if order amount meets the requirement
            if order.final_amount >= monthly_quota:
                # Mark first payment as complete
                member.first_payment_complete = True
                member.first_payment_amount = order.final_amount
                member.first_purchase_bonus_received = True
                member.save(update_fields=['first_payment_complete', 'first_payment_amount', 'first_purchase_bonus_received'])
                
                logger.info(f"First payment completed for member {member.member_id}: {order.final_amount} >= {monthly_quota}")
                
                # Check if member has a sponsor to award bonus
                if member.sponsor:
                    # Create a bonus commission of 1000 rupees for the sponsor
                    logger.info(f"Creating ₹1000 bonus for sponsor {member.sponsor.member_id}")
                    
                    commission = Commission.objects.create(
                        member=member.sponsor,
                        from_member=member,
                        order=order,
                        amount=Decimal('1000.00'),  # 1000 rupees bonus
                        level=1,  # Direct sponsor
                        is_paid=True,  # Mark as paid immediately
                        payment_date=timezone.now(),
                        date=timezone.now(),
                        commission_type='BONUS',
                        is_first_purchase_bonus=True,
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
                        title='First Purchase Bonus',
                        message=f'You have received a bonus of ₹1000 for {member.user.get_full_name()}\'s first qualifying purchase.',
                        notification_type='COMMISSION',
                        recipient=member.sponsor
                    )
                    
                    # Create notification for member
                    Notification.objects.create(
                        title='First Purchase Complete',
                        message=f'Congratulations! You have completed your first qualifying purchase. Your account is now fully active.',
                        notification_type='INDIVIDUAL',
                        recipient=member
                    )
                    
                return True
            else:
                logger.info(f"Payment amount {order.final_amount} does not meet quota {monthly_quota} for first payment")
                
            return False
            
    except Exception as e:
        logger.error(f"Error processing first payment bonus: {str(e)}")
        return False
    

def calculate_commissions_admin(target_date=None, force_payment=False, specific_member=None, include_bp_transfer=True):
    """
    Calculate commissions for testing or admin purposes
    
    Args:
        target_date: The date to use for calculations
        force_payment: Whether to immediately mark commissions as paid
        specific_member: Optional member_id to calculate for just one member
        include_bp_transfer: Whether to include BP point transfers
    
    Returns:
        dict: Result information
    """
    try:
        if not target_date:
            target_date = timezone.now().date()
            
        # Calculate the month range - default to last month
        first_day_current_month = target_date.replace(day=1)
        last_month_end = first_day_current_month - timedelta(days=1)
        first_day_last_month = last_month_end.replace(day=1)
        
        # Get all active MLM members or a specific member
        if specific_member:
            members = MLMMember.objects.filter(
                member_id=specific_member,
                is_active=True
            ).select_related('position', 'user')
        else:
            members = MLMMember.objects.filter(
                is_active=True,
                position__can_earn_commission=True  # Only include members who can earn commissions
            ).select_related('position', 'user')
        
        if not members.exists():
            return {
                'success': False,
                'message': 'No eligible members found',
                'details': {}
            }
        
        # Track results
        commissions_created = 0
        total_amount = Decimal('0.00')
        total_bp_transferred = 0
        member_results = []
        
        # Process each member
        for member in members:
            # Check if member maintains monthly quota
            monthly_quota_maintained = member.check_monthly_quota_maintenance(
                month=first_day_last_month
            )
            
            if not monthly_quota_maintained:
                member_results.append({
                    'member_id': member.member_id,
                    'name': member.user.get_full_name() or member.user.username,
                    'status': 'SKIPPED',
                    'reason': 'Monthly quota not maintained',
                    'commission_amount': '0.00',
                    'bp_transferred': 0
                })
                continue
            
            # Get all direct downline members
            downline = MLMMember.objects.filter(
                sponsor=member,
                is_active=True
            ).select_related('position', 'user')
            
            # Calculate commissions for each downline
            member_commission_total = Decimal('0.00')
            member_bp_total = 0
            
            for downline_member in downline:
                # Process financial commission
                # Only calculate if member's position percentage is higher
                if member.position.discount_percentage <= downline_member.position.discount_percentage:
                    continue
                
                # Calculate percentage difference
                difference_percentage = member.position.discount_percentage - downline_member.position.discount_percentage
                
                # Get downline's purchases for last month
                downline_purchases = Order.objects.filter(
                    user=downline_member.user,
                    order_date__gte=first_day_last_month,
                    order_date__lt=first_day_current_month,
                    status__in=['CONFIRMED', 'SHIPPED', 'DELIVERED']
                ).aggregate(total=Sum('final_amount'))['total'] or Decimal('0.00')
                
                # Process BP transfer from downline to sponsor if enabled
                downline_bp = 0
                if include_bp_transfer:
                    downline_bp = downline_member.total_bp
                    
                    # Log the BP transfer
                    logger.info(f"Transferring {downline_bp} BP from {downline_member.member_id} to {member.member_id}")
                    
                    # Add BP to the sponsor
                    member.total_bp += downline_bp
                    member_bp_total += downline_bp
                    total_bp_transferred += downline_bp
                
                if downline_purchases > 0:
                    # Calculate commission
                    commission_amount = (downline_purchases * Decimal(str(difference_percentage))) / 100
                    
                    if commission_amount > 0:
                        # Create commission record
                        commission = Commission.objects.create(
                            member=member,
                            from_member=downline_member,
                            order=None,  # Monthly calculation, not tied to a specific order
                            amount=commission_amount,
                            level=1,  # Direct downline
                            is_paid=force_payment,  # Set according to the force_payment parameter
                            commission_type='MONTHLY',
                            calculation_month=first_day_last_month,
                            details={
                                'month': first_day_last_month.strftime('%Y-%m'),
                                'percentage_difference': float(difference_percentage),
                                'downline_purchases': float(downline_purchases),
                                'member_position': member.position.name,
                                'downline_position': downline_member.position.name,
                                'bp_transferred': downline_bp
                            }
                        )
                        
                        # If force_payment is True, update the wallet balance immediately
                        if force_payment:
                            # Update member's total earnings
                            member.total_earnings += commission_amount
                            
                            # Add transaction to the wallet
                            wallet, created = Wallet.objects.get_or_create(user=member.user)
                            
                            # Create wallet transaction
                            WalletTransaction.objects.create(
                                wallet=wallet,
                                amount=commission_amount,
                                transaction_type='COMMISSION',
                                description=f'Monthly commission from {downline_member.user.get_full_name() or downline_member.member_id}',
                                reference_id=str(commission.id)
                            )
                            
                            # Update wallet balance
                            wallet.balance += commission_amount
                            wallet.save()
                            
                            # Set payment date
                            commission.payment_date = timezone.now()
                            commission.save(update_fields=['payment_date'])
                        
                        member_commission_total += commission_amount
                        commissions_created += 1
            
            # Save the member with updated BP points and earnings
            member.save()
            
            # Record result for this member
            member_results.append({
                'member_id': member.member_id,
                'name': member.user.get_full_name() or member.user.username,
                'status': 'SUCCESS',
                'commission_amount': str(member_commission_total),
                'commissions_count': commissions_created,
                'bp_transferred': member_bp_total
            })
            
            total_amount += member_commission_total
        
        return {
            'success': True,
            'message': f"Successfully calculated {commissions_created} commissions totaling ₹{total_amount} and transferred {total_bp_transferred} BP",
            'details': {
                'date_range': f"{first_day_last_month} to {last_month_end}",
                'members_processed': len(members),
                'total_commissions': commissions_created,
                'total_amount': str(total_amount),
                'total_bp_transferred': total_bp_transferred,
                'force_payment': force_payment,
                'include_bp_transfer': include_bp_transfer,
                'member_results': member_results
            }
        }
        
    except Exception as e:
        logger.error(f"Error calculating admin commissions: {str(e)}")
        return {
            'success': False,
            'message': f"Error calculating commissions: {str(e)}",
            'details': {}
        }