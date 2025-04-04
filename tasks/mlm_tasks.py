import logging
from mlm.celery import app
from django.utils import timezone
from utils.commission_calculation import calculate_monthly_commissions
from utils.position_upgrade import check_and_upgrade_all_positions
from home.models import MLMMember

logger = logging.getLogger(__name__)

@app.task(name='mlm.calculate_monthly_commissions')
def monthly_commission_calculation_task():
    """
    Celery task to run monthly commission calculations
    This should be scheduled to run on the 1st of each month
    """
    # Check if today is the 1st of the month
    today = timezone.now()
    if today.day != 1:
        logger.info("Skipping monthly commission calculation - not the 1st of the month")
        return False
        
    logger.info("Starting monthly commission calculation")
    result = calculate_monthly_commissions()
    
    if result:
        logger.info("Monthly commission calculation completed successfully")
    else:
        logger.error("Monthly commission calculation failed")
        
    return result

@app.task(name='mlm.check_position_upgrades')
def daily_position_upgrade_check_task():
    """
    Celery task to run daily position upgrade checks
    """
    logger.info("Starting daily position upgrade check")
    result = check_and_upgrade_all_positions()
    
    if result:
        logger.info("Daily position upgrade check completed successfully")
    else:
        logger.error("Daily position upgrade check failed")
        
    return result

@app.task(name='mlm.reset_monthly_quota')
def monthly_quota_reset_task():
    """
    Celery task to reset monthly quotas
    This should be scheduled to run on the 1st of each month
    """
    # Check if today is the 1st of the month
    today = timezone.now()
    if today.day != 1:
        logger.info("Skipping monthly quota reset - not the 1st of the month")
        return False
        
    try:
        # Reset current_month_purchase for all members
        updated_count = MLMMember.objects.update(current_month_purchase=0)
        
        logger.info(f"Monthly quota reset completed successfully. Reset {updated_count} members.")
        return True
        
    except Exception as e:
        logger.error(f"Error in monthly quota reset: {str(e)}")
        return False