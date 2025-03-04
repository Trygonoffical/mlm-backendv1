# Finally, let's set up a cron job for automatic calculation on the 1st of each month
# Create a file: scripts/cron_jobs.py

#!/usr/bin/env python
"""
Cron job script to calculate monthly commissions on the 1st of each month.
Add this to your server's crontab:

0 0 1 * * /path/to/your/venv/bin/python /path/to/your/project/scripts/cron_jobs.py calculate_commissions
"""

import os
import sys
import django
import logging
from datetime import datetime

# Set up Django environment
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'mlm.settings')
django.setup()

# Set up logging
logging.basicConfig(
    filename='cron_jobs.log',
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger('cron_jobs')

def calculate_commissions():
    """Calculate monthly commissions"""
    from home.utils import calculate_monthly_commissions
    
    # Get current day
    today = datetime.now()
    
    # Only run on the 1st of the month
    if today.day == 1:
        logger.info('Starting monthly commission calculation')
        
        try:
            result = calculate_monthly_commissions()
            if result:
                logger.info('Successfully calculated monthly commissions')
            else:
                logger.error('Failed to calculate monthly commissions')
        except Exception as e:
            logger.error(f'Error calculating monthly commissions: {str(e)}')
    else:
        logger.info(f'Skipping commission calculation - today is {today.day}, not 1st of month')

if __name__ == '__main__':
    if len(sys.argv) > 1:
        command = sys.argv[1]
        
        if command == 'calculate_commissions':
            calculate_commissions()
        else:
            logger.error(f'Unknown command: {command}')
    else:
        logger.error('No command specified')