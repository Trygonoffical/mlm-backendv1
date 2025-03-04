from django.core.management.base import BaseCommand
from django.utils import timezone
import logging
from home.utils import calculate_monthly_commissions

logger = logging.getLogger(__name__)

class Command(BaseCommand):
    help = 'Calculate monthly commissions for MLM members'

    def add_arguments(self, parser):
        parser.add_argument(
            '--force',
            action='store_true',
            help='Force calculation regardless of date',
        )

    def handle(self, *args, **kwargs):
        today = timezone.now()
        
        # Only run on the 1st of the month
        if today.day != 1:
            self.stdout.write(self.style.WARNING(f"Today is not the 1st of the month (it's {today.day}), skipping"))
            return
            
        self.stdout.write(self.style.SUCCESS(f"Starting monthly commission calculation for {today.strftime('%B %Y')}"))
        
        # Import the calculation function
        # from home.utils import calculate_monthly_commissions
        
        try:
            # Run the calculation
            result = calculate_monthly_commissions()
            
            if result:
                self.stdout.write(self.style.SUCCESS("Monthly commission calculation completed successfully"))
            else:
                self.stdout.write(self.style.ERROR("Monthly commission calculation failed or was skipped"))
                
        except Exception as e:
            logger.error(f"Error in monthly commission calculation command: {str(e)}")
            self.stdout.write(self.style.ERROR(f"Error: {str(e)}"))