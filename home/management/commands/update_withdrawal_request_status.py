from django.core.management.base import BaseCommand
from django.utils import timezone
import logging

logger = logging.getLogger(__name__)

class Command(BaseCommand):
    help = 'Update withdrawal request status to allow processing after the 15th of the month'

    def handle(self, *args, **kwargs):
        today = timezone.now()
        
        # Only run on or after the 15th
        if today.day < 15:
            self.stdout.write(self.style.WARNING(f"Today is before the 15th (it's {today.day}), skipping"))
            return
            
        self.stdout.write(self.style.SUCCESS(f"Starting withdrawal status update for {today.strftime('%B %Y')}"))
        
        # Import the update function
        from home.utils import update_withdrawal_request_status
        
        try:
            # Run the update
            result = update_withdrawal_request_status()
            
            if result:
                self.stdout.write(self.style.SUCCESS("Withdrawal status update completed successfully"))
            else:
                self.stdout.write(self.style.WARNING("No withdrawal status updates needed"))
                
        except Exception as e:
            logger.error(f"Error in withdrawal status update command: {str(e)}")
            self.stdout.write(self.style.ERROR(f"Error: {str(e)}"))