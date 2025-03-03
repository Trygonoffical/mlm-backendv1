# Import all tasks for easy reference

from tasks.mlm_tasks import (
    monthly_commission_calculation_task,
    daily_position_upgrade_check_task,
    monthly_quota_reset_task
)

from tasks.notification_tasks import (
    send_kyc_approval_notification_task
)

# Add other task imports as you create them