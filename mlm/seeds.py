# Create a file at yourapp/seeds.py

from django.contrib.auth import get_user_model
from home.models import StaffRole, StaffMember

User = get_user_model()

def create_admin(username, email, password):
    # Create user if doesn't exist
    if not User.objects.filter(username=username).exists():
        user = User.objects.create_superuser(
            username=username,
            email=email,
            password=password,
            role='ADMIN'
        )
        
        # Get or create admin role
        admin_role, created = StaffRole.objects.get_or_create(
            name='Administrator',
            defaults={'description': 'System administrator with all permissions'}
        )
        
        # Create staff profile
        StaffMember.objects.create(
            user=user,
            role=admin_role,
            department='Administration'
        )
        
        print(f"Admin user {username} created successfully")
    else:
        print(f"User with username {username} already exists")