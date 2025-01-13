# serializers.py
from rest_framework import serializers
from home.models import User

class UserSerializer(serializers.ModelSerializer):
    class Meta:
        model = User
        fields = [
            'id', 
            'username', 
            'phone_number', 
            'email', 
            'role',
            'first_name',
            'last_name',
            'is_active',
         
        ]
        read_only_fields = ['id']