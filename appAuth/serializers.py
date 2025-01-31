# serializers.py
from rest_framework import serializers
from home.models import User
from django.contrib.auth import get_user_model


# class UserSerializer(serializers.ModelSerializer):
#     class Meta:
#         model = User
#         fields = [
#             'id', 
#             'username', 
#             'phone_number', 
#             'email', 
#             'role',
#             'first_name',
#             'last_name',
#             'is_active',
         
#         ]
#         read_only_fields = ['id']



# User = get_user_model()

class MLMMemberSerializer(serializers.Serializer):
    member_id = serializers.CharField()
    position = serializers.CharField(source='position.name')
    can_earn = serializers.BooleanField(source='position.can_earn_commission')
    is_active = serializers.BooleanField()
    total_earnings = serializers.DecimalField(max_digits=10, decimal_places=2)
    current_month_purchase = serializers.DecimalField(max_digits=10, decimal_places=2)

class UserSerializer(serializers.ModelSerializer):
    mlm_data = MLMMemberSerializer(source='mlm_profile', read_only=True)

    class Meta:
        model = User
        fields = ('id', 'username', 'email', 'phone_number', 'role', 'first_name', 'last_name','mlm_data')
        read_only_fields = ('id', 'role')