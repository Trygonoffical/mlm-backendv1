from home.views import config
from django.urls import path 
from appAuth.views import GenerateOTP , VerifyOTP
urlpatterns = [
    path('config/', config),
    path('generate-otp/', GenerateOTP.as_view(), name='generate-otp'),
    path('verify-otp/', VerifyOTP.as_view(), name='verify-otp'),
]