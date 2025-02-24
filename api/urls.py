from home.views import config
from django.conf import settings
from django.conf.urls.static import static
from django.urls import path , include
from rest_framework.routers import DefaultRouter
from appAuth.views import GenerateOTP , VerifyOTP , UserLogin , RefreshToken , ValidateTokenView , CustomTokenRefreshView , HomeSliderViewSet , CategoryViewSet , ProductViewSet , PositionViewSet , MLMMemberViewSet , TestimonialViewSet , AdvertisementViewSet , SuccessStoryViewSet , CustomerPickViewSet , CompanyInfoViewSet , AboutViewSet , HomeSectionViewSet , MenuViewSet , CustomPageViewSet , KYCDocumentViewSet , BlogViewSet , CreateOrderView, VerifyPaymentView , AddressViewSet , CustomerProfileView , OrderProcessView , PaymentWebhookView , download_invoice , OrderViewSet , WalletViewSet, WalletTransactionViewSet, WithdrawalRequestViewSet , NotificationViewSet , AdminOrderListView , UpdateOrderStatusView , MLMOrderListView , MLMMemberTreeView , MLMMemberDetailsView , MLMReportView , MLMDashboardView , AdminDashboardView , MLMMemberRegistrationView , DownlineListView , ContactViewSet , NewsletterViewSet , MLMLiveCommissionView , AdminCustomerViewSet , OrderTrackingView , CheckUsernameView , UpdateStockView , CheckStockAvailabilityView , OrderCancellationView , RequestPasswordResetView , ProcessPasswordResetView , PasswordResetRequestListView , MLMProfileView


router = DefaultRouter()
router.register(r'home-sliders', HomeSliderViewSet, basename='home-slider')
router.register(r'categories', CategoryViewSet , basename='category')
router.register(r'products', ProductViewSet , basename='products')
router.register(r'positions', PositionViewSet , basename='positions') 
router.register(r'mlm-members', MLMMemberViewSet , basename='mlm-members')
router.register(r'testimonials', TestimonialViewSet , basename='testimonials')
router.register(r'advertisements', AdvertisementViewSet , basename='advertisements')
router.register(r'success-story', SuccessStoryViewSet , basename='success-story')
router.register(r'customer-pick', CustomerPickViewSet , basename='customer-pick')
router.register(r'company-info', CompanyInfoViewSet , basename='company-info')
router.register(r'about', AboutViewSet, basename='about')
router.register(r'home-sections', HomeSectionViewSet, basename='home-sections')
router.register(r'menu', MenuViewSet, basename='menu')
router.register(r'custom-pages', CustomPageViewSet , basename='custom-pages')
router.register(r'kyc-documents', KYCDocumentViewSet, basename='kyc-document')
router.register(r'blogs', BlogViewSet , basename='blogs')
router.register(r'addresses', AddressViewSet , basename='addresses')
router.register(r'allorders', OrderViewSet, basename='allorders')

router.register(r'wallet', WalletViewSet, basename='wallet')
router.register(r'wallet-transactions', WalletTransactionViewSet, basename='wallet-transactions')
router.register(r'withdrawal-requests', WithdrawalRequestViewSet, basename='withdrawal-requests')
router.register(r'notifications', NotificationViewSet, basename='notifications')
router.register(r'contacts', ContactViewSet, basename='contact')
router.register(r'newsletters', NewsletterViewSet ,basename='newsletters' )
router.register(r'admin/customers', AdminCustomerViewSet, basename='admin-customers')

urlpatterns = [
    path('config/', config),
    path('generate-otp/', GenerateOTP.as_view(), name='generate-otp'),
    path('verify-otp/', VerifyOTP.as_view(), name='verify-otp'),


    #home slider url
    path('', include(router.urls)),

    # Username/password routes for MLM members and admin
    path('login/', UserLogin.as_view(), name='user-login'),
    path('refresh-token/', RefreshToken.as_view(), name='refresh-token'),


    # For middelware
    path('validate-token/', ValidateTokenView.as_view(), name='validate-token'),
    path('token/refresh/', CustomTokenRefreshView.as_view(), name='token_refresh'),

    #paymnet Verification
    path('create-order/', CreateOrderView.as_view(), name='create_order'),
    path('verify-payment/', VerifyPaymentView.as_view(), name='verify_payment'),

    # Customer Profile update
    path('profile/details/', CustomerProfileView.as_view(), name='customer-profile-details'),
    path('profile/update/', CustomerProfileView.as_view(), name='customer-profile-update'),

    # MLM Memver Profile update
    path('MLMprofile/details/', MLMProfileView.as_view(), name='Member-profile-details'),
    path('MLMprofile/update/', MLMProfileView.as_view(), name='member-profile-update'),


    path('orders/create/', OrderProcessView.as_view(), name='create-order'),
    path('orders/<int:order_id>/invoice/', download_invoice, name='download-invoice'),
    path('payments/webhook/', PaymentWebhookView.as_view(), name='payment-webhook'),


    path('wallet/withdraw/', WalletViewSet.as_view({'post': 'withdraw'}), name='wallet-withdraw'),
    path('admin/wallet/withdrawals/<int:pk>/approve/', 
         WithdrawalRequestViewSet.as_view({'post': 'approve'}), name='withdrawal-approve'),
    path('admin/wallet/withdrawals/<int:pk>/reject/', 
         WithdrawalRequestViewSet.as_view({'post': 'reject'}), name='withdrawal-reject'),

    path('mlm-members/<str:member_id>/verify-bank/', 
     MLMMemberViewSet.as_view({'post': 'verify_bank_details'}), 
     name='verify-bank-details'),


     path('mlm-members/<str:member_id>/update-profile/', 
         MLMMemberViewSet.as_view({'post': 'update_profile'}), 
         name='mlm-member-update-profile'),
    
    path('mlm-members/<str:member_id>/reset-password/', 
         MLMMemberViewSet.as_view({'post': 'reset_password'}), 
         name='mlm-member-reset-password'),

    path('admin/orders/', AdminOrderListView.as_view(), name='admin-order-list'),
    path('admin/orders/<int:order_id>/status/', UpdateOrderStatusView.as_view(), name='update-order-status'),

    path('mlm/orders/', MLMOrderListView.as_view(), name='mlm-order-list'),


    path('mlm/member-tree/', MLMMemberTreeView.as_view(), name='mlm-member-tree'),
    path('mlm/member/<str:member_id>/', MLMMemberDetailsView.as_view(), name='mlm-member-details'),

    path('mlm/reports/', MLMReportView.as_view(), name='mlm-reports'),

    path('mlm/dashboard/', MLMDashboardView.as_view(), name='mlm-dashboard'),

    path('admin/dashboard/', AdminDashboardView.as_view(), name='admin-dashboard'),

#     path('mlm/register-member/', MLMMemberRegistrationView.as_view(), name='mlm-member-registration'),




    path('mlm/register-member/', MLMMemberRegistrationView.as_view(), name='mlm-member-registration'),
    path('mlm/downline/', DownlineListView.as_view(), name='mlm-downline-list'),

     path('mlm/member/<str:member_id>/live-commissions/', MLMLiveCommissionView.as_view(), name='mlm-live-commissions'),

     path('orders/track/', OrderTrackingView.as_view(), name='order-tracking'),

     path('check-username/', CheckUsernameView.as_view(), name='check-username'),



    path('update-stock/', UpdateStockView.as_view(), name='update-stock'),
    path('check-stock/', CheckStockAvailabilityView.as_view(), name='check-stock'),
    path('orders/<int:order_id>/cancel/', OrderCancellationView.as_view(), name='cancel-order'),

    path('request-password-reset/', 
         RequestPasswordResetView.as_view(), 
         name='request-password-reset'),
    path('process-password-reset/<int:request_id>/',
         ProcessPasswordResetView.as_view(),
         name='process-password-reset'),
    path('password-reset-requests/', 
         PasswordResetRequestListView.as_view(), 
         name='password-reset-requests'),
    # path('kyc-documents/bank-details/', 
    #  KYCDocumentViewSet.as_view({'get': 'bank_details', 'post': 'bank_details', 'put': 'bank_details'}), 
    #  name='kyc-bank-details'),
]


