from django.urls import path, include
from rest_framework_simplejwt.views import TokenRefreshView
from . import views
from rest_framework.routers import DefaultRouter

router = DefaultRouter()
router.register(r'items', views.ItemViewSet, basename='item')
router.register(r'customers', views.CustomerViewSet, basename='customer')
router.register(r'vendors', views.VendorViewSet, basename='vendor')
router.register(r'create-employees', views.CreateEmployeeViewSet, basename='createemployee')
router.register(r'vehicles', views.VehicleViewSet, basename='vehicle')

urlpatterns = [
    

    ## create urls

      
     path('', include(router.urls)),
    path('api/items/types/', views.ItemViewSet.as_view({'get': 'item_types'}), name='item-types'),
   #  path('api/employees/designations/', views.EmployeeViewSet.as_view({'get': 'designations'}), name='employee-designations'),
    path('api/vehicles/expired-documents/', views.VehicleViewSet.as_view({'get': 'expired_documents'}), name='expired-documents'),
    # Authentication URLs


    path('register/', views.CompanyRegisterView.as_view(), name='company-register'),
    path('verify-otp/', views.VerifyOTPView.as_view(), name='verify-otp'),
    path('resend-otp/', views.ResendOTPView.as_view(), name='resend-otp'),
    path('login/', views.CompanyLoginView.as_view(), name='company-login'),
    path('logout/', views.CompanyLogoutView.as_view(), name='company-logout'),
    path('token/refresh/', TokenRefreshView.as_view(), name='token-refresh'),
    
    # Company URLs
    path('dashboard/', views.CompanyDashboardView.as_view(), name='company-dashboard'),
    path('profile/', views.CompanyProfileView.as_view(), name='company-profile'),
    path('change-password/', views.ChangePasswordView.as_view(), name='change-password'),
    
    # Employee URLs
    path('employees/', views.EmployeeListView.as_view(), name='employee-list'),
    path('employees/add/', views.AddEmployeeView.as_view(), name='add-employee'),
    path('employees/<int:pk>/', views.EmployeeDetailView.as_view(), name='employee-detail'),
    path('employees/<int:employee_id>/reset-password/', 
         views.ResetEmployeePasswordView.as_view(), 
         name='reset-employee-password'),
    
    # Warehouse URLs
  path('warehouses/', views.WarehouseListCreateView.as_view(), name='warehouse-list-create'),
    path('warehouses/<int:warehouse_id>/', views.WarehouseDetailView.as_view(), name='warehouse-detail'),
    path('warehouses/count/', views.WarehouseCountView.as_view(), name='warehouse-count'),
    path('warehouses/search/', views.WarehouseSearchView.as_view(), name='warehouse-search'),
    path('warehouses/bulk-delete/', views.WarehouseBulkDeleteView.as_view(), name='warehouse-bulk-delete'),


     path('forgot-password/', views.ForgotPasswordView.as_view(), name='forgot-password'),

       path('verify-forgot-password-otp/', views.VerifyForgotPasswordOTPView.as_view(), name='verify-forgot-password-otp'),
    path('resend-forgot-password-otp/', views.ResendForgotPasswordOTPView.as_view(), name='resend-forgot-password-otp'),
    
    # ✅ reset-password भी ADD करें
    path('reset-password/', views.ResetPasswordView.as_view(), name='reset-password'),

       # Employee Authentication URLs
    path('employee/login/', views.EmployeeLoginView.as_view(), name='employee-login'),
    path('employee/profile/', views.EmployeeProfileView.as_view(), name='employee-profile'),
    path('employee/dashboard/', views.EmployeeDashboardView.as_view(), name='employee-dashboard'),
    path('employee/change-password/', views.EmployeeChangePasswordView.as_view(), name='employee-change-password'),
    # Utility URLs
    path('check-exists/', views.CheckCompanyExistsView.as_view(), name='check-company-exists'),
 # Debug URL (remove in production)
    path('debug/auth-info/', views.DebugAuthInfoView.as_view(), name='debug-auth-info'),

]


