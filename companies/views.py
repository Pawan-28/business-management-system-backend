from django.shortcuts import render
import json


# Create your views here.
import random
from datetime import datetime, timedelta
from django.utils import timezone
from django.conf import settings
from django.core.cache import cache
from rest_framework import status, permissions, generics
from rest_framework.response import Response
from rest_framework.views import APIView
from rest_framework_simplejwt.tokens import RefreshToken
from rest_framework_simplejwt.views import TokenObtainPairView, TokenRefreshView
from rest_framework.parsers import MultiPartParser, FormParser
from django.contrib.auth import authenticate, logout
from .models import Company, Employee, CompanySettings, Warehouse, EmployeeLoginHistory
from .serializers import (
    CompanyRegistrationSerializer,
    CompanyLoginSerializer,
    CompanyProfileSerializer,
    EmployeeSerializer,
    AddEmployeeSerializer,
    ChangePasswordSerializer,
    OTPSerializer,
    WarehouseSerializer,
    EmployeeProfileSerializer,
    EmployeeLoginSerializer,
    EmployeeChangePasswordSerializer,
)

# companies/views.py me CompanyRegisterView update karein
class CompanyRegisterView(APIView):
    permission_classes = [permissions.AllowAny]
    
    def post(self, request):
        print("="*50)
        print("REGISTRATION REQUEST RECEIVED")
        print("Request data:", request.data)
        print("Request content type:", request.content_type)
        print("="*50)
        
        serializer = CompanyRegistrationSerializer(data=request.data)
        
        print("Validating serializer...")
        is_valid = serializer.is_valid()
        print(f"Serializer valid: {is_valid}")
        
        if not is_valid:
            print("SERIALIZER ERRORS:")
            print(json.dumps(serializer.errors, indent=2))
            print("="*50)
            
            return Response({
                'success': False,
                'errors': serializer.errors
            }, status=status.HTTP_400_BAD_REQUEST)
        
        print("Serializer is valid, creating company...")
        
        try:
            company = serializer.save()
            print(f"Company created: {company.company_id}")
            
            # Generate OTP
            otp = str(random.randint(100000, 999999))
            otp_expiry = timezone.now() + timedelta(minutes=10)
            
            # Save OTP to company
            company.otp = otp
            company.otp_expiry = otp_expiry
            company.save()
            
            # Create company settings
            CompanySettings.objects.create(company=company)
            
            print(f"OTP generated: {otp} for mobile: {company.mobile}")
            
            return Response({
                'success': True,
                'message': 'Company registered successfully. OTP sent to mobile.',
                'company_id': company.company_id,
                'mobile': company.mobile,
                'requires_otp_verification': True
            }, status=status.HTTP_201_CREATED)
            
        except Exception as e:
            print(f"Error creating company: {str(e)}")
            return Response({
                'success': False,
                'error': str(e)
            }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

class VerifyOTPView(APIView):
    permission_classes = [permissions.AllowAny]
    
    def post(self, request):
        serializer = OTPSerializer(data=request.data)
        if serializer.is_valid():
            mobile = serializer.validated_data['mobile']
            otp = serializer.validated_data['otp']
            
            try:
                company = Company.objects.get(mobile=mobile)
                
                # Check OTP
                if company.otp != otp or company.otp_expiry < timezone.now():
                    return Response({
                        'success': False,
                        'error': 'Invalid or expired OTP'
                    }, status=status.HTTP_400_BAD_REQUEST)
                
                # Mark company as verified
                company.is_verified = True
                company.otp = None
                company.otp_expiry = None
                company.save()
                
                # Generate tokens
                refresh = RefreshToken.for_user(company)
                
                return Response({
                    'success': True,
                    'message': 'Company verified successfully',
                    'company_id': company.company_id,
                    'tokens': {
                        'refresh': str(refresh),
                        'access': str(refresh.access_token)
                    },
                    'company': {
                        'company_id': company.company_id,
                        'company_name': company.company_name,
                        'email': company.email,
                        'mobile': company.mobile
                    }
                })
                
            except Company.DoesNotExist:
                return Response({
                    'success': False,
                    'error': 'Company not found'
                }, status=status.HTTP_404_NOT_FOUND)
        
        return Response({
            'success': False,
            'errors': serializer.errors
        }, status=status.HTTP_400_BAD_REQUEST)

class CompanyLoginView(TokenObtainPairView):
    serializer_class = CompanyLoginSerializer
    permission_classes = [permissions.AllowAny]
    
    def post(self, request, *args, **kwargs):
        response = super().post(request, *args, **kwargs)
        
        if response.status_code == 200:
            # Customize response
            data = response.data
            return Response({
                'success': True,
                'message': 'Login successful',
                'tokens': {
                    'refresh': data['refresh'],
                    'access': data['access']
                },
                'company': data['company']
            })
        
        return response

class CompanyLogoutView(APIView):
    permission_classes = [permissions.IsAuthenticated]
    
    def post(self, request):
        try:
            refresh_token = request.data.get('refresh')
            if refresh_token:
                token = RefreshToken(refresh_token)
                token.blacklist()
            
            logout(request)
            
            return Response({
                'success': True,
                'message': 'Logged out successfully'
            })
        except Exception as e:
            return Response({
                'success': False,
                'error': str(e)
            }, status=status.HTTP_400_BAD_REQUEST)

class CompanyDashboardView(APIView):
    permission_classes = [permissions.IsAuthenticated]
    
    def get(self, request):
        company = request.user
        employees = company.employees.all()
        
        # Calculate statistics
        total_employees = employees.count()
        active_employees = employees.filter(is_active=True, status='active').count()
        
        # Recent employees
        recent_employees = employees.order_by('-created_at')[:5]
        recent_employees_data = EmployeeSerializer(recent_employees, many=True).data
        
        # Company info
        company_info = {
            'company_id': company.company_id,
            'company_name': company.company_name,
            'email': company.email,
            'mobile': company.mobile,
            'gst_number': company.gst_number,
            'is_verified': company.is_verified,
            'created_at': company.created_at
        }
        
        return Response({
            'success': True,
            'dashboard': {
                'stats': {
                    'total_employees': total_employees,
                    'active_employees': active_employees,
                    'inactive_employees': total_employees - active_employees
                },
                'company_info': company_info,
                'recent_employees': recent_employees_data
            }
        })

class CompanyProfileView(generics.RetrieveUpdateAPIView):
    serializer_class = CompanyProfileSerializer
    permission_classes = [permissions.IsAuthenticated]
    parser_classes = [MultiPartParser, FormParser]
    
    def get_object(self):
        return self.request.user
    
    def update(self, request, *args, **kwargs):
        # Handle logo upload separately if needed
        return super().update(request, *args, **kwargs)

class EmployeeListView(generics.ListAPIView):
    serializer_class = EmployeeSerializer
    permission_classes = [permissions.IsAuthenticated]
    
    def get_queryset(self):
        company = self.request.user
        return Employee.objects.filter(company=company)

class AddEmployeeView(APIView):
    permission_classes = [permissions.IsAuthenticated]
    
    def post(self, request):
        serializer = AddEmployeeSerializer(
            data=request.data,
            context={'request': request}
        )
        
        if serializer.is_valid():
            employee = serializer.save()
            
            return Response({
                'success': True,
                'message': 'Employee added successfully',
                'employee': EmployeeSerializer(employee).data
            }, status=status.HTTP_201_CREATED)
        
        return Response({
            'success': False,
            'errors': serializer.errors
        }, status=status.HTTP_400_BAD_REQUEST)

class EmployeeDetailView(generics.RetrieveUpdateDestroyAPIView):
    serializer_class = EmployeeSerializer
    permission_classes = [permissions.IsAuthenticated]
    
    def get_queryset(self):
        company = self.request.user
        return Employee.objects.filter(company=company)
    
    def destroy(self, request, *args, **kwargs):
        instance = self.get_object()
        instance.is_active = False
        instance.status = 'inactive'
        instance.save()
        
        return Response({
            'success': True,
            'message': 'Employee deactivated successfully'
        })

class ResetEmployeePasswordView(APIView):
    permission_classes = [permissions.IsAuthenticated]
    
    def post(self, request, employee_id):
        try:
            employee = Employee.objects.get(
                employee_id=employee_id,
                company=request.user
            )
            
            # Generate new password
            import secrets
            new_password = secrets.token_urlsafe(8)
            
            # Update password
            employee.password = new_password  # In production, hash this
            employee.temp_password = True
            employee.last_password_change = timezone.now()
            employee.save()
            
            # Send email with new password
            # send_password_reset_email(employee.email, new_password)
            
            return Response({
                'success': True,
                'message': 'Password reset successfully. New password sent to employee.',
                'new_password': new_password  # Remove in production
            })
            
        except Employee.DoesNotExist:
            return Response({
                'success': False,
                'error': 'Employee not found'
            }, status=status.HTTP_404_NOT_FOUND)

class ChangePasswordView(APIView):
    permission_classes = [permissions.IsAuthenticated]
    
    def post(self, request):
        serializer = ChangePasswordSerializer(data=request.data)
        
        if serializer.is_valid():
            company = request.user
            old_password = serializer.validated_data['old_password']
            new_password = serializer.validated_data['new_password']
            
            # Verify old password
            if not company.check_password(old_password):
                return Response({
                    'success': False,
                    'error': 'Old password is incorrect'
                }, status=status.HTTP_400_BAD_REQUEST)
            
            # Update password
            company.set_password(new_password)
            company.save()
            
            # Blacklist all tokens
            tokens = RefreshToken.objects.filter(user=company)
            for token in tokens:
                token.blacklist()
            
            return Response({
                'success': True,
                'message': 'Password changed successfully. Please login again.'
            })
        
        return Response({
            'success': False,
            'errors': serializer.errors
        }, status=status.HTTP_400_BAD_REQUEST)

class ResendOTPView(APIView):
    permission_classes = [permissions.AllowAny]
    
    def post(self, request):
        mobile = request.data.get('mobile')
        
        if not mobile:
            return Response({
                'success': False,
                'error': 'Mobile number is required'
            }, status=status.HTTP_400_BAD_REQUEST)
        
        try:
            company = Company.objects.get(mobile=mobile)
            
            # Generate new OTP
            otp = str(random.randint(100000, 999999))
            otp_expiry = timezone.now() + timedelta(minutes=10)
            
            company.otp = otp
            company.otp_expiry = otp_expiry
            company.save()
            
            # Send OTP
            # send_otp_sms(mobile, otp)
            print(f"[DEBUG] New OTP for {mobile}: {otp}")
            
            return Response({
                'success': True,
                'message': 'OTP sent successfully',
                'mobile': mobile
            })
            
        except Company.DoesNotExist:
            return Response({
                'success': False,
                'error': 'Company not found'
            }, status=status.HTTP_404_NOT_FOUND)

class CheckCompanyExistsView(APIView):
    permission_classes = [permissions.AllowAny]
    
    def get(self, request):
        email = request.query_params.get('email')
        mobile = request.query_params.get('mobile')
        gst_number = request.query_params.get('gst_number')
        
        response = {}
        
        if email:
            response['email_exists'] = Company.objects.filter(email=email).exists()
        
        if mobile:
            response['mobile_exists'] = Company.objects.filter(mobile=mobile).exists()
        
        if gst_number:
            response['gst_exists'] = Company.objects.filter(gst_number=gst_number).exists()
        
        return Response(response)
    

#warehouse views 
from rest_framework import generics, permissions, status
from rest_framework.response import Response
from rest_framework.views import APIView
from django.shortcuts import get_object_or_404
from .models import Warehouse
from .serializers import WarehouseSerializer

# ===================== WAREHOUSE VIEWS =====================

class WarehouseListCreateView(generics.ListCreateAPIView):
    serializer_class = WarehouseSerializer
    permission_classes = [permissions.IsAuthenticated]
    
    def get_queryset(self):
        """
        Since request.user is already a Company object (from your authentication),
        we can use it directly
        """
        try:
            # request.user is already a Company object
            company = self.request.user
            print(f"DEBUG: Getting warehouses for company: {company.company_name}")
            return Warehouse.objects.filter(company=company).order_by('-created_at')
        except Exception as e:
            print(f"DEBUG Error in get_queryset: {e}")
            return Warehouse.objects.none()
    
    def perform_create(self, serializer):
        """
        Save warehouse with the authenticated company
        """
        try:
            # request.user is already the Company object
            company = self.request.user
            print(f"DEBUG: Creating warehouse for company: {company.company_name}")
            serializer.save(company=company)
        except Exception as e:
            print(f"DEBUG Error in perform_create: {e}")
            raise
    
    def list(self, request, *args, **kwargs):
        """
        Custom list response with company info
        """
        try:
            response = super().list(request, *args, **kwargs)
            company = request.user  # Already a Company object
            
            response.data = {
                "success": True,
                "company": {
                    "company_id": company.company_id,
                    "company_name": company.company_name,
                    "email": company.email,
                },
                "warehouses": response.data,
                "count": len(response.data),
                "timestamp": timezone.now().isoformat()
            }
            return response
        except Exception as e:
            print(f"DEBUG Error in list: {e}")
            return Response({
                "success": False,
                "error": str(e)
            }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

class WarehouseDetailView(generics.RetrieveUpdateDestroyAPIView):
    serializer_class = WarehouseSerializer
    permission_classes = [permissions.IsAuthenticated]
    lookup_field = 'warehouse_id'
    
    def get_queryset(self):
        """
        Get warehouses for authenticated company
        """
        try:
            # request.user is Company object
            company = self.request.user
            return Warehouse.objects.filter(company=company)
        except:
            return Warehouse.objects.none()
    
    def get_object(self):
        """
        Get warehouse with permission check
        """
        queryset = self.get_queryset()
        warehouse_id = self.kwargs['warehouse_id']
        
        try:
            obj = queryset.get(warehouse_id=warehouse_id)
            print(f"DEBUG: Found warehouse: {obj.warehouse_name}")
            return obj
        except Warehouse.DoesNotExist:
            print(f"DEBUG: Warehouse {warehouse_id} not found")
            from django.http import Http404
            raise Http404("Warehouse not found or you don't have permission")
    
    def perform_update(self, serializer):
        """
        Update warehouse - company remains same
        """
        try:
            # Keep the same company (request.user is the company)
            company = self.request.user
            print(f"DEBUG: Updating warehouse for company: {company.company_name}")
            serializer.save(company=company)
        except Exception as e:
            print(f"DEBUG Error in perform_update: {e}")
            raise
    
    def destroy(self, request, *args, **kwargs):
        """
        Delete warehouse with proper response
        """
        try:
            instance = self.get_object()
            warehouse_name = instance.warehouse_name
            company_name = instance.company.company_name
            
            self.perform_destroy(instance)
            
            print(f"DEBUG: Deleted warehouse '{warehouse_name}' from company '{company_name}'")
            
            return Response({
                "success": True,
                "message": f"Warehouse '{warehouse_name}' deleted successfully",
                "deleted_id": kwargs['warehouse_id'],
                "company": company_name,
                "timestamp": timezone.now().isoformat()
            })
            
        except Exception as e:
            print(f"DEBUG Error in destroy: {e}")
            return Response({
                "success": False,
                "error": str(e)
            }, status=status.HTTP_400_BAD_REQUEST)

# Additional warehouse views

class WarehouseCountView(APIView):
    permission_classes = [permissions.IsAuthenticated]
    
    def get(self, request):
        try:
            # request.user is Company object
            company = request.user
            count = Warehouse.objects.filter(company=company).count()
            
            return Response({
                "success": True,
                "company_id": company.company_id,
                "company_name": company.company_name,
                "warehouse_count": count,
                "timestamp": timezone.now().isoformat()
            })
        except Exception as e:
            return Response({
                "success": False,
                "error": str(e)
            }, status=status.HTTP_400_BAD_REQUEST)

class WarehouseSearchView(generics.ListAPIView):
    serializer_class = WarehouseSerializer
    permission_classes = [permissions.IsAuthenticated]
    
    def get_queryset(self):
        try:
            # request.user is Company object
            company = self.request.user
            queryset = Warehouse.objects.filter(company=company)
            
            # Search by name or address
            search_query = self.request.query_params.get('search', '')
            if search_query:
                queryset = queryset.filter(
                    warehouse_name__icontains=search_query
                ) | queryset.filter(
                    address__icontains=search_query
                )
            
            return queryset.order_by('-created_at')
        except Exception as e:
            print(f"DEBUG Error in search: {e}")
            return Warehouse.objects.none()
    
    def list(self, request, *args, **kwargs):
        try:
            response = super().list(request, *args, **kwargs)
            company = request.user
            
            return Response({
                "success": True,
                "company": company.company_name,
                "search_results": response.data,
                "count": len(response.data),
                "search_query": request.query_params.get('search', ''),
                "timestamp": timezone.now().isoformat()
            })
        except Exception as e:
            return Response({
                "success": False,
                "error": str(e)
            }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

# Bulk operations for warehouse
class WarehouseBulkDeleteView(APIView):
    permission_classes = [permissions.IsAuthenticated]
    
    def delete(self, request):
        """
        Delete multiple warehouses at once
        """
        try:
            warehouse_ids = request.data.get('warehouse_ids', [])
            
            if not warehouse_ids:
                return Response({
                    "success": False,
                    "error": "No warehouse IDs provided"
                }, status=status.HTTP_400_BAD_REQUEST)
            
            company = request.user
            warehouses = Warehouse.objects.filter(
                warehouse_id__in=warehouse_ids,
                company=company
            )
            
            count = warehouses.count()
            
            if count == 0:
                return Response({
                    "success": False,
                    "error": "No warehouses found to delete"
                }, status=status.HTTP_404_NOT_FOUND)
            
            # Get names before deleting
            warehouse_names = list(warehouses.values_list('warehouse_name', flat=True))
            
            # Delete warehouses
            warehouses.delete()
            
            return Response({
                "success": True,
                "message": f"Deleted {count} warehouse(s)",
                "deleted_count": count,
                "deleted_names": warehouse_names,
                "company": company.company_name,
                "timestamp": timezone.now().isoformat()
            })
            
        except Exception as e:
            return Response({
                "success": False,
                "error": str(e)
            }, status=status.HTTP_400_BAD_REQUEST)

# Debug view to check authentication
class DebugAuthInfoView(APIView):
    permission_classes = [permissions.IsAuthenticated]
    
    def get(self, request):
        """
        Debug endpoint to check what request.user contains
        """
        user = request.user
        
        data = {
            "success": True,
            "authentication_info": {
                "user_type": str(type(user)),
                "is_authenticated": request.user.is_authenticated,
                "user_id": getattr(user, 'id', None),
                "company_id": getattr(user, 'company_id', None),
                "company_name": getattr(user, 'company_name', None),
                "email": getattr(user, 'email', None),
                "attributes": [attr for attr in dir(user) if not attr.startswith('_')][:15]
            },
            "request_info": {
                "method": request.method,
                "content_type": request.content_type,
                "has_auth_header": 'Authorization' in request.headers,
                "user_agent": request.META.get('HTTP_USER_AGENT', '')
            }
        }
        
        # Check if it's a Company object
        if hasattr(user, 'company_name'):
            data["authentication_info"]["object_type"] = "Company"
            data["authentication_info"]["warehouse_count"] = Warehouse.objects.filter(company=user).count()
        
        return Response(data)




# Employee Authentication Views
# views.py में EmployeeLoginView

class EmployeeLoginView(APIView):
    permission_classes = [permissions.AllowAny]
    
    def post(self, request):
        print("="*50)
        print("EMPLOYEE LOGIN REQUEST RECEIVED")
        print("Data:", request.data)
        print("="*50)
        
        serializer = EmployeeLoginSerializer(data=request.data)
        
        if serializer.is_valid():
            try:
                validated_data = serializer.validated_data
                
                # ✅ Employee object लें
                employee = validated_data.get('employee_object')
                
                if not employee:
                    return Response({
                        'success': False,
                        'error': 'Employee object not found in response'
                    }, status=status.HTTP_400_BAD_REQUEST)
                
                print(f"DEBUG: Employee login successful - {employee.full_name}")
                
                # Track login history
                EmployeeLoginHistory.objects.create(
                    employee=employee,
                    ip_address=self.get_client_ip(request),
                    user_agent=request.META.get('HTTP_USER_AGENT', ''),
                    success=True
                )
                
                return Response({
                    'success': True,
                    'message': 'Login successful',
                    'tokens': {
                        'refresh': validated_data.get('refresh'),
                        'access': validated_data.get('access')
                    },
                    'employee': validated_data.get('employee_data', {}),
                    'company': validated_data.get('company_data', {})
                }, status=status.HTTP_200_OK)
                
            except Exception as e:
                print(f"DEBUG: Employee login processing error: {str(e)}")
                import traceback
                traceback.print_exc()
                return Response({
                    'success': False,
                    'error': str(e)
                }, status=status.HTTP_400_BAD_REQUEST)
        
        print("DEBUG: Employee login validation failed")
        print("Errors:", serializer.errors)
        return Response({
            'success': False,
            'errors': serializer.errors
        }, status=status.HTTP_400_BAD_REQUEST)
    
    def get_client_ip(self, request):
        x_forwarded_for = request.META.get('HTTP_X_FORWARDED_FOR')
        if x_forwarded_for:
            ip = x_forwarded_for.split(',')[0]
        else:
            ip = request.META.get('REMOTE_ADDR')
        return ip

class EmployeeProfileView(APIView):
    permission_classes = [permissions.IsAuthenticated]
    
    def get(self, request):
        """
        Get employee profile - Requires employee token
        """
        # Get employee from token or request
        try:
            # This needs custom authentication to get employee from token
            # For now, get from email in token
            email = request.user.email
            employee = Employee.objects.get(email=email, is_active=True)
            
            return Response({
                'success': True,
                'employee': EmployeeProfileSerializer(employee).data
            })
        except Employee.DoesNotExist:
            return Response({
                'success': False,
                'error': 'Employee profile not found'
            }, status=status.HTTP_404_NOT_FOUND)
        except Exception as e:
            return Response({
                'success': False,
                'error': str(e)
            }, status=status.HTTP_400_BAD_REQUEST)

class EmployeeChangePasswordView(APIView):
    permission_classes = [permissions.AllowAny]
    
    def post(self, request):
        # Custom validation for employee
        email = request.data.get('email')
        company_id = request.data.get('company_id')
        old_password = request.data.get('old_password')
        new_password = request.data.get('new_password')
        confirm_password = request.data.get('confirm_password')
        
        # Manual validation
        if not all([email, company_id, old_password, new_password, confirm_password]):
            return Response({
                'success': False,
                'error': 'All fields are required'
            }, status=status.HTTP_400_BAD_REQUEST)
        
        if new_password != confirm_password:
            return Response({
                'success': False,
                'error': 'New passwords do not match'
            }, status=status.HTTP_400_BAD_REQUEST)
        
        if new_password == old_password:
            return Response({
                'success': False,
                'error': 'New password must be different from old password'
            }, status=status.HTTP_400_BAD_REQUEST)
        
        try:
            employee = Employee.objects.get(
                email=email,
                company_id=company_id,
                is_active=True
            )
            
            if not employee.check_password(old_password):
                return Response({
                    'success': False,
                    'error': 'Old password is incorrect'
                }, status=status.HTTP_400_BAD_REQUEST)
            
            employee.set_password(new_password)
            employee.save()
            
            return Response({
                'success': True,
                'message': 'Password changed successfully'
            })
            
        except Employee.DoesNotExist:
            return Response({
                'success': False,
                'error': 'Employee not found'
            }, status=status.HTTP_404_NOT_FOUND)
        except Exception as e:
            return Response({
                'success': False,
                'error': str(e)
            }, status=status.HTTP_400_BAD_REQUEST)

class EmployeeDashboardView(APIView):
    permission_classes = [permissions.IsAuthenticated]
    
    def get(self, request):
        """
        Employee dashboard with stats based on role
        """
        try:
            # Get employee
            email = request.user.email
            employee = Employee.objects.get(email=email, is_active=True)
            
            # Basic employee info
            employee_data = EmployeeProfileSerializer(employee).data
            
            # Role-based dashboard data
            dashboard_data = {
                'employee': employee_data,
                'company': {
                    'company_id': employee.company.company_id,
                    'company_name': employee.company.company_name,
                },
                'stats': {}
            }
            
            # Add role-specific data
            if employee.role in ['admin', 'manager']:
                # Managers can see employee count
                total_employees = Employee.objects.filter(
                    company=employee.company,
                    is_active=True
                ).count()
                dashboard_data['stats']['total_employees'] = total_employees
            
            # Add warehouse count if applicable
            if employee.role in ['admin', 'manager', 'supervisor']:
                warehouse_count = Warehouse.objects.filter(
                    company=employee.company
                ).count()
                dashboard_data['stats']['warehouse_count'] = warehouse_count
            
            return Response({
                'success': True,
                'dashboard': dashboard_data
            })
            
        except Employee.DoesNotExist:
            return Response({
                'success': False,
                'error': 'Employee not found'
            }, status=status.HTTP_404_NOT_FOUND)

# ===================== URL CONFIGURATION =====================

# Add these to your urls.py
"""
from django.urls import path
from . import views

urlpatterns = [
    # Warehouse URLs
    path('warehouses/', views.WarehouseListCreateView.as_view(), name='warehouse-list-create'),
    path('warehouses/<int:warehouse_id>/', views.WarehouseDetailView.as_view(), name='warehouse-detail'),
    path('warehouses/count/', views.WarehouseCountView.as_view(), name='warehouse-count'),
    path('warehouses/search/', views.WarehouseSearchView.as_view(), name='warehouse-search'),
    path('warehouses/bulk-delete/', views.WarehouseBulkDeleteView.as_view(), name='warehouse-bulk-delete'),
    
    # Debug URL (remove in production)
    path('debug/auth-info/', views.DebugAuthInfoView.as_view(), name='debug-auth-info'),
]
"""