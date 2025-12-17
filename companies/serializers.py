from rest_framework import serializers
from rest_framework_simplejwt.serializers import TokenObtainPairSerializer
from rest_framework_simplejwt.tokens import RefreshToken
from django.contrib.auth import authenticate
from .models import Company, Employee, Warehouse
from django.core.validators import validate_email
from django.core.exceptions import ValidationError

class CompanyRegistrationSerializer(serializers.ModelSerializer):
    password = serializers.CharField(
        write_only=True,
        required=True,
        style={'input_type': 'password'},
        min_length=8,
        error_messages={
            'min_length': 'Password must be at least 8 characters long.'
        }
    )
    confirm_password = serializers.CharField(
        write_only=True,
        required=True,
        style={'input_type': 'password'}
    )
    
    class Meta:
        model = Company
        fields = [
            'company_name',
            'gst_number',
            'registration_number',
            'email',
            'mobile',
            'alternate_mobile',
            'address_line1',
            'address_line2',
            'city',
            'state',
            'pincode',
            'country',
            'business_type',
            'business_subtype',
            'website',
            'industry',
            'company_size',
            'established_year',
            'password',
            'confirm_password'
        ]
        extra_kwargs = {
            'company_name': {'required': True},
            'gst_number': {'required': True},
            'email': {'required': True},
            'mobile': {'required': True},
        }
    
    def validate_email(self, value):
        try:
            validate_email(value)
        except ValidationError:
            raise serializers.ValidationError("Enter a valid email address.")
        
        if Company.objects.filter(email=value).exists():
            raise serializers.ValidationError("A company with this email already exists.")
        return value
    
    def validate_mobile(self, value):
        if Company.objects.filter(mobile=value).exists():
            raise serializers.ValidationError("A company with this mobile number already exists.")
        return value
    
    def validate_gst_number(self, value):
        if Company.objects.filter(gst_number=value).exists():
            raise serializers.ValidationError("A company with this GST number already exists.")
        return value
    
    def validate(self, data):
        if data['password'] != data['confirm_password']:
            raise serializers.ValidationError({
                'confirm_password': "Passwords do not match."
            })
        
        # Validate password strength
        password = data['password']
        if len(password) < 8:
            raise serializers.ValidationError({
                'password': "Password must be at least 8 characters long."
            })
        
        return data
    
    def create(self, validated_data):
        # Remove confirm_password from validated_data
        validated_data.pop('confirm_password')
        
        password = validated_data.pop('password')
        
        # Create company
        company = Company.objects.create_company(
            **validated_data,
            password=password
        )
        
        return company

class CompanyLoginSerializer(TokenObtainPairSerializer):
    email = serializers.EmailField(required=True)
    password = serializers.CharField(
        write_only=True,
        required=True,
        style={'input_type': 'password'}
    )
    
    def validate(self, attrs):
        email = attrs.get('email')
        password = attrs.get('password')
        
        # Check if company exists
        try:
            company = Company.objects.get(email=email)
        except Company.DoesNotExist:
            raise serializers.ValidationError({
                'email': 'No company found with this email address.'
            })
        
        # Check if company is verified
        if not company.is_verified:
            raise serializers.ValidationError({
                'email': 'Company not verified. Please verify your email first.'
            })
        
        # Check if company is active
        if not company.is_active:
            raise serializers.ValidationError({
                'email': 'Company account is inactive. Please contact support.'
            })
        
        # Authenticate
        company = authenticate(
            email=email,
            password=password
        )
        
        if not company:
            raise serializers.ValidationError({
                'password': 'Invalid password.'
            })
        
        # Generate tokens
        refresh = self.get_token(company)
        
        # Update last login
        company.save()
        
        return {
            'refresh': str(refresh),
            'access': str(refresh.access_token),
            'company': {
                'company_id': company.company_id,
                'company_name': company.company_name,
                'email': company.email,
                'mobile': company.mobile,
                'is_verified': company.is_verified,
            }
        }
    
    @classmethod
    def get_token(cls, user):
        token = super().get_token(user)
        
        # Add custom claims
        token['company_id'] = user.company_id
        token['company_name'] = user.company_name
        token['email'] = user.email
        token['is_verified'] = user.is_verified
        
        return token

class CompanyProfileSerializer(serializers.ModelSerializer):
    full_address = serializers.CharField(read_only=True)
    established_year = serializers.IntegerField(required=False, allow_null=True)
    
    class Meta:
        model = Company
        fields = [
            'company_id',
            'company_name',
            'registration_number',
            'gst_number',
            'email',
            'mobile',
            'alternate_mobile',
            'address_line1',
            'address_line2',
            'city',
            'state',
            'pincode',
            'country',
            'full_address',
            'business_type',
            'business_subtype',
            'website',
            'industry',
            'company_size',
            'established_year',
            'logo',
            'is_verified',
            'created_at'
        ]
        read_only_fields = ['company_id', 'email', 'is_verified', 'created_at']
class EmployeeSerializer(serializers.ModelSerializer):
    company_name = serializers.CharField(source='company.company_name', read_only=True)
    
    class Meta:
        model = Employee
        fields = [
            'employee_id',
            'employee_code',
            'company',
            'company_name',
            'full_name',
            'email',
            'mobile',
            # 'role',
            # 'department',
            # 'designation',
            # 'joining_date',
            # 'salary',
            'employment_type',
            'status',
            'is_active',
            'address',
            'date_of_birth',
            'profile_picture',
            'created_at',
            'last_login'
        ]
        read_only_fields = ['employee_id', 'employee_code', 'created_at', 'last_login']
    
    def validate_email(self, value):
        request = self.context.get('request')
        company = request.user if request else None
        
        # If updating an existing instance, allow same email
        instance = getattr(self, 'instance', None)
        if instance and instance.email == value:
            return value
        
        # Check if email already exists for this company (excluding current instance)
        if company and Employee.objects.filter(company=company, email=value).exclude(pk=getattr(instance, 'pk', None)).exists():
            raise serializers.ValidationError(
                "An employee with this email already exists in your company."
            )
        return value

class AddEmployeeSerializer(serializers.ModelSerializer):
    password = serializers.CharField(
        write_only=True,
        required=False,
        style={'input_type': 'password'}
    )
    send_credentials = serializers.BooleanField(write_only=True, default=True)
    
    class Meta:
        model = Employee
        fields = [
            'full_name',
            'email',
            'mobile',
            # 'role',
            # 'department',
            # 'designation',
            # 'joining_date',
            # 'salary',
            'employment_type',
            'address',
            'date_of_birth',
            'password',
            'send_credentials'
        ]
    
    def create(self, validated_data):
        request = self.context.get('request')
        company = request.user
        
        send_credentials = validated_data.pop('send_credentials', True)
        password = validated_data.pop('password', None)
        
        if not password:
            # Generate random password
            import secrets
            password = secrets.token_urlsafe(8)
        
        employee = Employee.objects.create(
            company=company,
            password=password,
            **validated_data
        )
        
        if send_credentials:
            # Send email with credentials
            pass  # Implement email sending
        
        return employee

class ChangePasswordSerializer(serializers.Serializer):
    old_password = serializers.CharField(required=True)
    new_password = serializers.CharField(required=True, min_length=8)
    confirm_password = serializers.CharField(required=True)
    
    def validate(self, data):
        if data['new_password'] != data['confirm_password']:
            raise serializers.ValidationError({
                'confirm_password': "New passwords do not match."
            })
        
        if data['old_password'] == data['new_password']:
            raise serializers.ValidationError({
                'new_password': "New password must be different from old password."
            })
        
        return data

class OTPSerializer(serializers.Serializer):
    mobile = serializers.CharField(required=True)
    otp = serializers.CharField(required=True, min_length=6, max_length=6)

    
from rest_framework import serializers
from .models import Warehouse, Company

class WarehouseSerializer(serializers.ModelSerializer):
    company_name = serializers.CharField(source='company.company_name', read_only=True)
    warehouse_name = serializers.CharField(required=False, allow_blank=True)
    company_id = serializers.IntegerField(source='company.company_id', read_only=True)
    
    class Meta:
        model = Warehouse
        fields = [
            'warehouse_id',
            'warehouse_name',
            'address',
            'company_id',
            'company_name',
            'created_at'
        ]
        read_only_fields = ['warehouse_id', 'created_at']
    
    def validate_warehouse_name(self, value):
        # Allow empty warehouse_name (we'll auto-generate if missing).
        request = self.context.get('request')
        if not value:
            return value

        # If provided, prevent duplicates within the same company on creation
        if request and request.method == 'POST':  # Only for creation
            company = request.user
            if Warehouse.objects.filter(company=company, warehouse_name__iexact=value).exists():
                raise serializers.ValidationError(
                    "A warehouse with this name already exists in your company."
                )
        return value
    
    def create(self, validated_data):
        # Ensure company is set and auto-generate warehouse_name if missing
        request = self.context.get('request')
        company = request.user if request else None

        if company:
            validated_data['company'] = company

            if not validated_data.get('warehouse_name'):
                # Create a sensible default name based on count
                count = Warehouse.objects.filter(company=company).count() + 1
                validated_data['warehouse_name'] = f"Warehouse {count}"

        return super().create(validated_data)
    
    def update(self, instance, validated_data):
        # Prevent changing company
        validated_data.pop('company', None)
        return super().update(instance, validated_data)

# For bulk operations
class WarehouseBulkSerializer(serializers.Serializer):
    warehouse_ids = serializers.ListField(
        child=serializers.IntegerField(),
        min_length=1
    )
    
    def validate_warehouse_ids(self, value):
        request = self.context.get('request')
        if request:
            company = request.user
            # Check if all warehouses belong to user's company
            valid_ids = set(Warehouse.objects.filter(
                company=company,
                warehouse_id__in=value
            ).values_list('warehouse_id', flat=True))
            
            invalid_ids = set(value) - valid_ids
            if invalid_ids:
                raise serializers.ValidationError(
                    f"Warehouses with IDs {list(invalid_ids)} do not exist or you don't have permission to access them."
                )
        return value

# For creating multiple warehouses at once
class WarehouseBulkCreateSerializer(serializers.Serializer):
    warehouses = WarehouseSerializer(many=True)
    
    def create(self, validated_data):
        request = self.context.get('request')
        company = request.user
        
        warehouses_data = validated_data['warehouses']
        warehouses = []
        
        for warehouse_data in warehouses_data:
            warehouse_name = warehouse_data.get('warehouse_name')
            if not warehouse_name:
                count = Warehouse.objects.filter(company=company).count() + 1
                warehouse_name = f"Warehouse {count}"

            warehouse = Warehouse(
                company=company,
                warehouse_name=warehouse_name,
                address=warehouse_data.get('address', '')
            )
            warehouses.append(warehouse)
        
        Warehouse.objects.bulk_create(warehouses)
        return {'warehouses': warehouses}
    
# Employee Authentication Serializers
from rest_framework import serializers
from rest_framework_simplejwt.tokens import RefreshToken
from django.contrib.auth.hashers import check_password
from django.utils import timezone  # ✅ इसे import करें
from .models import Employee

# serializers.py में EmployeeLoginSerializer

class EmployeeLoginSerializer(serializers.Serializer):
    email = serializers.EmailField(required=True)
    password = serializers.CharField(write_only=True, required=True, style={'input_type': 'password'})
    company_id = serializers.IntegerField(required=True)
    
    def validate(self, data):
        email = data.get('email', '').lower().strip()
        password = data.get('password')
        company_id = data.get('company_id')
        
        print(f"DEBUG: Employee login attempt - Email: {email}, Company ID: {company_id}")
        
        # Debug: List all employees in this company
        all_employees = Employee.objects.filter(company_id=company_id)
        print(f"DEBUG: Total employees in company {company_id}: {all_employees.count()}")
        for emp in all_employees:
            print(f"  - {emp.email} (active={emp.is_active}, status={emp.status})")
        
        try:
            # Find employee - try without strict filters first
            employee = Employee.objects.filter(
                email=email, 
                company_id=company_id
            ).first()
            
            # If employee not found in this company, check if email exists in other companies
            if not employee:
                employee_in_other_company = Employee.objects.filter(email=email).first()
                if employee_in_other_company:
                    print(f"DEBUG: Employee email exists but in different company")
                    raise serializers.ValidationError({
                        'email': 'This email belongs to a different company. Please check your company ID.'
                    })
                else:
                    print(f"DEBUG: Employee not found - Email: {email}, Company ID: {company_id}")
                    raise serializers.ValidationError({
                        'email': 'Employee not found.'
                    })
            
            # Check if active
            if not employee.is_active or employee.status != 'active':
                print(f"DEBUG: Employee inactive - Email: {email}, is_active={employee.is_active}, status={employee.status}")
                raise serializers.ValidationError({
                    'email': 'Employee account is inactive.'
                })
            
            print(f"DEBUG: Employee found: {employee.full_name}, Company: {employee.company.company_name}")
            print(f"DEBUG: Password hash in DB: {employee.password[:50]}...")
            
            # Check password
            if not employee.check_password(password):
                print(f"DEBUG: Password incorrect for employee: {email}")
                raise serializers.ValidationError({
                    'password': 'Invalid password.'
                })
            
            print(f"DEBUG: Password correct!")
            
            # Update last login
            from django.utils import timezone
            employee.last_login = timezone.now()
            employee.save()
            
            # Generate tokens (company का use करें)
            from rest_framework_simplejwt.tokens import RefreshToken
            refresh = RefreshToken.for_user(employee.company)
            refresh['employee_id'] = employee.employee_id
            # refresh['employee_role'] = employee.role
            refresh['employee_email'] = employee.email
            
            # ✅ Employee OBJECT को validated_data में add करें
            data['employee_object'] = employee
            
            # Response data
            data['refresh'] = str(refresh)
            data['access'] = str(refresh.access_token)
            data['employee_data'] = {
                'id': employee.employee_id,
                'code': employee.employee_code,
                'full_name': employee.full_name,
                'email': employee.email,
                # 'role': employee.role,
                # 'department': employee.department,
                # 'designation': employee.designation,
                'temp_password': employee.temp_password
            }
            data['company_data'] = {
                'id': employee.company.company_id,
                'name': employee.company.company_name,
                'email': employee.company.email
            }
            
            return data
            
        except serializers.ValidationError:
            raise
        except Exception as e:
            print(f"DEBUG: Employee login error: {str(e)}")
            import traceback
            traceback.print_exc()
            raise serializers.ValidationError({
                'error': 'Login failed. Please try again.'
            })
class EmployeeChangePasswordSerializer(serializers.Serializer):
    email = serializers.EmailField(required=True)
    company_id = serializers.IntegerField(required=True)
    old_password = serializers.CharField(required=True, write_only=True)
    new_password = serializers.CharField(required=True, min_length=8, write_only=True)
    confirm_password = serializers.CharField(required=True, write_only=True)
    
    def validate(self, data):
        if data['new_password'] != data['confirm_password']:
            raise serializers.ValidationError({
                'confirm_password': "New passwords do not match."
            })
        
        if data['old_password'] == data['new_password']:
            raise serializers.ValidationError({
                'new_password': "New password must be different from old password."
            })
        
        return data

class EmployeeProfileSerializer(serializers.ModelSerializer):
    company_name = serializers.CharField(source='company.company_name', read_only=True)
    company_email = serializers.CharField(source='company.email', read_only=True)
    
    class Meta:
        model = Employee
        fields = [
            'employee_id',
            'employee_code',
            'full_name',
            'email',
            'mobile',
            # 'role',
            # 'department',
            # 'designation',
            'company_name',
            'company_email',
            # 'joining_date',
            'employment_type',
            'status',
            'is_active',
            'address',
            'date_of_birth',
            'profile_picture',
            'temp_password',
            'last_login',
            'created_at'
        ]
        read_only_fields = [
            'employee_id',
            'employee_code', 
            'company_name',
            'company_email',
            'last_login',
            'created_at'
        ]        



# Forgot password serializers
class ForgotPasswordSerializer(serializers.Serializer):
    email = serializers.EmailField(required=True)

class ResetPasswordSerializer(serializers.Serializer):
    token = serializers.UUIDField(required=True)
    new_password = serializers.CharField(required=True, min_length=8)
    confirm_password = serializers.CharField(required=True)
    
    def validate(self, data):
        if data['new_password'] != data['confirm_password']:
            raise serializers.ValidationError("Passwords do not match")
        return data




## create modules



from rest_framework import serializers
from .models import (
    Item, Customer, CustomerContact, 
    Vendor, VendorContact, Employee, Vehicle
)

class ItemSerializer(serializers.ModelSerializer):
    company_name = serializers.CharField(source='company.company_name', read_only=True)
    
    class Meta:
        model = Item
        fields = [
            'id', 'item_code', 'item_name', 'item_description', 
            'item_type', 'hsn_code', 'company', 'company_name',
            'created_by', 'created_at', 'updated_at', 'is_active'
        ]
        read_only_fields = ['item_code', 'company', 'created_by', 'created_at', 'updated_at']
    
    def create(self, validated_data):
        validated_data['company'] = self.context['request'].user
        validated_data['created_by'] = self.context['request'].user
        return super().create(validated_data)



class CustomerContactSerializer(serializers.ModelSerializer):
    class Meta:
        model = CustomerContact
        fields = [
            'id', 'contact_name', 'phone_number', 'email',
            'designation', 'is_primary', 'created_at'
        ]

class CustomerSerializer(serializers.ModelSerializer):
    # CustomerContact से related data
    customer_contacts = CustomerContactSerializer(many=True, read_only=True, source='customer_contact')
    
    # TextField से list बनाने के लिए method fields
    emails_list = serializers.SerializerMethodField()
    contact_persons_list = serializers.SerializerMethodField()
    contact_numbers_list = serializers.SerializerMethodField()
    
    created_by_name = serializers.CharField(source='created_by.username', read_only=True)
    company_name = serializers.CharField(source='company.company_name', read_only=True, allow_null=True)
    
    class Meta:
        model = Customer
        fields = [
            'id', 'company', 'company_name', 'customer_code', 'customer_name', 'gst_number',
            'address', 'po_number', 'credit_days', 'emails', 'emails_list',
            'contact_persons', 'contact_numbers', 'contact_persons_list', 'contact_numbers_list',
            'send_price_email', 'customer_contacts', 'created_by', 'created_by_name',
            'created_at', 'updated_at', 'is_active'
        ]
        read_only_fields = ['customer_code', 'created_by', 'created_at', 'updated_at']
    
    def get_emails_list(self, obj):
        return obj.get_emails_list()
    
    def get_contact_persons_list(self, obj):
        if obj.contact_persons:
            return [person.strip() for person in obj.contact_persons.split(';') if person.strip()]
        return []
    
    def get_contact_numbers_list(self, obj):
        if obj.contact_numbers:
            return [num.strip() for num in obj.contact_numbers.split(';') if num.strip()]
        return []
    
    def create(self, validated_data):
        request = self.context.get('request')
        if request and hasattr(request, 'user'):
            validated_data['created_by'] = request.user
        return Customer.objects.create(**validated_data)
    
    def update(self, instance, validated_data):
        for attr, value in validated_data.items():
            setattr(instance, attr, value)
        instance.save()
        return instance


class VendorContactSerializer(serializers.ModelSerializer):
    class Meta:
        model = VendorContact
        fields = [
            'id', 'contact_name', 'phone_number', 'email',
            'designation', 'is_primary', 'created_at'
        ]

class VendorSerializer(serializers.ModelSerializer):
    # VendorContact से related data - यह optional है
    vendor_contacts = VendorContactSerializer(many=True, read_only=True, source='vendor_contact')
    
    # TextField से list बनाने के लिए method fields
    emails_list = serializers.SerializerMethodField()
    contact_persons_list = serializers.SerializerMethodField()
    contact_numbers_list = serializers.SerializerMethodField()
    
    created_by_name = serializers.CharField(source='created_by.username', read_only=True)
    company_name = serializers.CharField(source='company.company_name', read_only=True, allow_null=True)
    
    class Meta:
        model = Vendor
        fields = [
            'id', 'company', 'company_name', 'vendor_code', 'vendor_name', 'gst_number',
            'address', 'emails', 'emails_list', 'contact_persons', 'contact_numbers',
            'contact_persons_list', 'contact_numbers_list', 'vendor_contacts',
            'account_number', 'bank_name', 'bank_branch', 'ifsc_code',
            'created_by', 'created_by_name', 'created_at', 'updated_at', 'is_active'
        ]
        read_only_fields = ['vendor_code', 'created_by', 'created_at', 'updated_at']
    
    def get_emails_list(self, obj):
        if obj.emails:
            return [email.strip() for email in obj.emails.split(';') if email.strip()]
        return []
    
    def get_contact_persons_list(self, obj):
        if obj.contact_persons:
            return [person.strip() for person in obj.contact_persons.split(';') if person.strip()]
        return []
    
    def get_contact_numbers_list(self, obj):
        if obj.contact_numbers:
            return [num.strip() for num in obj.contact_numbers.split(';') if num.strip()]
        return []
    
    def create(self, validated_data):
        request = self.context.get('request')
        if request and hasattr(request, 'user'):
            validated_data['created_by'] = request.user
        return Vendor.objects.create(**validated_data)
    
    def update(self, instance, validated_data):
        for attr, value in validated_data.items():
            setattr(instance, attr, value)
        instance.save()
        return instance




class VehicleSerializer(serializers.ModelSerializer):
    created_by_name = serializers.CharField(source='created_by.username', read_only=True)
    is_insurance_expired = serializers.BooleanField(read_only=True)
    is_pollution_cert_expired = serializers.BooleanField(read_only=True)
    
    class Meta:
        model = Vehicle
        fields = [
            'id', 'vehicle_code', 'vehicle_name', 'vehicle_number',
            'fc_expiry_date', 'transit_insurance_expiry', 'vehicle_insurance_expiry',
            'road_tax_expiry', 'pollution_cert_expiry', 'tn_permit_expiry',
            'ka_permit_expiry', 'is_insurance_expired', 'is_pollution_cert_expired',
            'created_by', 'created_by_name', 'created_at', 'updated_at',
            'is_active'
        ]
        read_only_fields = ['vehicle_code', 'created_by', 'created_at', 'updated_at']
    
    def create(self, validated_data):
        request = self.context.get('request')
        if request and hasattr(request, 'user'):
            validated_data['created_by'] = request.user
        return super().create(validated_data)


from rest_framework import serializers
from .models import CreateEmployee

# class CreateEmployeeSerializer(serializers.ModelSerializer):
#     designation_display = serializers.CharField(source='get_designation_display', read_only=True)
#     created_by_name = serializers.CharField(source='created_by.username', read_only=True)
#     is_dl_expired = serializers.BooleanField(read_only=True)
#     is_hazardous_license_expired = serializers.BooleanField(read_only=True)
    
#     class Meta:
#         model = CreateEmployee
#         fields = [
#             'id', 'employee_code', 'employee_name', 'designation',
#             'designation_display', 'salary', 'account_number', 'bank_name',
#             'bank_branch', 'ifsc_code', 'transport_amount', 'dl_number',
#             'dl_expiry_date', 'hazardous_cert_number', 'hazardous_license_expiry',
#             'is_dl_expired', 'is_hazardous_license_expired',
#             'created_by', 'created_by_name', 'created_at', 'updated_at',
#             'is_active'
#         ]
#         read_only_fields = ['employee_code', 'created_by', 'created_at', 'updated_at']
    
#     def create(self, validated_data):
#         request = self.context.get('request')
#         if request and hasattr(request, 'user'):
#             validated_data['created_by'] = request.user
#         return super().create(validated_data)
    
#     def validate(self, data):
#         # Clear transport_amount if designation is not driver
#         if data.get('designation') != 'driver' and 'transport_amount' in data:
#             data['transport_amount'] = None
#         return data


# serializers.py
from rest_framework import serializers
from .models import CreateEmployee

class CreateEmployeeSerializer(serializers.ModelSerializer):
    company_name = serializers.CharField(source='company.company_name', read_only=True)
    created_by_name = serializers.CharField(source='created_by.username', read_only=True)
    designation_display = serializers.CharField(source='get_designation_display', read_only=True)
    is_dl_expired = serializers.BooleanField(read_only=True)
    is_hazardous_license_expired = serializers.BooleanField(read_only=True)
    
    class Meta:
        model = CreateEmployee
        fields = [
            'id', 'employee_code', 'employee_name', 'designation',
            'designation_display', 'salary', 'account_number', 'bank_name',
            'bank_branch', 'ifsc_code', 'transport_amount', 'dl_number',
            'dl_expiry_date', 'hazardous_cert_number', 'hazardous_license_expiry',
            'is_dl_expired', 'is_hazardous_license_expired',
            'company', 'company_name', 'created_by', 'created_by_name',
            'created_at', 'updated_at', 'is_active'
        ]
        read_only_fields = [
            'employee_code', 'company', 'company_name', 
            'created_by', 'created_by_name', 'created_at', 
            'updated_at'
        ]
    
    def create(self, validated_data):
        validated_data['company'] = self.context['request'].user
        validated_data['created_by'] = self.context['request'].user
        return super().create(validated_data)
    
    def validate(self, data):
        designation = data.get(
            'designation',
            self.instance.designation if self.instance else None
        )

    # Driver ke alawa sabke liye transport_amount null
        if designation != 'driver':
            data['transport_amount'] = None

    # ❌ No DL / Hazardous validation
        return data       