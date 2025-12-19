from django.db import models

# Create your models here.
from django.db import models
from django.contrib.auth.models import AbstractBaseUser, BaseUserManager, PermissionsMixin
from django.contrib.auth.hashers import make_password, check_password
from django.core.validators import RegexValidator
from django.utils import timezone
import uuid


class CompanyManager(BaseUserManager):
    def create_company(self, email, password=None, **extra_fields):
        if not email:
            raise ValueError('Email address is required')
        
        email = self.normalize_email(email)
        company = self.model(email=email, **extra_fields)
        
        if password:
            company.set_password(password)
        
        company.save(using=self._db)
        return company
    
    def create_superuser(self, email, password=None, **extra_fields):
        extra_fields.setdefault('is_staff', True)
        extra_fields.setdefault('is_superuser', True)
        extra_fields.setdefault('is_verified', True)
        
        return self.create_company(email, password, **extra_fields)

class Company(AbstractBaseUser, PermissionsMixin):
    # Basic Company Information
    company_id = models.AutoField(primary_key=True)
    company_name = models.CharField(max_length=255, verbose_name="Company Name")
    registration_number = models.CharField(max_length=50, unique=True, verbose_name="Registration Number")
    
    # GST Information
    gst_number = models.CharField(
        max_length=15, 
        unique=True, 
        verbose_name="GST Number",
        validators=[
            RegexValidator(
                regex='^[0-9]{2}[A-Z]{5}[0-9]{4}[A-Z]{1}[1-9A-Z]{1}Z[0-9A-Z]{1}$',
                message='Enter a valid GST number'
            )
        ]
    )
    
    # Contact Information
    email = models.EmailField(unique=True, verbose_name="Email Address")
    mobile = models.CharField(
        max_length=10,
        unique=True,
        verbose_name="Mobile Number",
        validators=[
            RegexValidator(
                regex=r'^[6-9]\d{9}$',
                message='Enter a valid 10-digit mobile number'
            )
        ]
    )
    alternate_mobile = models.CharField(max_length=10, blank=True, null=True)
    
    # Address
    address_line1 = models.CharField(max_length=255, verbose_name="Address Line 1")
    address_line2 = models.CharField(max_length=255, blank=True, null=True, verbose_name="Address Line 2")
    city = models.CharField(max_length=100, verbose_name="City")
    state = models.CharField(max_length=100, verbose_name="State")
    pincode = models.CharField(max_length=6, verbose_name="Pincode")
    country = models.CharField(max_length=100, default="India", verbose_name="Country")
    
    # Business Information
    BUSINESS_TYPES = [
        ('essential', 'Essential'),
        ('non_essential', 'Non-Essential'),
        ('services', 'Services'),
        ('manufacturing', 'Manufacturing'),
        ('retail', 'Retail'),
        ('wholesale', 'Wholesale'),
        ('other', 'Other'),
    ]
    
    business_type = models.CharField(
        max_length=50, 
        choices=BUSINESS_TYPES, 
        verbose_name="Business Type"
    )
    business_subtype = models.CharField(max_length=100, verbose_name="Business Subtype")
    
    # Company Details
    website = models.URLField(blank=True, null=True, verbose_name="Website")
    industry = models.CharField(max_length=100, blank=True, null=True, verbose_name="Industry")
    company_size = models.CharField(max_length=50, blank=True, null=True, verbose_name="Company Size")
    established_year = models.PositiveIntegerField(blank=True, null=True, verbose_name="Established Year")
    
    # Verification
    is_verified = models.BooleanField(default=False, verbose_name="Verified")
    verification_token = models.UUIDField(default=uuid.uuid4, editable=False, unique=True)
    otp = models.CharField(max_length=6, blank=True, null=True)
    otp_expiry = models.DateTimeField(blank=True, null=True)
    
    # Company Logo
    logo = models.ImageField(
        upload_to='company_logos/',
        blank=True,
        null=True,
        verbose_name="Company Logo"
    )
    
    # Status
    is_active = models.BooleanField(default=True, verbose_name="Active")
    is_staff = models.BooleanField(default=False, verbose_name="Staff Status")
    
    # Timestamps
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    
    # Login fields
    last_login = models.DateTimeField(blank=True, null=True)
    
    USERNAME_FIELD = 'email'
    REQUIRED_FIELDS = ['company_name', 'mobile', 'gst_number']
    
    objects = CompanyManager()
    
    class Meta:
        verbose_name = "Company"
        verbose_name_plural = "Companies"
        db_table = 'companies'
        indexes = [
            models.Index(fields=['email']),
            models.Index(fields=['mobile']),
            models.Index(fields=['gst_number']),
            models.Index(fields=['is_verified']),
            models.Index(fields=['created_at']),
        ]
    
    def __str__(self):
        return f"{self.company_name} ({self.company_id})"
    
    @property
    def full_address(self):
        address_parts = [self.address_line1]
        if self.address_line2:
            address_parts.append(self.address_line2)
        address_parts.extend([self.city, self.state, self.pincode, self.country])
        return ', '.join(filter(None, address_parts))
    
    


class Employee(models.Model):
    # ROLE_CHOICES = [
    #     ('admin', 'Administrator'),
    #     ('manager', 'Manager'),
    #     ('supervisor', 'Supervisor'),
    #     ('staff', 'Staff'),
    #     ('viewer', 'Viewer'),
    #     ('accountant', 'Accountant'),
    #     ('hr', 'HR Manager'),
    # ]
    
    STATUS_CHOICES = [
        ('active', 'Active'),
        ('inactive', 'Inactive'),
        ('suspended', 'Suspended'),
        ('on_leave', 'On Leave'),
    ]
    
    # Basic Information
    employee_id = models.AutoField(primary_key=True)
    company = models.ForeignKey(
        Company, 
        on_delete=models.CASCADE, 
        related_name='employees',
        verbose_name="Company"
    )
    employee_code = models.CharField(
        max_length=50, 
        unique=True, 
        verbose_name="Employee Code"
    )
    
    # Personal Details
    full_name = models.CharField(max_length=255, verbose_name="Full Name")
    email = models.EmailField(verbose_name="Email Address")
    mobile = models.CharField(
        max_length=10,
        verbose_name="Mobile Number",
        validators=[
            RegexValidator(
                regex=r'^[6-9]\d{9}$',
                message='Enter a valid 10-digit mobile number'
            )
        ]
    )
    
    # Job Details
    # role = models.CharField(
    #     max_length=50, 
    #     choices=ROLE_CHOICES, 
    #     verbose_name="Role",
    #     default='staff'
    # )
    # department = models.CharField(max_length=100, blank=True, null=True, verbose_name="Department")
    # designation = models.CharField(max_length=100, blank=True, null=True, verbose_name="Designation")
    # joining_date = models.DateField(verbose_name="Joining Date")
    
    # Employment Details
    # salary = models.DecimalField(
    #     max_digits=10, 
    #     decimal_places=2, 
    #     blank=True, 
    #     null=True, 
    #     verbose_name="Salary"
    # )
    employment_type = models.CharField(
        max_length=50,
        choices=[
            ('full_time', 'Full Time'),
            ('part_time', 'Part Time'),
            ('contract', 'Contract'),
            ('intern', 'Intern'),
        ],
        default='full_time',
        verbose_name="Employment Type"
    )
    
    # Authentication
    

    password = models.CharField(max_length=255, verbose_name="Password")
    temp_password = models.BooleanField(default=True, verbose_name="Temporary Password")
    last_password_change = models.DateTimeField(auto_now_add=True, verbose_name="Last Password Change")
    

    
    
    
    
    # Status
    status = models.CharField(
        max_length=20, 
        choices=STATUS_CHOICES, 
        default='active',
        verbose_name="Status"
    )
    is_active = models.BooleanField(default=True, verbose_name="Active")
    
    # Additional Information
    address = models.TextField(blank=True, null=True, verbose_name="Address")
    date_of_birth = models.DateField(blank=True, null=True, verbose_name="Date of Birth")
    profile_picture = models.ImageField(
        upload_to='employee_profiles/',
        blank=True,
        null=True,
        verbose_name="Profile Picture"
    )
    
    # Timestamps
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    last_login = models.DateTimeField(blank=True, null=True, verbose_name="Last Login")
    
    class Meta:
        verbose_name = "Employee"
        verbose_name_plural = "Employees"
        db_table = 'employees'
        unique_together = ['company', 'email']
        indexes = [
            models.Index(fields=['employee_code']),
            models.Index(fields=['email']),
            models.Index(fields=['company', 'status']),
            # models.Index(fields=['company', 'role']),
            # models.Index(fields=['joining_date']),
        ]
    
   
   
    
    def __str__(self):
        return f"{self.full_name} - {self.employee_code}"
    
    def generate_employee_code(self):
        """Generate unique employee code"""
        if self.employee_code:
            return
        
        company_prefix = self.company.company_name[:3].upper()
        last_employee = Employee.objects.filter(
            company=self.company
        ).order_by('employee_id').last()
        
        if last_employee:
            last_number = int(last_employee.employee_code[3:])
            new_number = last_number + 1
        else:
            new_number = 1
        
        self.employee_code = f"{company_prefix}{new_number:03d}"
    
    def hash_password_if_needed(self):
        """Hash password if it's plain text"""
        if self.password and not self.password.startswith('pbkdf2_sha256$'):
            self.password = make_password(self.password)
            self.temp_password = False
            self.last_password_change = timezone.now()
    
    def save(self, *args, **kwargs):
        # Generate employee code
        self.generate_employee_code()
        
        # Hash password if needed
        self.hash_password_if_needed()
        
        # Call parent save
        super().save(*args, **kwargs)
    
    def set_password(self, raw_password):
        """Set new password (explicitly)"""
        self.password = make_password(raw_password)
        self.temp_password = False
        self.last_password_change = timezone.now()
        self.save()
    
    def check_password(self, raw_password):
        """Check if password matches"""
        return check_password(raw_password, self.password)

class CompanySettings(models.Model):
    company = models.OneToOneField(
        Company,
        on_delete=models.CASCADE,
        related_name='settings',
        verbose_name="Company"
    )
    
    # General Settings
    timezone = models.CharField(max_length=50, default='Asia/Kolkata', verbose_name="Timezone")
    date_format = models.CharField(
        max_length=20,
        default='DD/MM/YYYY',
        choices=[
            ('DD/MM/YYYY', 'DD/MM/YYYY'),
            ('MM/DD/YYYY', 'MM/DD/YYYY'),
            ('YYYY-MM-DD', 'YYYY-MM-DD'),
        ],
        verbose_name="Date Format"
    )
    
    # Security Settings
    password_expiry_days = models.PositiveIntegerField(default=90, verbose_name="Password Expiry (Days)")
    max_login_attempts = models.PositiveIntegerField(default=5, verbose_name="Max Login Attempts")
    session_timeout = models.PositiveIntegerField(default=30, verbose_name="Session Timeout (Minutes)")
    
    # Notification Settings
    email_notifications = models.BooleanField(default=True, verbose_name="Email Notifications")
    sms_notifications = models.BooleanField(default=True, verbose_name="SMS Notifications")
    push_notifications = models.BooleanField(default=True, verbose_name="Push Notifications")
    
    # Employee Settings
    auto_generate_password = models.BooleanField(default=True, verbose_name="Auto Generate Passwords")
    require_employee_activation = models.BooleanField(default=True, verbose_name="Require Employee Activation")
    
    # Timestamps
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    
    class Meta:
        verbose_name = "Company Settings"
        verbose_name_plural = "Company Settings"
        db_table = 'company_settings'
    
    def __str__(self):
        return f"Settings for {self.company.company_name}"

class EmployeeLoginHistory(models.Model):
    employee = models.ForeignKey(
        Employee,
        on_delete=models.CASCADE,
        related_name='login_history',
        verbose_name="Employee"
    )
    login_time = models.DateTimeField(auto_now_add=True, verbose_name="Login Time")
    ip_address = models.GenericIPAddressField(verbose_name="IP Address")
    user_agent = models.TextField(verbose_name="User Agent")
    location = models.CharField(max_length=255, blank=True, null=True, verbose_name="Location")
    success = models.BooleanField(default=True, verbose_name="Login Successful")
    
    class Meta:
        verbose_name = "Employee Login History"
        verbose_name_plural = "Employee Login Histories"
        db_table = 'employee_login_history'
        indexes = [
            models.Index(fields=['employee', 'login_time']),
            models.Index(fields=['login_time']),
        ]
    
    def __str__(self):
        status = "Success" if self.success else "Failed"
        return f"{self.employee} - {self.login_time} ({status})"
    

#warehouse models 


#warehouse models 


class Warehouse(models.Model):
    warehouse_id = models.AutoField(primary_key=True)

    company = models.ForeignKey(
        Company,
        on_delete=models.CASCADE,
        related_name="warehouses"
    )

    warehouse_name = models.CharField(max_length=255)
    address = models.TextField()

    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        db_table = "warehouses"

    def __str__(self):
        return self.warehouse_name

# models.py में EmployeeLoginHistory class के बाद ADD करें

class PasswordResetToken(models.Model):
    company = models.ForeignKey(
        Company,
        on_delete=models.CASCADE,
        related_name='password_reset_tokens',
        verbose_name="Company",
        null=True,
        blank=True
    )
    token = models.UUIDField(default=uuid.uuid4, editable=False, unique=True)
    email = models.EmailField(verbose_name="Email Address")
    
    # ✅ User type field add करें
    user_type = models.CharField(
        max_length=20,
        choices=[('company', 'Company'), ('employee', 'Employee')],
        default='company',
        verbose_name="User Type"
    )
    
    created_at = models.DateTimeField(auto_now_add=True)
    expires_at = models.DateTimeField(default=timezone.now)
    used = models.BooleanField(default=False)
    
    class Meta:
        verbose_name = "Password Reset Token"
        verbose_name_plural = "Password Reset Tokens"
        db_table = 'password_reset_tokens'
        indexes = [
            models.Index(fields=['token']),
            models.Index(fields=['email']),
            models.Index(fields=['user_type']),
            models.Index(fields=['expires_at']),
        ]
    
    def __str__(self):
        return f"Reset token for {self.email} ({self.user_type})"
    
    def is_valid(self):
        from django.utils import timezone
        return not self.used and self.expires_at > timezone.now()
    


## create modules



from django.db import models
from django.contrib.auth import get_user_model
from .models import Company

User = get_user_model()
from django.core.validators import MinValueValidator, MaxValueValidator

class Item(models.Model):
    company = models.ForeignKey(Company, on_delete=models.CASCADE, related_name='items', null=True, blank=True)
    ITEM_TYPES = [
        ('fuel', 'Fuel'),
        ('pipeline', 'Pipeline'),
        ('others', 'Others'),
    ]
    
    item_code = models.CharField(max_length=50, unique=True)
    item_name = models.CharField(max_length=200, unique=True)
    item_description = models.TextField(blank=True, null=True)
    item_type = models.CharField(max_length=20, choices=ITEM_TYPES, default='others')
    hsn_code = models.CharField(max_length=50, blank=True, null=True)
    created_by = models.ForeignKey(User, on_delete=models.SET_NULL, null=True, related_name='items_created')
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    is_active = models.BooleanField(default=True)
    
    class Meta:
        ordering = ['-created_at']
        verbose_name = 'Item'
        verbose_name_plural = 'Items'
    
    def __str__(self):
        return f"{self.item_code} - {self.item_name}"
    
    def save(self, *args, **kwargs):
        if not self.item_code:
            prefix = "ITEM"
            company_part = str(self.company.company_id) if self.company else "0"

            if self.company:
                last_item = Item.objects.filter(company=self.company).order_by('-id').first()
            else:
                last_item = Item.objects.order_by('-id').first()

            new_num = 1
            if last_item and last_item.item_code:
                parts = last_item.item_code.split('-')
                try:
                    last_num = int(parts[-1])
                    new_num = last_num + 1
                except Exception:
                    new_num = 1

            self.item_code = f"{prefix}-{company_part}-{new_num:05d}"

        super().save(*args, **kwargs)

    


class Customer(models.Model):
    company = models.ForeignKey(Company, on_delete=models.CASCADE, related_name='customers', null=True, blank=True)
    customer_code = models.CharField(max_length=50, unique=True)
    customer_name = models.CharField(max_length=200,unique=True )
    
    gst_number = models.CharField(max_length=15, blank=True, null=True)
    address = models.TextField(blank=True, null=True)
    po_number = models.CharField(max_length=100, blank=True, null=True)
    credit_days = models.IntegerField(default=30, validators=[MinValueValidator(0), MaxValueValidator(365)])
    emails = models.TextField(blank=True, null=True, help_text="Separate multiple emails with ;")
    contact_persons = models.TextField(blank=True, null=True, help_text="Separate multiple person with ;")
    contact_numbers = models.TextField(blank=True, null=True, help_text="Separate multiple numbers with ;")
    send_price_email = models.BooleanField(default=False)
    created_by = models.ForeignKey(User, on_delete=models.SET_NULL, null=True, related_name='customers_created')
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    is_active = models.BooleanField(default=True)


    
    
    class Meta:
        ordering = ['-created_at']
        verbose_name = 'Customer'
        verbose_name_plural = 'Customers'
    
    def __str__(self):
        return f"{self.customer_code} - {self.customer_name}"
    
    def save(self, *args, **kwargs):
        if not self.customer_code:
            prefix = "CUST"
            company_part = str(self.company.company_id) if self.company else "0"

            if self.company:
                last_customer = Customer.objects.filter(company=self.company).order_by('-id').first()
            else:
                last_customer = Customer.objects.order_by('-id').first()

            new_num = 1
            if last_customer and last_customer.customer_code:
                parts = last_customer.customer_code.split('-')
                try:
                    last_num = int(parts[-1])
                    new_num = last_num + 1
                except Exception:
                    new_num = 1

            self.customer_code = f"{prefix}-{company_part}-{new_num:05d}"

        super().save(*args, **kwargs)
    
    def get_emails_list(self):
        if self.emails:
            return [email.strip() for email in self.emails.split(';') if email.strip()]
        return []


class CustomerContact(models.Model):
    
    customer = models.ForeignKey(Customer, on_delete=models.CASCADE, related_name='customer_contact')
    contact_name = models.CharField(max_length=100)
    phone_number = models.CharField(max_length=15)
    email = models.EmailField(blank=True, null=True)
    designation = models.CharField(max_length=100, blank=True, null=True)
    is_primary = models.BooleanField(default=False)
    created_at = models.DateTimeField(auto_now_add=True)
    
    class Meta:
        ordering = ['-is_primary', 'contact_name']
        verbose_name = 'Customer Contact'
        verbose_name_plural = 'Customer Contacts'
    
    def __str__(self):
        return f"{self.contact_name} - {self.customer.customer_name}"

    # def save(self, *args, **kwargs):
    #     if not self.customer_code:
    #         prefix = "CUST"
    #         if self.company:
    #             company_prefix = self.company.company_name[:3].upper()
    #             last_customer = Customer.objects.filter(company=self.company).order_by('-id').first()
    #         else:
    #             last_customer = Customer.objects.order_by('-id').first()    


class Vendor(models.Model):
    company = models.ForeignKey(Company, on_delete=models.CASCADE, related_name='vendors', null=True, blank=True)
    vendor_code = models.CharField(max_length=50, unique=True)
    
    vendor_name = models.CharField(max_length=200, unique=True)
    gst_number = models.CharField(max_length=15, blank=True, null=True)
    address = models.TextField(blank=True, null=True)
    emails = models.TextField(blank=True, null=True, help_text="Separate multiple emails with ;")

    contact_persons=models.TextField(blank=True, null=True, help_text="Separate multiple person with ;")
    contact_numbers=models.TextField(blank=True, null=True, help_text="Separate multiple numbers with ;")
    account_number = models.CharField(max_length=50, blank=True, null=True)
    bank_name = models.CharField(max_length=100, blank=True, null=True)
    bank_branch = models.CharField(max_length=100, blank=True, null=True)
    ifsc_code = models.CharField(max_length=20, blank=True, null=True)
    created_by = models.ForeignKey(User, on_delete=models.SET_NULL, null=True, related_name='vendors_created')
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    is_active = models.BooleanField(default=True)
    
    class Meta:
        ordering = ['-created_at']
        verbose_name = 'Vendor'
        verbose_name_plural = 'Vendors'
    
    def __str__(self):
        return f"{self.vendor_code} - {self.vendor_name}"
    
    def save(self, *args, **kwargs):
        if not self.vendor_code:
            prefix = "VEND"
            company_part = str(self.company.company_id) if self.company else "0"

            if self.company:
                last_vendor = Vendor.objects.filter(company=self.company).order_by('-id').first()
            else:
                last_vendor = Vendor.objects.order_by('-id').first()

            new_num = 1
            if last_vendor and last_vendor.vendor_code:
                parts = last_vendor.vendor_code.split('-')
                try:
                    last_num = int(parts[-1])
                    new_num = last_num + 1
                except Exception:
                    new_num = 1

            self.vendor_code = f"{prefix}-{company_part}-{new_num:05d}"

        super().save(*args, **kwargs)


class VendorContact(models.Model):
    vendor = models.ForeignKey(Vendor, on_delete=models.CASCADE, related_name='vendor_contact')
    contact_name = models.CharField(max_length=100)
    phone_number = models.CharField(max_length=15)
    email = models.EmailField(blank=True, null=True)
    designation = models.CharField(max_length=100, blank=True, null=True)
    is_primary = models.BooleanField(default=False)
    created_at = models.DateTimeField(auto_now_add=True)
    
    class Meta:
        ordering = ['-is_primary', 'contact_name']
        verbose_name = 'Vendor Contact'
        verbose_name_plural = 'Vendor Contacts'
    
    def __str__(self):
        return f"{self.contact_name} - {self.vendor.vendor_name}"




class Vehicle(models.Model):
    company = models.ForeignKey(Company, on_delete=models.CASCADE, related_name='vehicles', null=True, blank=True)
    vehicle_code = models.CharField(max_length=50, unique=True)
   
    vehicle_name = models.CharField(max_length=200)
    vehicle_number = models.CharField(max_length=50, unique=True)
    fc_expiry_date = models.DateField(blank=True, null=True)
    transit_insurance_expiry = models.DateField(blank=True, null=True)
    vehicle_insurance_expiry = models.DateField(blank=True, null=True)
    # road_tax_expiry = models.DateField(blank=True, null=True)
    road_tax = models.JSONField(
    default=list,
    blank=True,
    help_text="State-wise road tax expiry dates in format: [{'state': 'MH', 'expiry_date': '2024-12-31'}, ...]"
)
    state_permits = models.JSONField(
        default=list,
        blank=True,
        help_text="State-wise permits in format: [{'state': 'MH', 'expiry_date': '2024-12-31'}, ...]"
    )
    pollution_cert_expiry = models.DateField(blank=True, null=True)
    tn_permit_expiry = models.DateField(blank=True, null=True)
    ka_permit_expiry = models.DateField(blank=True, null=True)
    # National permit
    has_national_permit = models.BooleanField(default=False)
    national_permit_expiry = models.DateField(blank=True, null=True)

    # Notification / reminder settings (emails and SMS)
    notification_emails = models.TextField(
        blank=True,
        null=True,
        help_text="Separate multiple emails with ;"
    )
    notification_phone_numbers = models.TextField(
        blank=True,
        null=True,
        help_text="Separate multiple numbers with ;"
    )
    enable_7day_reminder = models.BooleanField(default=True)
    enable_3day_reminder = models.BooleanField(default=True)
    enable_expiry_day_reminder = models.BooleanField(default=True)

    created_by = models.ForeignKey(User, on_delete=models.SET_NULL, null=True, related_name='vehicles_created')
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    is_active = models.BooleanField(default=True)
    
    class Meta:
        ordering = ['-created_at']
        verbose_name = 'Vehicle'
        verbose_name_plural = 'Vehicles'
    
    def __str__(self):
        return f"{self.vehicle_code} - {self.vehicle_name} ({self.vehicle_number})"
    
    @property
    def is_insurance_expired(self):
        """
        Helper property for serializers:
        True when vehicle_insurance_expiry is in the past.
        """
        from django.utils import timezone
        if self.vehicle_insurance_expiry:
            return self.vehicle_insurance_expiry < timezone.now().date()
        return False

    @property
    def is_pollution_cert_expired(self):
        """
        Helper property for serializers:
        True when pollution_cert_expiry is in the past.
        """
        from django.utils import timezone
        if self.pollution_cert_expiry:
            return self.pollution_cert_expiry < timezone.now().date()
        return False

    def save(self, *args, **kwargs):
        if not self.vehicle_code:
            prefix = "VEH"
            company_part = str(self.company.company_id) if self.company else "0"

            if self.company:
                last_vehicle = Vehicle.objects.filter(company=self.company).order_by('-id').first()
            else:
                last_vehicle = Vehicle.objects.order_by('-id').first()

            new_num = 1
            if last_vehicle and last_vehicle.vehicle_code:
                parts = last_vehicle.vehicle_code.split('-')
                try:
                    last_num = int(parts[-1])
                    new_num = last_num + 1
                except Exception:
                    new_num = 1

            self.vehicle_code = f"{prefix}-{company_part}-{new_num:05d}"

        super().save(*args, **kwargs)


from django.db import models
from django.contrib.auth import get_user_model
from django.core.validators import MinValueValidator
from decimal import Decimal

User = get_user_model()

class CreateEmployee(models.Model):
    company = models.ForeignKey(
        Company,
        on_delete=models.CASCADE,
        related_name='created_employees'   # ✅ UNIQUE
    )


    DESIGNATION_CHOICES = [
        ('manager', 'Manager'),
        ('transporter', 'Transporter'),
        ('asst_manager', 'Assistant Manager'),
        ('driver', 'Driver'),
        ('md', 'MD'),
        ('other', 'Other'),
    ]

    employee_code = models.CharField(max_length=50)
    employee_name = models.CharField(max_length=200)
    designation = models.CharField(
        max_length=20,
        choices=DESIGNATION_CHOICES,
        default='manager'
    )

    salary = models.DecimalField(max_digits=12, decimal_places=2, null=True, blank=True)
    account_number = models.CharField(max_length=50, blank=True, null=True)
    bank_name = models.CharField(max_length=100, blank=True, null=True)
    bank_branch = models.CharField(max_length=100, blank=True, null=True)
    ifsc_code = models.CharField(max_length=20, blank=True, null=True)

    transport_amount = models.DecimalField(
        max_digits=10,
        decimal_places=2,
        null=True,
        blank=True,
        validators=[MinValueValidator(Decimal('0.00'))]
    )

    dl_number = models.CharField(max_length=50, blank=True, null=True)
    dl_expiry_date = models.DateField(null=True, blank=True)
    hazardous_cert_number = models.CharField(max_length=100, blank=True, null=True)
    hazardous_license_expiry = models.DateField(null=True, blank=True)

    created_by = models.ForeignKey(
        User,
        on_delete=models.SET_NULL,
        null=True,
        related_name='employees_created'
    )

    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    is_active = models.BooleanField(default=True)

    class Meta:
        ordering = ['-created_at']
        verbose_name = 'Employee'
        verbose_name_plural = 'Employees'
        constraints = [
            models.UniqueConstraint(
                fields=['company', 'employee_code'],
                name='unique_employee_code_per_company'
            )
        ]

    def __str__(self):
        return f"{self.employee_code} - {self.employee_name}"

    def save(self, *args, **kwargs):
        if not self.company:
            raise ValueError("Company is required")

        if not self.employee_code:
            prefix = "EMP"
            company_emps = CreateEmployee.objects.filter(company=self.company)

            max_num = 0
            for emp in company_emps:
                if emp.employee_code and emp.employee_code.startswith(prefix):
                    try:
                        num = int(emp.employee_code.split('-')[-1])
                        max_num = max(max_num, num)
                    except:
                        pass

            self.employee_code = f"{prefix}-{max_num + 1:05d}"

        if self.designation != 'driver':
            self.transport_amount = None

        super().save(*args, **kwargs)
