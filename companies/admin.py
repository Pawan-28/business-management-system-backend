from django.contrib import admin
from django.contrib.auth.admin import UserAdmin
from django.utils.html import format_html
from .models import (
    Company, Employee, CompanySettings, EmployeeLoginHistory,
    Item, Customer, CustomerContact, Vendor, VendorContact, 
    Vehicle, CreateEmployee
)

# ---------- Company Models ----------
class CompanyAdmin(UserAdmin):
    list_display = ('company_id', 'company_name', 'email', 'mobile', 'is_verified', 'is_active', 'created_at')
    list_filter = ('is_verified', 'is_active', 'business_type', 'created_at')
    search_fields = ('company_name', 'email', 'mobile', 'gst_number')
    ordering = ('-created_at',)
    
    fieldsets = (
        ('Company Information', {
            'fields': ('company_name', 'registration_number', 'gst_number')
        }),
        ('Contact Information', {
            'fields': ('email', 'mobile', 'alternate_mobile', 'website')
        }),
        ('Address Information', {
            'fields': ('address_line1', 'address_line2', 'city', 'state', 'pincode', 'country')
        }),
        ('Business Information', {
            'fields': ('business_type', 'business_subtype', 'industry', 'company_size', 'established_year')
        }),
        ('Verification & Status', {
            'fields': ('is_verified', 'verification_token', 'otp', 'otp_expiry', 'is_active')
        }),
        ('Permissions', {
            'fields': ('is_staff', 'is_superuser', 'groups', 'user_permissions')
        }),
        ('Important Dates', {
            'fields': ('last_login', 'created_at', 'updated_at')
        }),
    )
    
    add_fieldsets = (
        (None, {
            'classes': ('wide',),
            'fields': ('company_name', 'email', 'mobile', 'gst_number', 'password1', 'password2'),
        }),
    )
    
    readonly_fields = ('created_at', 'updated_at', 'verification_token')

class EmployeeAdmin(admin.ModelAdmin):
    list_display = ('employee_code', 'full_name', 'company', 'status', 'is_active')
    list_filter = ('status', 'is_active', 'company')
    search_fields = ('full_name', 'email', 'mobile', 'employee_code')
    list_select_related = ('company',)
    
    fieldsets = (
        ('Personal Information', {
            'fields': ('full_name', 'email', 'mobile', 'date_of_birth', 'profile_picture', 'address')
        }),
        ('Employment Details', {
            'fields': ('company', 'employee_code', 'employment_type')
        }),
        ('Authentication', {
            'fields': ('password', 'temp_password', 'last_password_change', 'last_login')
        }),
        ('Status', {
            'fields': ('status', 'is_active')
        }),
    )
    
    readonly_fields = ('employee_code', 'last_password_change', 'last_login')
    
    def get_queryset(self, request):
        qs = super().get_queryset(request)
        if request.user.is_superuser:
            return qs
        # Non-superusers see only their company's employees
        if hasattr(request.user, 'company'):
            return qs.filter(company=request.user.company)
        return qs

class CompanySettingsAdmin(admin.ModelAdmin):
    list_display = ('company', 'timezone', 'date_format', 'email_notifications')
    list_select_related = ('company',)

class EmployeeLoginHistoryAdmin(admin.ModelAdmin):
    list_display = ('employee', 'login_time', 'ip_address', 'success', 'location')
    list_filter = ('success', 'login_time')
    search_fields = ('employee__full_name', 'employee__email', 'ip_address')
    readonly_fields = ('login_time',)
    
    def has_add_permission(self, request):
        return False

# ---------- Company Filter ----------
class CompanyFilter(admin.SimpleListFilter):
    title = 'company'
    parameter_name = 'company'
    
    def lookups(self, request, model_admin):
        companies = Company.objects.all()
        return [(c.company_id, c.company_name) for c in companies]
    
    def queryset(self, request, queryset):
        if self.value():
            return queryset.filter(company_id=self.value())
        return queryset

# ---------- Item Models ----------
@admin.register(Item)
class ItemAdmin(admin.ModelAdmin):
    list_display = ('item_code', 'item_name', 'item_type', 'company', 'is_active')
    list_filter = (CompanyFilter, 'item_type', 'is_active', 'created_at')
    search_fields = ('item_code', 'item_name', 'hsn_code')
    readonly_fields = ('item_code', 'created_by', 'created_at', 'updated_at')
    
    def get_queryset(self, request):
        qs = super().get_queryset(request)
        if request.user.is_superuser:
            return qs
        # Non-superusers see only their company's items
        if hasattr(request.user, 'company'):
            return qs.filter(company=request.user.company)
        return qs

# ---------- Customer Models ----------
class CustomerContactInline(admin.TabularInline):
    model = CustomerContact
    extra = 1
    
    def get_queryset(self, request):
        qs = super().get_queryset(request)
        if request.user.is_superuser:
            return qs
        # Filter contacts by customer's company
        if hasattr(request.user, 'company'):
            return qs.filter(customer__company=request.user.company)
        return qs

@admin.register(Customer)
class CustomerAdmin(admin.ModelAdmin):
    list_display = ['customer_code', 'customer_name', 'gst_number', 'company', 'credit_days', 'created_at']
    list_filter = (CompanyFilter, 'send_price_email', 'is_active', 'created_at')
    search_fields = ['customer_code', 'customer_name', 'gst_number', 'po_number']
    readonly_fields = ['customer_code', 'created_by', 'created_at', 'updated_at']
    inlines = [CustomerContactInline]
    
    def get_queryset(self, request):
        qs = super().get_queryset(request)
        if request.user.is_superuser:
            return qs
        if hasattr(request.user, 'company'):
            return qs.filter(company=request.user.company)
        return qs

# ---------- Vendor Models ----------
class VendorContactInline(admin.TabularInline):
    model = VendorContact
    extra = 1
    
    def get_queryset(self, request):
        qs = super().get_queryset(request)
        if request.user.is_superuser:
            return qs
        if hasattr(request.user, 'company'):
            return qs.filter(vendor__company=request.user.company)
        return qs

@admin.register(Vendor)
class VendorAdmin(admin.ModelAdmin):
    list_display = ['vendor_code', 'vendor_name', 'gst_number', 'company', 'bank_name', 'created_at']
    list_filter = (CompanyFilter, 'is_active', 'created_at')
    search_fields = ['vendor_code', 'vendor_name', 'gst_number', 'ifsc_code']
    readonly_fields = ['vendor_code', 'created_by', 'created_at', 'updated_at']
    inlines = [VendorContactInline]
    
    def get_queryset(self, request):
        qs = super().get_queryset(request)
        if request.user.is_superuser:
            return qs
        if hasattr(request.user, 'company'):
            return qs.filter(company=request.user.company)
        return qs

# ---------- Vehicle Model ----------
@admin.register(Vehicle)
class VehicleAdmin(admin.ModelAdmin):
    list_display = ['vehicle_code', 'vehicle_name', 'vehicle_number', 'company', 'vehicle_insurance_expiry', 'is_active']
    list_filter = (CompanyFilter, 'is_active', 'created_at')
    search_fields = ['vehicle_code', 'vehicle_name', 'vehicle_number']
    readonly_fields = ['vehicle_code', 'created_by', 'created_at', 'updated_at']
    
    def get_queryset(self, request):
        qs = super().get_queryset(request)
        if request.user.is_superuser:
            return qs
        if hasattr(request.user, 'company'):
            return qs.filter(company=request.user.company)
        return qs

# ---------- CreateEmployee Model ----------
@admin.register(CreateEmployee)
class CreateEmployeeAdmin(admin.ModelAdmin):
    list_display = ('employee_code', 'employee_name', 'designation', 'company', 'salary', 'is_active')
    list_filter = (CompanyFilter, 'designation', 'is_active', 'created_at')
    search_fields = ('employee_code', 'employee_name', 'dl_number')
    readonly_fields = ('created_at', 'updated_at')
    
    fieldsets = (
        ('Basic Information', {
            'fields': ('employee_code', 'employee_name', 'designation', 'salary', 'company')
        }),
        ('Bank Details', {
            'fields': ('account_number', 'bank_name', 'bank_branch', 'ifsc_code'),
            'classes': ('collapse',)
        }),
        ('Driver Specific', {
            'fields': ('transport_amount', 'dl_number', 'dl_expiry_date'),
            'classes': ('collapse',)
        }),
        ('Hazardous Details', {
            'fields': ('hazardous_cert_number', 'hazardous_license_expiry'),
            'classes': ('collapse',)
        }),
        ('Audit Information', {
            'fields': ('created_by', 'created_at', 'updated_at', 'is_active'),
            'classes': ('collapse',)
        }),
    )
    
    def get_queryset(self, request):
        qs = super().get_queryset(request)
        if request.user.is_superuser:
            return qs
        if hasattr(request.user, 'company'):
            return qs.filter(company=request.user.company)
        return qs

# ---------- Register All Models ----------
# ❌ इन्हें हटाएं - @admin.register पहले ही कर चुके हैं
# admin.site.register(Company, CompanyAdmin)
# admin.site.register(Employee, EmployeeAdmin)
# admin.site.register(CompanySettings, CompanySettingsAdmin)
# admin.site.register(EmployeeLoginHistory, EmployeeLoginHistoryAdmin)

# सिर्फ वो models register करें जिनपर @admin.register नहीं लगा है
admin.site.register(Company, CompanyAdmin)
admin.site.register(Employee, EmployeeAdmin)
admin.site.register(CompanySettings, CompanySettingsAdmin)
admin.site.register(EmployeeLoginHistory, EmployeeLoginHistoryAdmin)