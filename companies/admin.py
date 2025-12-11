from django.contrib import admin

# Register your models here.
from django.contrib import admin
from django.contrib.auth.admin import UserAdmin
from .models import Company, Employee, CompanySettings, EmployeeLoginHistory
from django.utils.html import format_html

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
    
    def get_form(self, request, obj=None, **kwargs):
        form = super().get_form(request, obj, **kwargs)
        if 'password' in form.base_fields:
            form.base_fields['password'].help_text = "Raw passwords are not stored."
        return form

class EmployeeAdmin(admin.ModelAdmin):
    list_display = ('employee_code', 'full_name', 'company', 'role', 'status', 'is_active', 'joining_date')
    list_filter = ('status', 'role', 'is_active', 'department', 'joining_date')
    search_fields = ('full_name', 'email', 'mobile', 'employee_code')
    list_select_related = ('company',)
    
    fieldsets = (
        ('Personal Information', {
            'fields': ('full_name', 'email', 'mobile', 'date_of_birth', 'profile_picture', 'address')
        }),
        ('Employment Details', {
            'fields': ('company', 'employee_code', 'role', 'department', 'designation', 'joining_date')
        }),
        ('Employment Terms', {
            'fields': ('salary', 'employment_type')
        }),
        ('Authentication', {
            'fields': ('password', 'temp_password', 'last_password_change', 'last_login')
        }),
        ('Status', {
            'fields': ('status', 'is_active')
        }),
    )
    
    readonly_fields = ('employee_code', 'last_password_change', 'last_login')
    
    def save_model(self, request, obj, form, change):
        if not change:  # New employee
            # Generate temporary password
            import secrets
            temp_password = secrets.token_urlsafe(8)
            obj.password = temp_password  # In production, hash this
            obj.temp_password = True
        
        super().save_model(request, obj, form, change)

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

# Register models
admin.site.register(Company, CompanyAdmin)
admin.site.register(Employee, EmployeeAdmin)
admin.site.register(CompanySettings, CompanySettingsAdmin)
admin.site.register(EmployeeLoginHistory, EmployeeLoginHistoryAdmin)