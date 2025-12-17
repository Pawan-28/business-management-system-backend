import django_filters
from .models import Item, Customer, Vendor, Employee, Vehicle

class ItemFilter(django_filters.FilterSet):
    item_code = django_filters.CharFilter(lookup_expr='icontains')
    item_name = django_filters.CharFilter(lookup_expr='icontains')
    item_type = django_filters.ChoiceFilter(choices=Item.ITEM_TYPES)
    is_active = django_filters.BooleanFilter()
    
    class Meta:
        model = Item
        fields = ['item_code', 'item_name', 'item_type', 'is_active']


class CustomerFilter(django_filters.FilterSet):
    customer_code = django_filters.CharFilter(lookup_expr='icontains')
    customer_name = django_filters.CharFilter(lookup_expr='icontains')
    gst_number = django_filters.CharFilter(lookup_expr='icontains')
    po_number = django_filters.CharFilter(lookup_expr='icontains')
    is_active = django_filters.BooleanFilter()
    
    class Meta:
        model = Customer
        fields = ['customer_code', 'customer_name', 'gst_number', 'po_number', 'is_active']


class VendorFilter(django_filters.FilterSet):
    vendor_code = django_filters.CharFilter(lookup_expr='icontains')
    vendor_name = django_filters.CharFilter(lookup_expr='icontains')
    gst_number = django_filters.CharFilter(lookup_expr='icontains')
    ifsc_code = django_filters.CharFilter(lookup_expr='icontains')
    is_active = django_filters.BooleanFilter()
    
    class Meta:
        model = Vendor
        fields = ['vendor_code', 'vendor_name', 'gst_number', 'ifsc_code', 'is_active']


class EmployeeFilter(django_filters.FilterSet):
    employee_code = django_filters.CharFilter(lookup_expr='icontains')
    full_name = django_filters.CharFilter(lookup_expr='icontains')
    # role = django_filters.ChoiceFilter(choices=Employee.ROLE_CHOICES)
    status = django_filters.ChoiceFilter(choices=Employee.STATUS_CHOICES)
    is_active = django_filters.BooleanFilter()
    
    class Meta:
        model = Employee
        fields = ['employee_code', 'full_name',  'status', 'is_active']


class VehicleFilter(django_filters.FilterSet):
    vehicle_code = django_filters.CharFilter(lookup_expr='icontains')
    vehicle_name = django_filters.CharFilter(lookup_expr='icontains')
    vehicle_number = django_filters.CharFilter(lookup_expr='icontains')
    is_active = django_filters.BooleanFilter()
    
    class Meta:
        model = Vehicle
        fields = ['vehicle_code', 'vehicle_name', 'vehicle_number', 'is_active']