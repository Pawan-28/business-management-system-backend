from rest_framework import permissions

class IsSameCompany(permissions.BasePermission):
    """
    Permission to ensure users can only access their own company's data
    """
    def has_permission(self, request, view):
        # Allow only authenticated users
        return request.user and request.user.is_authenticated
    
    def has_object_permission(self, request, view, obj):
        if hasattr(obj, 'company'):
            return obj.company == request.user
        return False