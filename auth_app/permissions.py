from rest_framework import permissions

class IsAdmin(permissions.BasePermission):
    def has_permission(self, request, view):
        return request.user and request.user.role == 'admin'

class IsManager(permissions.BasePermission):
    def has_permission(self, request, view):
        return request.user and request.user.role == 'manager'

class IsEmployee(permissions.BasePermission):
    def has_permission(self, request, view):
        return request.user and request.user.role == 'employee'

class IsAdminOrManager(permissions.BasePermission):
    def has_permission(self, request, view):
        return request.user and request.user.role in ['admin', 'manager']
