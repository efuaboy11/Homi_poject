from rest_framework.permissions import BasePermission
from .models import Role

class IsAdminOrClientOrStoreOwner(BasePermission):
    def has_permission(self, request, view):
        return (
            request.user
            or request.user.is_authenticated
            or request.user.role == Role.ADMIN
            or request.user.role == Role.CLIENT
            or request.user.role == Role.STORE_OWNER
        )
        
class IsAdminOrStoreOwner(BasePermission):
    def has_permission(self, request, view):
        return (
            request.user
            or request.user.is_authenticated
            or request.user.role == Role.ADMIN
            or request.user.role == Role.STORE_OWNER
        )
        
        
class IsAdminOrStoreOwnerOrCourier(BasePermission):
    def has_permission(self, request, view):
        return (
            request.user
            or request.user.is_authenticated
            or request.user.role == Role.ADMIN
            or request.user.role == Role.STORE_OWNER
            or request.user.role == Role.COURIER
        )
        
        
class IsClient(BasePermission):
    def has_permission(self, request, view):
        return (
            request.user
            or request.user.is_authenticated
            or request.user.role == Role.CLIENT
        )
        

        