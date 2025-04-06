from django.urls import path
from .views import (
    RegisterView,LoginRequestView, LoginVerifyView,PasswordResetView, SetNewPasswordView,AccountUpdateView, AdminOnlyView,
    ManagerOnlyView,EmployeeOnlyView,AdminManagerView,
)

urlpatterns = [
    path('register/', RegisterView.as_view(), name='register'),
    path('login-request/', LoginRequestView.as_view(), name='login-request'),
    path('login-verify/', LoginVerifyView.as_view(), name='login-verify'),
    path('password-reset/', PasswordResetView.as_view(), name='password-reset'),
    path('set-new-password/', SetNewPasswordView.as_view(), name='set-new-password'),
    path('account-update/', AccountUpdateView.as_view(), name='account-update'),
    path('admin-only/', AdminOnlyView.as_view(), name='admin-only'),
    path('manager-only/', ManagerOnlyView.as_view(), name='manager-only'),
    path('employee-only/', EmployeeOnlyView.as_view(), name='employee-only'),
    path('admin-manager/', AdminManagerView.as_view(), name='admin-manager'),
]
