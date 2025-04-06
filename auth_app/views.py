import random
from django.contrib.auth import get_user_model
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import status, permissions
from rest_framework_simplejwt.tokens import RefreshToken
from .serializers import (
    RegistrationSerializer, LoginRequestSerializer,LoginOTPVerifySerializer, PasswordResetSerializer,AccountUpdateSerializer
)
from .permissions import IsAdmin, IsManager, IsEmployee, IsAdminOrManager
from rest_framework.permissions import IsAuthenticated
from django.urls import reverse
from django.core.mail import send_mail
from django.utils.http import urlsafe_base64_encode,urlsafe_base64_decode
from django.utils.encoding import force_bytes
from django.contrib.auth.tokens import default_token_generator
from .utils import generate_otp, send_sms_otp
from django.core.cache import cache

User = get_user_model()


class RegisterView(APIView):
    def post(self, request):
        serializer = RegistrationSerializer(data=request.data)
        if serializer.is_valid():
            user = serializer.save()

            otp = str(random.randint(100000, 999999))
            user.otp = otp
            user.save()

            return Response({"message": "User registered successfully."})
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


class LoginRequestView(APIView):
    def post(self, request):
        serializer = LoginRequestSerializer(data=request.data)
        if serializer.is_valid():
            phone = serializer.validated_data['phone']
            otp = generate_otp()
            
            cache.set(f'otp_{phone}', otp, timeout=300)
            
            send_sms_otp(phone, otp)

            return Response({"message": "OTP sent to phone."})
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

class LoginVerifyView(APIView):
    def post(self, request):
        serializer = LoginOTPVerifySerializer(data=request.data)
        if serializer.is_valid():
            phone = serializer.validated_data['phone']
            otp = serializer.validated_data['otp']

            cached_otp = cache.get(f'otp_{phone}')
            if cached_otp == otp:
                try:
                    user = User.objects.get(phone=phone)
                except User.DoesNotExist:
                    return Response({"error": "User not found"}, status=404)

                if not user.is_active:
                    user.is_active = True
                    user.save()

                refresh = RefreshToken.for_user(user)

                return Response({
                    "message": "OTP verified successfully.",
                    "access": str(refresh.access_token),
                    "refresh": str(refresh),
                })

            return Response({"error": "Invalid or expired OTP."}, status=400)
        return Response(serializer.errors, status=400)

class PasswordResetView(APIView):
    def post(self, request):
        serializer = PasswordResetSerializer(data=request.data)
        if serializer.is_valid():
            email = serializer.validated_data['email']
            print(f"[INFO] Password reset requested for: {email}")
            try:
                user = User.objects.get(email=email)
            except User.DoesNotExist:
                print("[ERROR] User not found with email:", email)
                return Response({"error": "User not found"}, status=404)

            uid = urlsafe_base64_encode(force_bytes(user.pk))
            token = default_token_generator.make_token(user)

            reset_url = request.build_absolute_uri(
                reverse('set-new-password') + f'?uid={uid}&token={token}'
            )

            print(f"[DEBUG] Generated UID: {uid}")
            print(f"[DEBUG] Generated Token: {token}")
            print(f"[INFO] Password reset link: {reset_url}")

            try:
                send_mail(
                    subject="Reset Your Password",
                    message=f"Click the link to reset your password: {reset_url}",
                    from_email="testing@gmail.com",
                    recipient_list=[user.email],
                    fail_silently=False,
                )
                print("[INFO] Password reset email sent successfully.")
            except Exception as e:
                print(f"[ERROR] Failed to send email: {e}")
                return Response({"error": "Failed to send email."}, status=500)

            return Response({"message": "Password reset link sent to email."})
        print("[ERROR] Invalid request data:", serializer.errors)
        return Response(serializer.errors, status=400)




class SetNewPasswordView(APIView):
    def post(self, request):
        uidb64 = request.data.get('uid') or request.query_params.get('uid')
        token = request.data.get('token') or request.query_params.get('token')
        new_password = request.data.get('new_password')

        if not uidb64 or not token or not new_password:
            return Response({"error": "Missing uid, token, or new_password."}, status=400)

        print(f"[INFO] Password reset requested. UIDB64: {uidb64}, Token: {token}")

        try:
            uid = urlsafe_base64_decode(uidb64).decode()
            print(f"[DEBUG] Decoded UID: {uid}")
            user = User.objects.get(pk=uid)
        except (TypeError, ValueError, OverflowError, User.DoesNotExist) as e:
            print(f"[ERROR] UID decode or user fetch failed: {e}")
            return Response({"error": "Invalid link or user not found"}, status=400)

        if default_token_generator.check_token(user, token):
            user.set_password(new_password)
            user.save()
            print("[INFO] Password updated successfully.")
            return Response({"message": "Password updated successfully."})
        else:
            print("[ERROR] Invalid or expired token.")
            return Response({"error": "Invalid or expired token"}, status=400)


class AccountUpdateView(APIView):
    permission_classes = [permissions.IsAuthenticated]

    def put(self, request):
        print(f"[DEBUG] Authenticated user: {request.user}")
        print(f"[DEBUG] Auth: {request.auth}")
        serializer = AccountUpdateSerializer(instance=request.user, data=request.data, partial=True)
        if serializer.is_valid():
            serializer.save()
            return Response({"message": "Account updated successfully."})
        return Response(serializer.errors, status=400)
    

class AdminOnlyView(APIView):
    permission_classes = [IsAuthenticated, IsAdmin]

    def get(self, request):
        return Response({"message": "Welcome Admin!"})

class ManagerOnlyView(APIView):
    permission_classes = [IsAuthenticated, IsManager]

    def get(self, request):
        return Response({"message": "Hello Manager!"})

class EmployeeOnlyView(APIView):
    permission_classes = [IsAuthenticated, IsEmployee]

    def get(self, request):
        return Response({"message": "Hi Employee!"})

class AdminManagerView(APIView):
    permission_classes = [IsAuthenticated, IsAdminOrManager]

    def get(self, request):
        return Response({"message": "Accessible to Admin or Manager"})

