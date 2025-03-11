from django.shortcuts import get_object_or_404
from rest_framework.response import Response
from rest_framework import permissions, status
from rest_framework.views import APIView
from rest_framework import generics
from .serializers import UserSerializer, ChangePasswordSerializer
from django.contrib.auth import authenticate
from django.contrib.auth import get_user_model
from rest_framework_simplejwt.tokens import RefreshToken
import random
from django.utils import timezone
from datetime import timedelta
from django.core.mail import send_mail
from django.conf import settings
from django.dispatch import receiver
from django.db.models.signals import post_save


User = get_user_model()


class UserListView(generics.ListAPIView):
    """
    API endpoint to list all users for task assignment.
    """
    queryset = User.objects.all().order_by('username')
    serializer_class = UserSerializer
    permission_classes = [permissions.IsAuthenticated]


class UserCreate(APIView):
    """
    API endpoint to create a new user and send a verification email with a 4-digit PIN.
    """
    def post(self, request):
        serializer = UserSerializer(data=request.data)
        if serializer.is_valid():
            user = serializer.save()
            verification_pin = str(random.randint(1000, 9999))  
            print(f"[DEBUG] Generated PIN: {verification_pin}")  

            user.verification_token = verification_pin
            user.verification_token_expiry = timezone.now() + timedelta(hours=24)
            user.save()

            # Debug: Print user details
            print(f"[DEBUG] User created: ID={user.id}, Username={user.username}, Email={user.email}")

            # Trigger the signal to send the verification email
            self._send_verification_email(user)

            response_data = {
                'id': user.id,
                'username': user.username,
                'email': user.email,
                'message': 'User created successfully. Please check your email for the verification PIN.'
            }
            return Response(response_data, status=status.HTTP_201_CREATED)
        print(f"[DEBUG] Serializer errors: {serializer.errors}")
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

    def _send_verification_email(self, user):
        """
        Helper method to send a verification email with a 4-digit PIN.
        """
        subject = "Verify your email address"
        html_message = f"""
        <p>Hi {user.username},</p>
        <p>Your verification PIN is: <strong>{user.verification_token}</strong></p>
        <p>Please enter this PIN on the verification page to verify your email address.</p>
        <p>If you didn't request this, you can safely ignore this email.</p>
        """
        plain_message = f"""
        Hi {user.username},
        Your verification PIN is: {user.verification_token}
        Please enter this PIN on the verification page to verify your email address.
        If you didn't request this, you can safely ignore this email.
        """

        try:
            send_mail(
                subject=subject,
                message=plain_message,
                html_message=html_message,
                from_email=settings.DEFAULT_FROM_EMAIL,
                recipient_list=[user.email],
                fail_silently=False,
            )
            print(f"[DEBUG] Verification email sent to {user.email}")
        except Exception as e:
            print(f"[DEBUG] Failed to send verification email: {e}")


@receiver(post_save, sender=User)
def send_verification_email_on_creation(sender, instance, created, **kwargs):
    """
    Signal handler to send a verification email when a new user is created.
    """
    if created:
        verification_pin = str(random.randint(1000, 9999))
        instance.verification_token = verification_pin
        instance.verification_token_expiry = timezone.now() + timedelta(hours=24)
        instance.save()

        print(f"[DEBUG] Verification PIN generated for user {instance.username}: {verification_pin}")

        subject = "Verify your email address"
        html_message = f"""
        <p>Hi {instance.username},</p>
        <p>Your verification PIN is: <strong>{instance.verification_token}</strong></p>
        <p>Please enter this PIN on the verification page to verify your email address.</p>
        <p>If you didn't request this, you can safely ignore this email.</p>
        """
        plain_message = f"""
        Hi {instance.username},
        Your verification PIN is: {instance.verification_token}
        Please enter this PIN on the verification page to verify your email address.
        If you didn't request this, you can safely ignore this email.
        """

        try:
            send_mail(
                subject=subject,
                message=plain_message,
                html_message=html_message,
                from_email=settings.DEFAULT_FROM_EMAIL,
                recipient_list=[instance.email],
                fail_silently=False,
            )
            print(f"[DEBUG] Verification email sent to {instance.email}")
        except Exception as e:
            print(f"[DEBUG] Failed to send verification email: {e}")


class VerifyEmailView(APIView):
    """
    API endpoint to verify a user's email using the 4-digit PIN.
    """
    def post(self, request):
        pin = request.data.get('pin')
        if not pin:
            print("[DEBUG] PIN is required for verification.")
            return Response({"error": "PIN is required"}, status=status.HTTP_400_BAD_REQUEST)

        user = get_object_or_404(User, verification_token=pin)
        print(f"[DEBUG] User found for PIN {pin}: ID={user.id}, Username={user.username}")

        if user.verification_token == pin:
            if user.verification_token_expiry and user.verification_token_expiry > timezone.now():
                user.is_verified = True
                user.verification_token = None
                user.verification_token_expiry = None
                user.save()
                print(f"[DEBUG] User {user.username} verified successfully.")
                return Response({"message": "Email verified successfully"}, status=status.HTTP_200_OK)
            else:
                print(f"[DEBUG] Expired verification PIN for user {user.username}.")
                return Response({"error": "Expired verification PIN"}, status=status.HTTP_400_BAD_REQUEST)
        else:
            print(f"[DEBUG] Invalid verification PIN for user {user.username}.")
            return Response({"error": "Invalid verification PIN"}, status=status.HTTP_400_BAD_REQUEST)


class ResendVerificationEmailView(APIView):
    """
    API endpoint to resend the verification email with a new 4-digit PIN.
    """
    def post(self, request):
        email = request.data.get('email')
        if not email:
            print("[DEBUG] Email is required for resending verification.")
            return Response({"error": "Email is required"}, status=status.HTTP_400_BAD_REQUEST)

        user = get_object_or_404(User, email=email)
        print(f"[DEBUG] User found for email {email}: ID={user.id}, Username={user.username}")

        verification_pin = str(random.randint(1000, 9999))
        user.verification_token = verification_pin
        user.verification_token_expiry = timezone.now() + timedelta(hours=24)
        user.save()

        print(f"[DEBUG] New verification PIN generated for user {user.username}: {verification_pin}")

        # Send the new verification email
        self._send_verification_email(user)

        return Response({"message": "Verification email resent successfully."}, status=status.HTTP_200_OK)

    def _send_verification_email(self, user):
        """
        Helper method to send a verification email with a 4-digit PIN.
        """
        subject = "Verify your email address"
        html_message = f"""
        <p>Hi {user.username},</p>
        <p>Your verification PIN is: <strong>{user.verification_token}</strong></p>
        <p>Please enter this PIN on the verification page to verify your email address.</p>
        <p>If you didn't request this, you can safely ignore this email.</p>
        """
        plain_message = f"""
        Hi {user.username},
        Your verification PIN is: {user.verification_token}
        Please enter this PIN on the verification page to verify your email address.
        If you didn't request this, you can safely ignore this email.
        """

        try:
            send_mail(
                subject=subject,
                message=plain_message,
                html_message=html_message,
                from_email=settings.DEFAULT_FROM_EMAIL,
                recipient_list=[user.email],
                fail_silently=False,
            )
            print(f"[DEBUG] Verification email sent to {user.email}")
        except Exception as e:
            print(f"[DEBUG] Failed to send verification email: {e}")


class UserLogin(APIView):
    def post(self, request):
        username = request.data.get('username')
        password = request.data.get('password')
        if not username or not password:
            print("[DEBUG] Username and password are required for login.")
            return Response({'error': 'Please provide both username and password'}, status=status.HTTP_400_BAD_REQUEST)

        user = authenticate(username=username, password=password)
        if not user:
            print(f"[DEBUG] Invalid credentials for username: {username}")
            return Response({'error': 'Invalid credentials'}, status=status.HTTP_401_UNAUTHORIZED)

        print(f"[DEBUG] User authenticated: ID={user.id}, Username={user.username}, Verified={user.is_verified}")

        if not user.is_verified:
            print(f"[DEBUG] User {user.username} is not verified.")
            return Response({'error': 'Email not verified. Please verify your email to login.'}, status=status.HTTP_403_FORBIDDEN)

        try:
            refresh = RefreshToken.for_user(user)
            print(f"[DEBUG] Refresh token generated for user {user.username}.")
        except Exception as e:
            print(f"[DEBUG] Error generating token for user {user.username}: {e}")
            return Response({'error': 'Failed to generate token. Please try again.'}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

        return Response(
            {
                'message': 'Login successful',
                'username': user.username,
                'access_token': str(refresh.access_token),
                'refresh_token': str(refresh)
            },
            status=status.HTTP_200_OK
        )


class Logout(APIView):
    """
    API endpoint to log out a user by blacklisting their refresh token.
    """
    def post(self, request):
        refresh_token = request.data.get('refresh_token')
        if not refresh_token:
            print("[DEBUG] Refresh token is required for logout.")
            return Response({'error': 'Refresh token is required'}, status=status.HTTP_400_BAD_REQUEST)

        try:
            token = RefreshToken(refresh_token)
            token.blacklist()
            print(f"[DEBUG] Refresh token blacklisted: {refresh_token}")
            return Response({'message': 'Logout successful'}, status=status.HTTP_205_RESET_CONTENT)
        except Exception as e:
            print(f"[DEBUG] Error blacklisting refresh token: {e}")
            return Response({'error': 'Invalid refresh token'}, status=status.HTTP_400_BAD_REQUEST)


class ChangePasswordView(APIView):
    """
    API endpoint to change a user's password.
    """
    permission_classes = [permissions.IsAuthenticated]

    def post(self, request):
        user = request.user
        serializer = ChangePasswordSerializer(data=request.data)
        if serializer.is_valid():
            if not user.check_password(serializer.validated_data['old_password']):
                print(f"[DEBUG] Incorrect old password for user {user.username}.")
                return Response({"old_password": ["Wrong password."]}, status=status.HTTP_400_BAD_REQUEST)
            user.set_password(serializer.validated_data['new_password'])
            user.save()
            print(f"[DEBUG] Password updated for user {user.username}.")
            return Response({"message": "Password updated successfully."}, status=status.HTTP_200_OK)
        print(f"[DEBUG] Serializer errors for password change: {serializer.errors}")
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


class UpdateProfileView(APIView):
    """
    API endpoint to update a user's profile.
    """
    permission_classes = [permissions.IsAuthenticated]

    def get(self, request):
        user = request.user
        serializer = UserSerializer(user)
        print(f"[DEBUG] Profile data retrieved for user {user.username}.")
        return Response(serializer.data, status=status.HTTP_200_OK)

    def put(self, request):
        user = request.user
        serializer = UserSerializer(user, data=request.data, partial=True)
        if serializer.is_valid():
            serializer.save()
            print(f"[DEBUG] Profile updated for user {user.username}.")
            return Response(serializer.data, status=status.HTTP_200_OK)
        print(f"[DEBUG] Serializer errors for profile update: {serializer.errors}")
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)