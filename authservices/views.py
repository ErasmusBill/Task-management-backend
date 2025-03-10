from django.shortcuts import get_object_or_404
from rest_framework.response import Response
from rest_framework import permissions, status
from rest_framework.views import APIView
from rest_framework import generics
from .serializers import UserSerializer, ChangePasswordSerializer
from django.contrib.auth import authenticate
from django.contrib.auth import get_user_model
from rest_framework_simplejwt.tokens import RefreshToken
import uuid
from django.utils import timezone
from datetime import timedelta
from django.core.mail import send_mail
from django.conf import settings
from urllib.parse import unquote

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
    API endpoint to create a new user and send a verification email.
    """
    def post(self, request):
        serializer = UserSerializer(data=request.data)
        if serializer.is_valid():
            user = serializer.save()
            verification_token = str(uuid.uuid4())  # Generate a new token
            print(f"Generated token: {verification_token}")  # For debugging

            # Save the token and expiry in the database
            user.verification_token = verification_token
            user.verification_token_expiry = timezone.now() + timedelta(hours=24)
            user.save()

            # Send verification email
            self._send_verification_email(user)

            response_data = {
                'id': user.id,
                'username': user.username,
                'email': user.email,
                'message': 'User created successfully. Please check your email to verify your account.'
            }
            return Response(response_data, status=status.HTTP_201_CREATED)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

    def _send_verification_email(self, user):
        """
        Helper method to send a verification email.
        """
        base_url = getattr(settings, 'FRONTEND_URL', "https://task-management-gold-iota.vercel.app").rstrip('/')
        verification_url = f"{base_url}/verify-email/{user.verification_token}/"

        subject = "Verify your email address"
        html_message = f"""
        <p>Hi {user.username},</p>
        <p>Please click the link below to verify your email address:</p>
        <p><a href="{verification_url}">Verify Email</a></p>
        <p>If you didn't request this, you can safely ignore this email.</p>
        """
        plain_message = f"""
        Hi {user.username},
        Please click the link below to verify your email address: {verification_url}
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
            print(f"Verification email sent to {user.email}")
        except Exception as e:
            print(f"Failed to send verification email: {e}")


class VerifyEmailView(APIView):
    """
    API endpoint to verify a user's email using the verification token.
    """
    def get(self, request, token):
        # Decode the token to handle URL-encoded characters
        decoded_token = unquote(token)
        print(f"Decoded token: {decoded_token}")  # For debugging

        # Find the user with the decoded token
        user = get_object_or_404(User, verification_token=decoded_token)

        if user.verification_token_expiry and user.verification_token_expiry > timezone.now():
            user.is_verified = True
            user.verification_token = None
            user.verification_token_expiry = None
            user.save()
            return Response({"message": "Email verified successfully"}, status=status.HTTP_200_OK)
        else:
            return Response({"error": "Invalid or expired verification token"}, status=status.HTTP_400_BAD_REQUEST)


class ResendVerificationEmailView(APIView):
    """
    API endpoint to resend the verification email.
    """
    def post(self, request):
        email = request.data.get('email')
        if not email:
            return Response({"error": "Email is required"}, status=status.HTTP_400_BAD_REQUEST)

        user = get_object_or_404(User, email=email)

        # Generate a new verification token
        user.verification_token = str(uuid.uuid4())
        user.verification_token_expiry = timezone.now() + timedelta(hours=24)
        user.save()

        # Send the new verification email
        self._send_verification_email(user)

        return Response({"message": "Verification email resent successfully."}, status=status.HTTP_200_OK)

    def _send_verification_email(self, user):
        """
        Helper method to send a verification email.
        """
        base_url = getattr(settings, 'FRONTEND_URL', "https://task-management-gold-iota.vercel.app").rstrip('/')
        verification_url = f"{base_url}/verify-email/{user.verification_token}/"

        subject = "Verify your email address"
        html_message = f"""
        <p>Hi {user.username},</p>
        <p>Please click the link below to verify your email address:</p>
        <p><a href="{verification_url}">Verify Email</a></p>
        <p>If you didn't request this, you can safely ignore this email.</p>
        """
        plain_message = f"""
        Hi {user.username},
        Please click the link below to verify your email address: {verification_url}
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
            print(f"Verification email resent to {user.email}")
        except Exception as e:
            print(f"Failed to resend verification email: {e}")


class UserLogin(APIView):
    """
    API endpoint to authenticate a user and return JWT tokens.
    """
    def post(self, request):
        username = request.data.get('username')
        password = request.data.get('password')
        if not username or not password:
            return Response({'error': 'Please provide both username and password'}, status=status.HTTP_400_BAD_REQUEST)

        user = authenticate(username=username, password=password)
        if not user:
            return Response({'error': 'Invalid credentials'}, status=status.HTTP_401_UNAUTHORIZED)

        if not user.is_verified:
            return Response({'error': 'Email not verified. Please verify your email to login.'}, status=status.HTTP_403_FORBIDDEN)

        refresh = RefreshToken.for_user(user)
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
            return Response({'error': 'Refresh token is required'}, status=status.HTTP_400_BAD_REQUEST)

        try:
            token = RefreshToken(refresh_token)
            token.blacklist()
            return Response({'message': 'Logout successful'}, status=status.HTTP_205_RESET_CONTENT)
        except Exception as e:
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
                return Response({"old_password": ["Wrong password."]}, status=status.HTTP_400_BAD_REQUEST)
            user.set_password(serializer.validated_data['new_password'])
            user.save()
            return Response({"message": "Password updated successfully."}, status=status.HTTP_200_OK)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


class UpdateProfileView(APIView):
    """
    API endpoint to update a user's profile.
    """
    permission_classes = [permissions.IsAuthenticated]

    def get(self, request):
        user = request.user
        serializer = UserSerializer(user)
        return Response(serializer.data, status=status.HTTP_200_OK)

    def put(self, request):
        user = request.user
        serializer = UserSerializer(user, data=request.data, partial=True)
        if serializer.is_valid():
            serializer.save()
            return Response(serializer.data, status=status.HTTP_200_OK)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)