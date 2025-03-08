from django.shortcuts import render,get_object_or_404
from rest_framework.response import Response
from rest_framework import permissions
from rest_framework.views import APIView
from rest_framework import generics, status
from .serializers import UserSerializer, ChangePasswordSerializer
from django.contrib.auth.models import User
from django.contrib.auth import authenticate,login
from django.contrib.auth import get_user_model
from rest_framework_simplejwt.tokens import RefreshToken
import uuid
from django.utils import timezone
from datetime import timedelta
from django.core.mail import send_mail
from django.dispatch import receiver
from django.db.models.signals import post_save
from django.conf import settings





User = get_user_model()
# Create your views here.
class UserListView(generics.ListAPIView):
    """
    API endpoint to list all users for task assignment
    """
    queryset = User.objects.all().order_by('username')
    serializer_class = UserSerializer
    #permission_classes = [permissions.IsAuthenticated]
    
class UserCreate(APIView):
    def post(self, request):
        serializer = UserSerializer(data=request.data)
        if serializer.is_valid():
            user = serializer.save()
            verification_token = str(uuid.uuid4())
            user.verification_token = verification_token
            user.verification_token_expiry = timezone.now() + timezone.timedelta(hours=24)
            user.save()
            print(f"Generated Verification Token: {verification_token}")
            response_data = {
                'id': serializer.data['id'],
                'username': serializer.data['username'],
                'email': serializer.data['email'],
                'message': 'User created successfully.'
            }
            return Response(response_data, status=status.HTTP_201_CREATED)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
    
    
@receiver(post_save, sender=User)
def send_verification_token(sender, instance, created, **kwargs):
    if created:
        verification_token = instance.verification_token
        base_url = getattr(settings, 'FRONTEND_URL', "https://task-management-gold-iota.vercel.app/")
        verification_url = f"{base_url}/verify-email?token={verification_token}/"
        
        subject = "Verify your email address"
        html_message = f"""
        <p>Hi {instance.username},</p>
        <p>Please click the link below to verify your email address:</p>
        <p><a href="{verification_url}">Verify Email</a></p>
        <p>If you didn't request this, you can safely ignore this email.</p>
        """
        plain_message = f"""
        Hi {instance.username},
        Please click the link below to verify your email address: {verification_url}
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
        except Exception as e:
            # Log the error
            print(f"Failed to send verification email: {e}")
                
class VerifyEmailView(APIView):
    def get(self, request, token):
        user = get_object_or_404(User, verification_token=token)   
        
        if user.verification_token_expiry and user.verification_token_expiry > timezone.now():
            user.is_verified = True
            user.verification_token = None
            user.verification_token_expiry = None
            user.save()
            return Response({"message":"Email verified successfully"}, status=status.HTTP_200_OK)     
        else:
            return Response({"error":"Invalid or expired verification token"}, status=status.HTTP_400_BAD_REQUEST)    
class ResendVerificationEmailView(APIView):
    def post(self, request):
        email = request.data.get('email')
        if not email:
            return Response({"error": "Email is required"}, status=status.HTTP_400_BAD_REQUEST)
        
        user = get_object_or_404(User, email=email)
        
        # Generate a new verification token
        verification_token = str(uuid.uuid4())
        user.verification_token = verification_token
        user.verification_token_expiry = timezone.now() + timezone.timedelta(hours=24)
        user.save()
        
        # Send the new verification email
        base_url = getattr(settings, 'FRONTEND_URL', "https://task-management-gold-iota.vercel.app/")
        verification_url = f"{base_url}/verify-email?token={verification_token}"
        
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
            return Response({"message": "Verification email resent successfully."}, status=status.HTTP_200_OK)
        except Exception as e:
            print(f"Failed to resend verification email: {e}")
            return Response({"error": "Failed to resend verification email. Please try again later."}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
    

class UserLogin(APIView):
    def post(self, request):
        username = request.data.get('username')
        password = request.data.get('password')
        if username is None or password is None:
            return Response({'error': 'Please provide both username and password'}, status=status.HTTP_400_BAD_REQUEST)
        user = authenticate(username=username, password=password)
        #login(request, user)
        if not user:
            return Response({'error': 'Invalid Credentials'}, status=status.HTTP_404_NOT_FOUND)
        
        if not user.is_verified:
            return Response({'error': 'Email not verified. Please verify your email to login.'}, status=status.HTTP_403_FORBIDDEN)
        
        refresh = RefreshToken.for_user(user)
        return Response(
                            {'message': 'Login successful',
                             'username':user.username,
                             'access_token':str(refresh.access_token),
                             'refresh_token':str(refresh)
                            }, 
                            status=status.HTTP_200_OK
                        ) 


class Logout(APIView):
    def post(self, request):
        refresh_token = request.data.get('refresh_token')
        if not refresh_token:
            return Response({'error': 'Refresh token is required'}, status=status.HTTP_400_BAD_REQUEST)
        
        try:
            token = RefreshToken(refresh_token)
            token.blacklist()
            return Response({'message': 'Logout successful'}, status=status.HTTP_205_RESET_CONTENT)
        except Exception as e:
        
            #print(f"Logout error: {str(e)}")
            return Response({'error': 'Invalid refresh token'}, status=status.HTTP_400_BAD_REQUEST)        
class ChangePasswordView(APIView):
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