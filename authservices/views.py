from django.shortcuts import render
from rest_framework.response import Response
from rest_framework import permissions
from rest_framework.views import APIView
from rest_framework import generics, status
from .serializers import UserSerializer, ChangePasswordSerializer
from django.contrib.auth.models import User
from django.contrib.auth import authenticate,login
from django.contrib.auth import get_user_model
from rest_framework_simplejwt.tokens import RefreshToken

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
            serializer.save()
            response_data = {
                'id': serializer.data['id'],
                'username': serializer.data['username'],
                'email': serializer.data['email'],
                'message': 'User created successfully.'
            }
            return Response(response_data, status=status.HTTP_201_CREATED)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

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