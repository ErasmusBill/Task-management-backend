from django.shortcuts import render
from rest_framework.response import Response
from rest_framework.views import APIView
from rest_framework import generics, status
from .serializers import UserSerializer
from django.contrib.auth import authenticate,login
from rest_framework_simplejwt.tokens import RefreshToken


# Create your views here.
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
        try:
            token = RefreshToken(refresh_token)
            token.blacklist()
            return Response({'message': 'Logout successful'}, status=status.HTTP_205_RESET_CONTENT)
        except:
            return Response({'message': 'Invalid refresh token'}, status=status.HTTP_400_BAD_REQUEST)
    
        