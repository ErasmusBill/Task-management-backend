from django.shortcuts import render, get_object_or_404
from rest_framework.response import Response
from rest_framework.decorators import api_view
from rest_framework import status, generics
from .serializers import TaskSerializer
from rest_framework_simplejwt.authentication import JWTAuthentication
from rest_framework.permissions import IsAuthenticated,IsAuthenticatedOrReadOnly,IsAdminUser
from rest_framework.views import APIView
from .models import Task
from django.core.mail import send_mail
from django.db.models.signals import post_save
from django.dispatch import receiver
import json
import http.client
from django.db.models.signals import post_save
import environ
from rest_framework.pagination import PageNumberPagination
# Create your views here.


class TaskCreate(APIView):
    authentication_classes = [JWTAuthentication]
    permission_classes = [IsAuthenticated,IsAdminUser]
    def post(self, request):
        serializer = TaskSerializer(data=request.data)
        if serializer.is_valid():
            serializer.save()
            return Response(serializer.data, status=status.HTTP_201_CREATED)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
    
def send_email_via_sendgrid(to_email, subject, body):
    """Send an email using the SendGrid API."""
    # Set up the connection
    conn = http.client.HTTPSConnection("rapidprod-sendgrid-v1.p.rapidapi.com")

    # Define the payload
    payload = json.dumps({
        "personalizations": [
            {
                "to": [{"email": to_email}],
                "subject": subject
            }
        ],
        "from": {"email": "erasmuschawey12345@gmail.com"}, 
        "content": [
            {
                "type": "text/plain",
                "value": body
            }
        ]
    })

    # Define the headers
    headers = {
        'x-rapidapi-key': "8febfb0c74mshf943a1a3aec2a46p10a91ejsnfc068c5acb5e", 
        'x-rapidapi-host': "rapidprod-sendgrid-v1.p.rapidapi.com",
        'Content-Type': "application/json"
    }

    # Send the request
    try:
        conn.request("POST", "/mail/send", payload, headers)
        res = conn.getresponse()
        data = res.read()
        print(f"API Response Status: {res.status}")
        print(f"API Response Data: {data.decode('utf-8')}")
    except Exception as e:
        print(f"Failed to send email: {e}")
    finally:
        conn.close()
        
    

@receiver(post_save, sender=Task)
def send_task_assignment_email(sender, instance, created, **kwargs):
    """Send an email when a task is assigned to a user using SendGrid API."""
    if created and instance.assigned_to:
        subject = "New Task Assigned to You"
        body = f"""
        Hello {instance.assigned_to.first_name} {instance.assigned_to.last_name},
        You have been assigned a new task: '{instance.title}'.
        Description: {instance.description}
        Please log in to your dashboard to view more details.
        Best Regards,
        Your Team
        """

        # Send the email using SendGrid API
        send_email_via_sendgrid(
            to_email=instance.assigned_to.email,
            subject=subject,
            body=body
        )


class TaskList(APIView):
    authentication_classes = [JWTAuthentication]
    permission_classes = [IsAuthenticatedOrReadOnly]
    
    def get(self, request):
        tasks = Task.objects.all()
        paginator = PageNumberPagination()
        paginator.page_size = 10
        paginated_tasks = paginator.paginate_queryset(tasks, request)
        serializer = TaskSerializer(paginated_tasks, many=True)
        return paginator.get_paginated_response(serializer.data)

class TaskDetail(APIView):
    authentication_classes = [JWTAuthentication]
    permission_classes = [IsAuthenticated]
    def get(self, request, pk):
        user = request.user
        task = get_object_or_404(Task, pk=pk) 
        if not user.is_staff and task.user != user:
            return Response(
                {"message": "You are not allowed to view this task"},
                status=status.HTTP_403_FORBIDDEN
            )
        serializer = TaskSerializer(task)
        return Response(serializer.data)

class TaskUpdate(APIView):
    authentication_classes = [JWTAuthentication]
    permission_classes = [IsAuthenticatedOrReadOnly,IsAdminUser]
    def put(self, request, pk):
        task = get_object_or_404(Task, pk=pk)  
        serializer = TaskSerializer(task, data=request.data)
        if serializer.is_valid():
            serializer.save()
            return Response(serializer.data)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

class TaskDelete(APIView):
    authentication_classes = [JWTAuthentication]
    permission_classes = [IsAuthenticatedOrReadOnly,IsAdminUser]
    def delete(self, request, pk):
        task = get_object_or_404(Task, pk=pk)  
        task.delete()
        return Response(status=status.HTTP_204_NO_CONTENT)
    
class TaskListByUser(APIView):
    authentication_classes = [JWTAuthentication]
    permission_classes = [IsAuthenticated, IsAdminUser] 

    def get(self, request, user_id):
        tasks = Task.objects.filter(user_id=user_id)  
        paginator = PageNumberPagination()
        paginator.page_size = 10
        paginated_tasks = paginator.paginate_queryset(tasks, request)
        serializer = TaskSerializer(paginated_tasks, many=True)
        return paginator.get_paginated_response(serializer.data)    
    
@api_view(['GET'])
def search_task(request):
    if request.method == 'GET':
        title = request.query_params.get('title')
        tasks = Task.objects.filter(title__icontains=title)
        serializer = TaskSerializer(tasks, many=True)
        return Response(serializer.data)    