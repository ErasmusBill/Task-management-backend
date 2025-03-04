from django.shortcuts import render, get_object_or_404
from rest_framework.response import Response
from rest_framework.decorators import api_view
from rest_framework import status, generics
from .serializers import TaskSerializer
from rest_framework_simplejwt.authentication import JWTAuthentication
from rest_framework.permissions import IsAuthenticated, IsAuthenticatedOrReadOnly, IsAdminUser
from rest_framework.views import APIView
from .models import Task
from django.core.mail import send_mail
from django.db.models.signals import post_save
from django.dispatch import receiver
from rest_framework.pagination import PageNumberPagination

# Create your views here.

class TaskCreate(APIView):
    #authentication_classes = [JWTAuthentication]
    #permission_classes = [IsAuthenticated, IsAdminUser]

    def post(self, request):
        # Ensure the user is authenticated
        if not request.user.is_authenticated:
            return Response({'error': 'Failed to retrieve user information. Please log in again.'}, status=status.HTTP_401_UNAUTHORIZED)

        # Proceed with task creation
        serializer = TaskSerializer(data=request.data)
        if serializer.is_valid():
            serializer.save(created_by=request.user)  # Automatically set created_by to the authenticated user
            return Response(serializer.data, status=status.HTTP_201_CREATED)
        
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

@receiver(post_save, sender=Task)
def send_task_assignment_email(sender, instance, created, **kwargs):
    """Send an email when a task is assigned to a user using Gmail."""
    if created and instance.assigned_to:
        #print("Task created and email is about to be sent.")
        subject = "New Task Assigned to You"
        body = f"""
        Hello {instance.assigned_to.first_name} {instance.assigned_to.last_name},
        You have been assigned a new task: '{instance.title}'.
        Description: {instance.description}
        Please log in to your dashboard to view more details.
        Best Regards,
        Your Team
        """

        # Send the email using Gmail
        send_mail(
            subject=subject,
            message=body,
            from_email='erasmuschawey12345@gmail.com',  # Replace with your Gmail address
            recipient_list=[instance.assigned_to.email],
            fail_silently=False,
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
    def put(self, request, pk):
        task = get_object_or_404(Task, pk=pk)  
        serializer = TaskSerializer(task, data=request.data)
        if serializer.is_valid():
            serializer.save()
            return Response(serializer.data)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

class TaskDelete(APIView):
    authentication_classes = [JWTAuthentication]
    def delete(self, request, pk):
        task = get_object_or_404(Task, pk=pk)  
        task.delete()
        return Response(status=status.HTTP_204_NO_CONTENT)
    
class TaskListByUser(APIView):
    authentication_classes = [JWTAuthentication]
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
    
@api_view(['GET'])
def get_status_choices(request):
    return Response(dict(Task.STATUS_CHOICES))