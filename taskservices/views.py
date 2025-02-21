from django.shortcuts import render, get_object_or_404
from rest_framework.response import Response
from rest_framework.decorators import api_view
from rest_framework import status, generics
from .serializers import TaskSerializer
from rest_framework.views import APIView
from .models import Task
from django.core.mail import send_mail
from django.db.models.signals import post_save
from django.dispatch import receiver

# Create your views here.

class TaskCreate(APIView):
    def post(self, request):
        serializer = TaskSerializer(data=request.data)
        if serializer.is_valid():
            serializer.save()
            return Response(serializer.data, status=status.HTTP_201_CREATED)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
    
@receiver(post_save, sender=Task)
def send_task_assignment_email(sender, instance, created, **kwargs):
    """Send an email when a task is assigned to a user."""
    if created and instance.assigned_to:
        subject = "New Task Assigned to You"
        message = f"""
        Hello {instance.assigned_to.first_name} {instance.assigned_to.last_name},

        You have been assigned a new task: '{instance.title}'.

        Description: {instance.description}

        Please log in to your dashboard to view more details.

        Best Regards,
        Your Team
        """
        recipient_email = instance.assigned_to.email

        # Send the email notification
        send_mail(
            subject,
            message,
            'erasmuschawey12345@gmail.com',  
            [recipient_email],
            fail_silently=False,
        )    

class TaskList(APIView):
    def get(self, request):
        tasks = Task.objects.all()
        serializer = TaskSerializer(tasks, many=True)
        return Response(serializer.data)

class TaskDetail(APIView):
    def get(self, request, pk):
        task = get_object_or_404(Task, pk=pk) 
        serializer = TaskSerializer(task)
        return Response(serializer.data)

class TaskUpdate(APIView):
    def put(self, request, pk):
        task = get_object_or_404(Task, pk=pk)  
        serializer = TaskSerializer(task, data=request.data)
        if serializer.is_valid():
            serializer.save()
            return Response(serializer.data)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

class TaskDelete(APIView):
    def delete(self, request, pk):
        task = get_object_or_404(Task, pk=pk)  
        task.delete()
        return Response(status=status.HTTP_204_NO_CONTENT)