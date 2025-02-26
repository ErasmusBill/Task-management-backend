from django.urls import path
from . import views

urlpatterns = [
    path('task-create/', views.TaskCreate.as_view(), name='task-create'),
    path('task-list/', views.TaskList.as_view(), name='task-list'),
    path('task-detail/<int:pk>/', views.TaskDetail.as_view(), name='task-detail'),
    path('task-update/<int:pk>/', views.TaskUpdate.as_view(), name='task-update'),
    path('task-delete/<int:pk>/', views.TaskDelete.as_view(), name='task-delete'),
    path('get_status_choices/',views.get_status_choices,name='get_status_choices'),
    path('search-task',views.search_task,name='search_task'),
    path('task-list-by-user/<int:user_id>/', views.TaskListByUser.as_view(), name='task-list-by-user'),
    
]
