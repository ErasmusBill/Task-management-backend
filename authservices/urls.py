from django.urls import path
from . import views

urlpatterns = [
    path('create/', views.UserCreate.as_view(), name='user_create'),
    path('login/', views.UserLogin.as_view(), name='user_login'),
    path('logout/', views.Logout.as_view(), name='user_logout'),
]