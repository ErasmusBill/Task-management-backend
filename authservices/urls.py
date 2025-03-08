from django.urls import path
from . import views

urlpatterns = [
    path('create/', views.UserCreate.as_view(), name='user_create'),
    path('login/', views.UserLogin.as_view(), name='user_login'),
    path('logout/', views.Logout.as_view(), name='user_logout'),
    path('change-password/', views.ChangePasswordView.as_view(), name='change_password'),
    path('update-profile/', views.UpdateProfileView.as_view(), name='user_update'),
    path('list-users/', views.UserListView.as_view(), name='user_list'),
    path('verify-email/<str:token>/',views.VerifyEmailView.as_view(), name='verify-mail'),
    path('resend-verification-email/', views.ResendVerificationEmailView.as_view(), name='resend-verification-email'),
]