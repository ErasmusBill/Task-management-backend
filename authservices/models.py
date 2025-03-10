from django.db import models
from django.contrib.auth.models import AbstractUser

class User(AbstractUser):
    verification_token = models.CharField(max_length=255, null=True, blank=True)
    verification_token_expiry = models.DateTimeField(null=True, blank=True)
    is_verified = models.BooleanField(default=False)
    email = models.EmailField(unique=True)

    groups = models.ManyToManyField(
        'auth.Group',
        verbose_name='groups',
        blank=True,
        help_text='The groups this user belongs to. A user will get all permissions granted to each of their groups.',
        related_name='custom_user_set',  
        related_query_name='custom_user',
    )
    user_permissions = models.ManyToManyField(
        'auth.Permission',
        verbose_name='user permissions',
        blank=True,
        help_text='Specific permissions for this user.',
        related_name='custom_user_set',  
        related_query_name='custom_user',
    )

    def __str__(self):
        return self.username
    
    
    
class VerifyEmail(models.Model):
    email = models.EmailField()
    token = models.CharField(max_length=255)
    is_verified = models.BooleanField(default=True)
          