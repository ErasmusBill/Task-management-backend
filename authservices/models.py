from django.db import models
from django.contrib.auth.models import AbstractUser

# Create your models here.

class User(AbstractUser):
    first_name = models.CharField(max_length=255)
    last_name = models.CharField(max_length=255)
    email = models.EmailField(unique=True)
    username = models.CharField(max_length=255, unique=True)
    verification_token = models.CharField(max_length=255, null=True, blank=True)
    verification_token_expiry = models.DateTimeField(null=True, blank=True)
    is_verified = models.BooleanField(default=False)
    
    def __str__(self):
        self.username