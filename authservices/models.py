from django.db import models
from django.contrib.auth.models import AbstractUser

class User(AbstractUser):
    # Custom fields
    verification_token = models.CharField(max_length=255, null=True, blank=True)
    verification_token_expiry = models.DateTimeField(null=True, blank=True)
    is_verified = models.BooleanField(default=False)

    # Make email unique (already done in your code)
    email = models.EmailField(unique=True)

    # Fix reverse accessor clash for groups and user_permissions
    groups = models.ManyToManyField(
        'auth.Group',
        verbose_name='groups',
        blank=True,
        help_text='The groups this user belongs to. A user will get all permissions granted to each of their groups.',
        related_name='custom_user_set',  # Unique related_name
        related_query_name='custom_user',
    )
    user_permissions = models.ManyToManyField(
        'auth.Permission',
        verbose_name='user permissions',
        blank=True,
        help_text='Specific permissions for this user.',
        related_name='custom_user_set',  # Unique related_name
        related_query_name='custom_user',
    )

    def __str__(self):
        return self.username  # Return the username as a string