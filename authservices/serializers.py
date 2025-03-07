from django.contrib.auth.models import get_user_model
from rest_framework import serializers
from django.contrib.auth.hashers import make_password
from django.contrib.auth.password_validation import validate_password
from django.core.exceptions import ValidationError

User = get_user_model()


class UserSerializer(serializers.ModelSerializer):
    password = serializers.CharField(write_only=True, max_length=128)
    password2 = serializers.CharField(write_only=True, max_length=128)

    class Meta:
        model = User
        fields = ['id', 'username', 'email', 'first_name', 'last_name','verification_token','verification_token_expiry' 'password', 'password2','is_verified']
        
        extra_kwargs = {
            'verification_token': {'read_only': True},
            'verification_token_expiry': {'read_only': True},
        }


    def validate_email(self, value):
        if User.objects.filter(email=value).exists():
            raise serializers.ValidationError("A user with that email address already exists.")
        return value
    
    def validate_password(self, value):
        if len(value) < 8:
            raise serializers.ValidationError("Password must be at least 8 characters long.")
        return value

    def validate(self, data):
        if data['password'] != data['password2']:
            raise serializers.ValidationError("Passwords do not match.")
        return data

    def create(self, validated_data):
        validated_data.pop('password2')
        validated_data['password'] = make_password(validated_data['password'])
        return super().create(validated_data)
    
    def update(self, instance, validated_data):
        """
        Update and return an existing user instance.
        """
        instance.first_name = validated_data.get('first_name', instance.first_name)
        instance.last_name = validated_data.get('last_name', instance.last_name)
        instance.email = validated_data.get('email', instance.email)
        instance.username = validated_data.get('username', instance.username)
        instance.save()
        return instance

    
    
class ChangePasswordSerializer(serializers.Serializer):
    old_password = serializers.CharField(required=True)
    new_password = serializers.CharField(required=True)

    def validate_new_password(self, value):
        try:
            validate_password(value)  
        except ValidationError as e:
            raise serializers.ValidationError(str(e))
        return value   