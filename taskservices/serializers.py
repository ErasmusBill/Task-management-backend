from .models import Task
from rest_framework import serializers

class TaskSerializer(serializers.ModelSerializer):
    class Meta:
        model = Task
        fields = '__all__'  
    
    def validate_title(self, value):
        """
        Validate the title field.
        """
        if len(value) < 5:
            raise serializers.ValidationError("Title must be at least 5 characters long.")
        return value

    def validate_status(self, value):
        """
        Validate the status field.
        """
        valid_statuses = [choice[0] for choice in Task.STATUS_CHOICES]
        if value not in valid_statuses:
            raise serializers.ValidationError(f"Status must be one of {valid_statuses}.")
        return value

    def validate(self, attrs):
        """
        Perform object-level validation.
        """
        if attrs.get('status') == 'completed' and not attrs.get('description'):
            raise serializers.ValidationError("A completed task must have a description.")
        return attrs
    
    def create(self, validated_data):
        """
        Create and return a new Task instance.
        """
        task = Task.objects.create(**validated_data)
        return task