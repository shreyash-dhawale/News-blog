from rest_framework import serializers
from .models import Post

class BlogSerializer(serializers.ModelSerializer):
    user = serializers.CharField(source='user.first_name', read_only=True)
    username = serializers.CharField(source='user.username', read_only=True)
    class Meta:
        model = Post
        fields = '__all__'

