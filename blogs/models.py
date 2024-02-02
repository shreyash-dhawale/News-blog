from django.db import models
from django.contrib.auth.models import User
from datetime import datetime

class Post(models.Model):
    title = models.CharField(max_length = 100)
    body = models.BinaryField(max_length = 16383)
    date = models.DateTimeField(default = datetime.now, blank = True)
    user =  models.CharField(max_length = 80)
    username = models.CharField(max_length = 25)