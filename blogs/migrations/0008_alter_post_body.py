# Generated by Django 4.2.7 on 2024-02-02 08:53

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('blogs', '0007_alter_post_body'),
    ]

    operations = [
        migrations.AlterField(
            model_name='post',
            name='body',
            field=models.BinaryField(max_length=16383),
        ),
    ]