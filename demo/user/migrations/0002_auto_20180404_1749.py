# Generated by Django 2.0.3 on 2018-04-04 09:49

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('user', '0001_initial'),
    ]

    operations = [
        migrations.CreateModel(
            name='Permission',
            fields=[
                ('id', models.AutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('name', models.CharField(max_length=64, unique=True)),
            ],
        ),
        migrations.CreateModel(
            name='UserPermission',
            fields=[
                ('id', models.AutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('uid', models.IntegerField()),
                ('perm_id', models.IntegerField()),
            ],
        ),
        migrations.AlterField(
            model_name='user',
            name='icon',
            field=models.ImageField(upload_to='avator/%Y/%m/%d/'),
        ),
    ]