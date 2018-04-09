# Generated by Django 2.0.3 on 2018-04-08 03:46

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('user', '0002_auto_20180404_1749'),
    ]

    operations = [
        migrations.CreateModel(
            name='Role',
            fields=[
                ('id', models.AutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('name', models.CharField(max_length=64, unique=True)),
            ],
        ),
        migrations.CreateModel(
            name='RolePermission',
            fields=[
                ('id', models.AutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('role_id', models.IntegerField()),
                ('perm_id', models.IntegerField()),
            ],
        ),
        migrations.RenameField(
            model_name='userpermission',
            old_name='perm_id',
            new_name='role_id',
        ),
    ]