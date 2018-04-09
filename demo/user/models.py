from django.db import models
from django.contrib.auth.hashers import make_password,check_password
from django.core.exceptions import ObjectDoesNotExist
# Create your models here.


class User(models.Model):
    """用户信息"""
    nickname= models.CharField(max_length=128,null=False,unique=False)
    password = models.CharField(max_length=128)
    icon = models.ImageField(upload_to='avator/%Y/%m/%d/')
    age = models.IntegerField()
    sex = models.IntegerField()


    def __str__(self):
        return self.nickname

    def set_password(self,password):
        """设置密码"""
        self.password = make_password(password)

    def check_password(self,password):
        return check_password(password,self.password)

    def to_json(self):
        info = {
            'id':self.id,
            'nickname': self.nickname,
            'icon':self.icon.url,
            'age':self.age,
            'sex':self.sex,
        }
        return info
    # def add_perm(self,perm_name):
    #     """增加权限"""
    #     try:
    #         perm = Permission.objects.get(name=perm_name)
    #     except User.DoesNotExist as e:
    #         return e
    #     UserPermission.objects.get_or_create(uid=self.id,perm_id=perm.id)


class Permission(models.Model):
    """权限"""
    name = models.CharField(
        max_length=64,null=False,blank=False,unique=True,
    )

    def __str__(self):
        return self.name


class Role(models.Model):
    """角色"""
    name = models.CharField(
        max_length=64,null=False,blank=False,unique=True,
    )

    def __str__(self):
        return self.name


class UserPermission(models.Model):
    """用户--权限 关联表"""
    uid = models.IntegerField()
    role_id = models.IntegerField()

    def __str__(self):
        user = User.objects.get(pk=self.uid)
        role = Permission.objects.get(pk=self.role_id)
        return '{}-{}'.format(user.nickname,role.name)


class RolePermission(models.Model):
    """角色---权限 关联表"""
    role_id = models.IntegerField()
    perm_id = models.IntegerField()


    def __str__(self):
        role = Role.objects.get(pk=self.role_id)
        perm = Permission.objects.get(pk=self.perm_id)
        return '{}-{}'.format(role.name,perm.name)