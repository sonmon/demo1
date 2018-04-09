from django.shortcuts import render ,redirect

from .models import Permission,Role,RolePermission,User,UserPermission


def check_perm(perm_name):
    def wrap1(view_func):
        def wrap2(request,*args,**kwargs):
            uid = request.session.get('uid')
            if uid is None:
                # 未登录
                url  = '/user/login/'
                request = redirect(url)

            else:
                # 已登录
                user = User.objects.get(pk=uid)
                if has_perm(user.id,perm_name):
                       # 成功
                    request = view_func(request,*args,**kwargs)
                else:
                    # 失败
                    tpl_name = 'user/permission_denied.html'
                    request = render(request,tpl_name)
            return request
        return wrap2
    return wrap1


def has_perm(uid,perm_name):
    """权限检查"""
    flag = False
    try:
        arr_id_role = UserPermission.objects.filter(uid=uid).values_list(
            'role_id',flat=True,
        )
        arr_id_perm = RolePermission.objects.filter(role_id__in=arr_id_role)\
            .values_list('perm_id',flat=True)
        perm = Permission.objects.get(name__exact=perm_name)
        if perm.id in arr_id_perm:
            flag = True
    except Exception:
        pass

    return flag


def get_roles(uid):
    """获取用户拥有的角色"""
    arr_id_role = UserPermission.objects.filter(uid=uid).values_list(
        'role_id',flat=True,
    )
    roles = Role.objects.filter(id__in=arr_id_role).all()
    return roles


def get_perms(role_id):
    """获取角色拥有的权限"""
    arr_id_perm  = RolePermission.objects.filter(role_id=role_id).values_list(
        'perm_id',flat=True,
    )
    perms = Permission.objects.filter(id__in=arr_id_perm).all()
    return perms