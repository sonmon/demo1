import json

from django.http import JsonResponse
from django.shortcuts import render,redirect
from django.core.exceptions import ObjectDoesNotExist

from user.helper import get_roles, check_perm
from .models import User, Permission, UserPermission, Role,RolePermission


# Create your views here.


def add_user(request):
    """注册用户"""
    info = {}
    tpl_name = 'user/add_user.html'
    if request.method == 'POST':
        # 保存用户提交数据
        nickname = request.POST.get('nickname')
        if User.objects.filter(nickname__exact=nickname).exists():
            # "昵称" 存在
            info = {'error':'"昵称"存在'}
            # 显示注册页面
            return render(request,tpl_name,info)
        password = request.POST.get('password')
        password2 = request.POST.get('password2')
        if password != password2:
            # 2次密码不一样
            info = {'error': '2次密码不一致'}
            # 显示注册页面
            return render(request,tpl_name,info)
        age = request.POST.get('age')
        sex = request.POST.get('sex')
        f_in = request.FILES.get('icon')
        user = User(nickname=nickname,password=password,age=age,sex=sex)
        if f_in:
            user.icon.save(f_in.name,f_in,save=False)

        user.set_password(password)
        user.save()

        # 在session中,记录用户信息
        request.session['uid'] = user.id
        request.session['nickname'] = user.nickname

        # 跳转到用户信息
        url = '/user/read_user/?uid={}'.format(user.id)
        return redirect(url)
    else:
        # 显示注册页面
        return render(request,tpl_name,info)


def read_user(request):
    """显示用户信息"""
    info = {
        'user' :None,
        'roles':None,
    }
    uid = int(request.GET.get('uid',0))
    is_json = request.GET.get('json',None)
    try:
        user = User.objects.get(pk=uid)
        info['user'] = user
        info['roles'] = get_roles(uid)
    except Exception:
        info['error'] = '用户不存在'
    if is_json is None:
        tpl_name = 'user/read_user.html'
        response = render(request,tpl_name,info)

    else:
        response =JsonResponse(user.to_json(),safe=False)

    return response


def login(request):
    """登录"""
    info = {}
    if request.method == "POST":
        nickname = request.POST.get('nickname')
        password = request.POST.get('password')
        user = User.objects.filter(nickname__exact=nickname).first()
        if user is None:
            # "昵称"不存在
            info = {'error':'"昵称"不存在'}
        elif not user.check_password(password):
            # 密码错误
            info = {'error': '密码错误','nickname':nickname}

        else:

            request.session['uid'] = user.id
            request.session['nickname'] = user.nickname
            url = '/user/read_user/?uid={}'.format(user.id)
            return redirect(url)
    tpl_name = 'user/login.html'
    return render(request,tpl_name,info)


def logout(request):
    """登出"""
    request.session.flush()
    tpl_name = 'user/login.html'
    return render(request,tpl_name)


def edit_user(request):
    """修改用户信息"""
    info = {'user': None}
    arr_error = []
    if request.method == 'POST':
        try:
            # 用户提交
            uid = int(request.POST.get('uid',0))
            f_in = request.FILES.get('icon')
            age = int(request.POST.get('age',0))
            sex = int(request.POST.get('sex',0))
            user = User.objects.get(pk=uid)
            user.age = age
            user.sex = sex
            if f_in:
                user.icon.save(f_in.name,f_in,save=False)

            user.save()
            # 跳转到用户信息
            url = '/user/read_user/?uid={}'.format(user.id)
            return redirect(url)
        except Exception as e:
            arr_error.append(str(e))
        # 显示"修改用户信息"的界面
    if info['user'] is None:
        try:
            uid = int(request.GET.get('uid', 0))
            user = User.objects.get(pk=uid)
            info['user'] = user
        except ObjectDoesNotExist:
            arr_error.append('记录不存在')
        except Exception as e:
            arr_error.append(str(e))
    if arr_error:
        info['error'] = json.dumps(arr_error, ensure_ascii=False)
    tpl_name = 'user/edit_user.html'
    return render(request, tpl_name, info)


def list_user(request):
    """显示用户列表"""
    tpl_name = 'user/list_user.html'
    users = User.objects.all()
    info = {'users':users}
    return render(request,tpl_name,info)


def del_user(request):
    """用户删除"""
    info = {}
    arr_error = []
    try:
        if request.method == 'POST':
            # 用户提交
            uid = int(request.POST.get('uid',0))
            User.objects.get(pk=uid).delete()
            return redirect('/user/list_user/')
    except Exception as e:
        arr_error.append(str(e))
    users = User.objects.all()

    if 'users' not in info:
        info['users'] = users

    if arr_error:
        info['error'] = json.dumps(arr_error)

    tpl_name = 'user/del_user.html'

    return render(request,tpl_name,info)


def add_permission(request):
    """权限名称的增加"""
    info = {}
    tpl_name = 'user/add_permission.html'
    if request.method == 'POST':
        # 保存提交数据
        name = request.POST.get('name')
        if Permission.objects.filter(name__exact=name).exists():
            # 名称存在
            info = {'error':'"名称"存在'}
            return render(request,tpl_name,info)

        perm = Permission.objects.create(name=name)
        # 跳转到权限信息
        url = '/user/read_permission/?perm_id={}'.format(perm.id)
        return redirect(url)

    else:
        # 显示权限名称页面
        return render(request,tpl_name,info)


def read_permission(request):
    """显示权限名称信息"""
    info = {}
    tpl_name = 'user/read_permission.html'
    perm_id = int(request.GET.get('perm_id',0))
    try:
        perm = Permission.objects.get(pk=perm_id)
        info['perm'] = perm
    except Exception:
        info['error'] = '权限名称不存在'

    return render(request,tpl_name,info)


def edit_permission(request):
    """修改权限名称信息"""
    info = {'perm': None}
    arr_error = []
    tpl_name = 'user/edit_permisson.html'
    if request.method == 'POST':
        try:
            # 用户提交
            name = request.POST.get('name')
            if Permission.objects.filter(name=name).exists():
                # "权限名称"存在
                info = {'error':'"名称"存在'}
                return render(request,tpl_name,info)
            perm_id = int(request.POST.get('perm_id',0))
            perm = Permission.objects.get(pk=perm_id)
            perm.name = name
            perm.save()
            # 跳转到权限名称信息
            url = '/user/read_permission/?perm_id={}'.format(perm_id)
            return redirect(url)
        except Exception as e:
            arr_error.append(str(e))
    # 显示"修改权限名称信息"的界面
    if info['perm'] is None:
        try:
            perm_id = int(request.GET.get('perm_id',0))
            perm = Permission.objects.get(pk=perm_id)
            info['perm'] = perm
        except ObjectDoesNotExist:
            arr_error.append('记录不存在')

        except Exception as e:
            arr_error.append(str(e))

    if arr_error:
        info['error'] = json.dumps(arr_error,ensure_ascii=False)
    return render(request,tpl_name,info)


def list_permission(request):
    """显示权限名称的列表"""
    tpl_name = 'user/list_permission.html'
    perms = Permission.objects.all()
    info = {'perms':perms}
    return render(request,tpl_name,info)


def del_permission(request):
    """删除权限名称"""
    info = {}
    arr_error = []
    perm_id = None
    if request.method == "POST":
        try:
            # 用户提交
            perm_id = int(request.POST.get('perm_id',0))
            Permission.objects.filter(pk=perm_id).delete()
            return redirect('/user/list_permission/')
        except Exception as e:
            arr_error.append(str(e))

    try:
        perms = Permission.objects.all()
        if 'perms' not in info:
            info['perms'] = perms

    except Exception as e:
        arr_error.append(str(e))
    tpl_name = 'user/del_permission.html'
    return render(request,tpl_name,info)


def add_role(request):
    """增加角色"""
    info = {}
    arr_error = []
    tpl_name = 'user/add_role.html'
    if request.method == 'POST':
        # 保存提交数据
        try:
            name = request.POST.get('name')
            if Role.objects.filter(name__exact=name).exists():
                # 名称存在
                raise ValueError('"名称"存在')
            role = Role.objects.create(name=name)
            # 跳转到权限信息
            url = '/user/read_role/?role_id={}'.format(role.id)
            return redirect(url)
        except Exception as e:
            arr_error.append(str(e))
    if arr_error:
        info['error'] = json.dumps(arr_error,ensure_ascii=False)

    # 显示权限名称页面
    return render(request,tpl_name,info)


def list_role(request):
    """显示用户列表"""
    tpl_name = 'user/list_role.html'
    roles = Role.objects.all()
    info = {'roles':roles}
    return render(request,tpl_name,info)


def read_role(request):
    ''' 显示角色列表 '''
    tpl_name = 'user/list_role.html'
    roles = Role.objects.all()
    info = {'roles': roles}
    return render(request, tpl_name, info)


def edit_role(request):
    """修改角色信息"""
    info = {'role': None}
    arr_error = []
    if request.method == 'POST':
        try:
            # 用户提交
            name = request.POST.get('name')
            if Role.objects.filter(name__exact=name).exists():
                # 记录存在
                raise ValueError('记录存在')

            role_id = int(request.POST.get('role_id',0))
            role = Role.objects.get(pk=role_id)
            role.name = name
            role.save()
            # 跳转到角色信息
            url = '/user/read_role/?role_id={}'.format(role_id)
            return redirect(url)
        except ObjectDoesNotExist:
            arr_error.append(str(e))
        # 显示"修改角色信息"的界面
        if info['role'] is None:
            try:
                role_id = int(request.GET.get('role_id',0))
                role = Role.objects.get(pk=role_id)
                info['role'] = role

            except ObjectDoesNotExist:
                arr_error.append(str(e))
        if arr_error:
            info['error'] = json.dumps(arr_error,ensure_ascii=False)
        tpl_name = 'user/edit_role.html'
        return render(request,tpl_name,info)


def del_role(request):
    """角色删除"""
    info = {}
    arr_error = []
    try:
        if request.method == 'POST':
            # 用户提交
            s_id_role = request.POST.getlist('role_id')
            arr_id_role = [int(i) for i in s_id_role]
            Role.objects.filter(id_in = arr_id_role).delete()
            return redirect('/user/list_role/')
    except Exception as e:
        arr_error.append(str(e))
    roles = Role.objects.all()
    if 'roles' not in info:
        info['roles'] = roles

    if arr_error:
        info['error'] = json.dumps(arr_error)
    tpl_name = 'user/del_role.html'

    return render(request,tpl_name,info)


@check_perm('admin')
def select_user_role(requset):
    """设置用户的角色"""
    info = {
        'user': None,
        # 用户拥有的角色id
        'arr_id_role': None,
        # 全部角色
        'roles': None,
    }
    arr_error = []
    tpl_name = 'user/select_user_role.html'

    if requset.method == 'POST':
        # 保存用户提交的数据
        try:
            uid = requset.POST.get('uid')
            user = User.objects.get(pk=uid)
            # 用户选择的角色
            s_id_role = requset.POST.getlist('role_id')
            arr_id_role = set([int(s) for s in s_id_role])
            # 数据库中,之前的记录
            arr_id_role_old = set(UserPermission.objects.filter(uid=uid)\
                                  .values_list('role_id',flat=True))
            # 需要删除的角色
            arr_id_role_del = arr_id_role_old - arr_id_role
            # 需要新增的角色
            arr_id_role_add = arr_id_role - arr_id_role_old
            # 写入数据库
            if arr_id_role_del:
                UserPermission.objects.filter(
                    uid=uid,
                    role_id__in=arr_id_role_del
                ).delete()

            if arr_id_role_add:
                arr_role_add = [
                   UserPermission(uid=uid,role_id=role_id)
                    for role_id in arr_id_role_add
                ]
                UserPermission.objects.bulk_create(arr_role_add)
                # 跳转到"用户--角色"的列表页面
                url = '/user/list_user_role/?uid={}'.format(uid)
                return redirect(url)
        except Exception as e:
            arr_error.append(str(e))

    if info['user'] is None:
        try:
            uid = int(requset.GET.get('uid',0))
            user = User.objects.get(pk=uid)
            info['user'] = user
        except Exception as e:
            arr_error.append(str(e))

    if info['arr_id_role'] is None:
        try:
            arr_id_role = UserPermission.objects.filter(uid=uid)\
                .values_list('role_id',flat=True)
            info['arr_id_role'] = arr_id_role
        except Exception as e:
            arr_error.append(str(e))

    if info['roles'] is None:
        try:
            roles = Role.objects.all()
            info['roles'] = roles
        except Exception as e:
            arr_error.append(str(e))

    if arr_error:
        info['error'] = json.dumps(arr_error,ensure_ascii=False)

    return render(requset,tpl_name,info)


def list_user_role(request):
    """显示用户拥有的角色"""
    tpl_name = 'user/list_user_role.html'
    info = {}
    uid = int(request.GET.get('uid',0))
    user = User.objects.get(pk=uid)
    info['user'] = user
    arr_id_role = UserPermission.objects.filter(uid=uid).values_list(
        'role_id',flat=True,
    )
    info['roles'] = Role.objects.filter(id__in=arr_id_role).all()
    return render(request,tpl_name,info)


@check_perm('admin')
def select_role_permission(request):
    """设置角色的权限"""
    info = {
        'role': None,
        # 角色拥有的权限id
        'arr_id_perm': None,
        # 全部权限
        'perms': None,
    }
    arr_error = []
    tpl_name = 'user/select_role_permission.html'
    if request.method == 'POST':
    # 保存用户提交的数据
        try:
            role_id = int(request.POST.get('role.id',0))
            role = Role.objects.get(pk=role_id)
            # 角色选择的权限
            s_id_perm = request.POST.getlist('perm_id')
            arr_id_perm = set([int(s) for s in s_id_perm])
            arr_id_perm_old = set(
                RolePermission.objects.filter(role_id=role_id)\
                    .values_list('perm_id',flat=True)

            )
            # 需要删除的权限
            arr_id_perm_del = arr_id_perm_old - arr_id_perm
            # 需要新增的权限
            arr_id_perm_add = arr_id_perm - arr_id_perm_old

            # 写入数据库
            if arr_id_perm_del:
                RolePermission.objects.filter(
                    role_id=role_id,
                    perm_id=arr_id_perm_del,
                ).delete()
            if arr_id_perm_add:
                arr_perm_add = [
                    RolePermission(role_id=role_id,
                                   perm_id=perm_id)
                                   for perm_id in arr_id_perm_add
                ]
                RolePermission.objects.bulk_create(arr_perm_add)
            # 跳转到"角色--权限"的列表页面
            url = '/user/list_role_permission/?role_id={}'.format(role_id)
            return redirect(url)
        except Exception as e:
            arr_error.append(str(e))

        if info['role'] is None:
            try:
                role_id = int(request.GET.get('role_id',0))
                role = Role.objects.get(pk=role_id)
                info['role'] = role
            except Exception as e:
                arr_error.append(str(e))

        if info['arr_id_perm'] is None:
            try:
                arr_id_perm = RolePermission.objects.filter(role_id=role_id)\
                    .values_list('perm_id',flat=True)
                info['arr_id_perm'] = arr_id_perm
            except Exception as e:
                arr_error.append(str(e))
        if info['perms'] is None:
            perms = Permission.objects.all()
            info['perms'] = perms

        return render(request,tpl_name,info)

def list_role_permission(request):
    """显示角色所拥有的权限"""
    tpl_name = 'user/list_role_permission.html'
    info = {
        'error': None,
        'role' : None,
        'perms': None,
    }
    try:
        role_id = int(request.GET.get('role_id',0))
        role = Role.objects.get(pk=role_id)
        info['role'] = role
        arr_id_perm = RolePermission.objects.filter(role_id=role_id).values_list(
            'perm_id',flat=True,
        )
        info['perms'] = Permission.objects.filter(id__in=arr_id_perm).all()
    except Exception as e:
        info['error'] = str(e)

    return render(request,tpl_name,info)
