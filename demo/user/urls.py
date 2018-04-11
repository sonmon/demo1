from django.urls import path
from . import views

urlpatterns = [
    # 用户信息
    path(r'add_user/',views.add_user),
    path(r'read_user/',views.read_user),
    path(r'edit_user/',views.edit_user),
    path(r'del_user/',views.del_user),
    path(r'list_user/',views.list_user),

    # 系统登录,登出
    path(r'login/',views.login),
    path(r'logout/',views.logout),

    # 权限
    path(r'add_permission/',views.add_permission),
    path(r'read_permission/',views.read_permission),
    path(r'list_permission/',views.list_permission),
    path(r'edit_permission/',views.edit_permission),
    path(r'del_permission/',views.del_permission),

    # 角色
    path(r'add_role/', views.add_role),
    path(r'read_role/', views.read_role),
    path(r'edit_role/', views.edit_role),
    path(r'del_role/', views.del_role),
    path(r'list_role/', views.list_role),

    # 用户拥有的角色
    path(r'select_user_role/', views.select_user_role),
    path(r'list_user_role/', views.list_user_role),

    # 角色拥有的权限
    path(r'select_role_permission/', views.select_role_permission),
    path(r'list_role_permission/', views.list_role_permission),

]