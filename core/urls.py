
from django.contrib import admin
from django.urls import path, include, re_path
from django.contrib.auth import views as auth_views
from rest_framework import permissions
from drf_yasg.views import get_schema_view
from drf_yasg import openapi

from accounts.views import registration_view, login_view, logout_view
from store import views as store_views


schema_view = get_schema_view(
   openapi.Info(
      title="API doc",
      default_version='v0.1',
      description="Test description",
      terms_of_service="https://www.google.com/policies/terms/",
      contact=openapi.Contact(email="gabriel.guerra25@outlook.com"),
      license=openapi.License(name="BSD License"),
   ),
   public=True,
   permission_classes=(permissions.AllowAny,),
)



urlpatterns = [


    path('admin/', admin.site.urls),
    path('', store_views.HomeView.as_view(), name='home'),

    #Store
    path('store/', include('store.urls', 'store')),
    path('register/', registration_view, name="register"),
    path('login/', login_view, name="login"),
    path('logout/', logout_view, name="logout"),
    #path("private_place/", store_views.private_place, name="private"),
    #path("list_products/", store_views.listing, name="listing"),
    
    # REST-framework
    path('api/accounts/', include('accounts.api.urls', 'accounts_api')),
    
    #path('auth/', include('dj_rest_auth.urls')),
    #path("accounts/", include("django.contrib.auth.urls")),

    #reset password like https://github.com/mitchtabian/CodingWithMitchBlog-REST-API/blob/master/src/mysite/urls.py

   path('password_change/done/', auth_views.PasswordChangeDoneView.as_view(template_name='registration/password_change_done.html'), 
        name='password_change_done'),

    path('password_change/', auth_views.PasswordChangeView.as_view(template_name='registration/password_change.html'), 
        name='password_change'),

    path('password_reset/done/', auth_views.PasswordResetCompleteView.as_view(template_name='registration/password_reset_done.html'),
     name='password_reset_done'),

    path('reset/<uidb64>/<token>/', auth_views.PasswordResetConfirmView.as_view(), name='password_reset_confirm'),
    path('password_reset/', auth_views.PasswordResetView.as_view(), name='password_reset'),
    
    path('reset/done/', auth_views.PasswordResetCompleteView.as_view(template_name='registration/password_reset_complete.html'),
     name='password_reset_complete'),




    #Swagger
    re_path(r'^swagger(?P<format>\.json|\.yaml)$', schema_view.without_ui(cache_timeout=0), name='schema-json'),
    path('swagger/', schema_view.with_ui('swagger', cache_timeout=0), name='schema-swagger-ui'),
    path('redoc/', schema_view.with_ui('redoc', cache_timeout=0), name='schema-redoc'),

    
]
