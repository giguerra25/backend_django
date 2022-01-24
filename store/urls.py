from django.urls import path, include
from django.conf.urls import url
from store import views as store_views

app_name = 'store'

urlpatterns = [

    #path("", store_views.listing, name="listing"),
    path("view_product/<int:product_id>/", store_views.view_product),
    path("see_request/", store_views.see_request),
    path("user_info/", store_views.user_info),
    path("private_place/", store_views.private_place),
    path("staff_place/", store_views.staff_place),

    #url(r'^login/$', store_views.user_login, name='login'),

]