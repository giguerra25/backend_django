from django.urls import path, include
from store import views as store_views

urlpatterns = [

    path("list_products/", store_views.listing, name="listing"),
    path("view_product/<int:product_id>/", store_views.view_product, name="view_product"),
    path("see_request/", store_views.see_request),
    path("user_info/", store_views.user_info),
    path("private_place/", store_views.private_place),
    path("staff_place/", store_views.staff_place),


]