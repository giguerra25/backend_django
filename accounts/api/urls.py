from django.urls import path, include
from accounts.api.views import (
				
				account_properties_view,
				update_account_view,
				registration_view,
				ObtainAuthTokenView,
				ChangePasswordView,
)



app_name = 'accounts'

urlpatterns = [

	path('change_password/', ChangePasswordView.as_view(), name="change_password"),
	path('login', ObtainAuthTokenView.as_view(), name="login"),
	path('properties', account_properties_view, name="properties"),
	path('properties/update', update_account_view, name="update"),
	path('register', registration_view, name="register"),
	path('', include('dj_rest_auth.urls')),

]