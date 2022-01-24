from django.urls import path, include
from accounts.api.views import (
				
				account_properties_view,
				update_account_view,
				registration_view,
				#ObtainAuthTokenView,
				ChangePasswordView,
				LogoutView,
				LoginView,
				does_account_exist_view
				#MyLogoutView,
)


app_name = 'accounts'

urlpatterns = [

	path('check_if_account_exists/', does_account_exist_view, name="check_if_account_exists"),

	path('change_password/', ChangePasswordView.as_view(), name="change_password"),
	#path('login/', ObtainAuthTokenView.as_view(), name="login"),
	path('login/', LoginView.as_view(), name="login"),
	path('properties/', account_properties_view, name="properties"),
	path('properties/update/', update_account_view, name="update"),
	path('register/', registration_view, name="register"),
	path('logout/', LogoutView.as_view(), name="logout"),
	
]