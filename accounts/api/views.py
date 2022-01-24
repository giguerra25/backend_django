from rest_framework import status
from rest_framework.response import Response
from rest_framework.decorators import (
								api_view, 
								permission_classes, 
								authentication_classes,)
from rest_framework.permissions import IsAuthenticated
from rest_framework.authentication import TokenAuthentication
from rest_framework.views import APIView
from rest_framework.generics import (
									UpdateAPIView,
									ListAPIView,)
from django.contrib.sessions.models import Session
from datetime import datetime
from django.contrib.auth import authenticate, logout
from django.utils.decorators import method_decorator
from accounts.api.serializers import (
                                    AccountPropertiesSerializer, 
                                        RegistrationSerializer,
                                        ChangePasswordSerializer,
										LoginSerializer,
										UserTokenSerializer,)
from accounts.models import Account
from rest_framework.authtoken.models import Token
from rest_framework.authtoken.views import ObtainAuthToken
from drf_yasg import openapi
from drf_yasg.utils import swagger_auto_schema
from dj_rest_auth.views import LogoutView


description_messages={
'register':"""This endpoint creates a new user. The client application should ensure the password is double checked to ensure
user does not enter mismatching password and also ensure the email address field is checked using regular
expressions to ensure it's an email address.""",
'account_propierties': "This endpoint requires log-in access. It's used to get data account of an user",
'login':"This endpoint logs in a user",
'logout':"This endpoint logs out a user who's logged in",
'update_account':"This endpoint updates a user's account",
'change_password':"This endpoint resets a user's password",
}


# Register
# Response: https://gist.github.com/mitchtabian/c13c41fa0f51b304d7638b7bac7cb694
# Url: https://<your-domain>/api/accounts/register
@swagger_auto_schema(
	method='post', 
	operation_description=description_messages['register'],
	request_body=RegistrationSerializer,
	responses={'200': 'That email/username is already in use.',
				'201': openapi.Response('Successfully registered new user.',
				examples={"application/json": {
										"response": "successfully registered new user.",
										"email": "user12@lab.com",
										"username": "user12",
										"pk": 16,
										"token": "7418d9a1197600e2cc326b1ee39cf9a556eed2eb"}},),
				'400': 'Bad or missing parameters or content-type not specified as application/json',})
@api_view(['POST', ])
@permission_classes([])
@authentication_classes([])
def registration_view(request):

	if request.method == 'POST':
		data = {}
		email = request.data.get('email', '0').lower()
		if validate_email(email) != None:
			data['error_message'] = 'That email is already in use.'
			data['response'] = 'Error'
			return Response(data, status=status.HTTP_200_OK)

		username = request.data.get('username', '0')
		if validate_username(username) != None:
			data['error_message'] = 'That username is already in use.'
			data['response'] = 'Error'
			return Response(data, status=status.HTTP_200_OK)

		serializer = RegistrationSerializer(data=request.data)
		
		if serializer.is_valid():
			account = serializer.save()
			data['response'] = 'successfully registered new user.'
			data['email'] = account.email
			data['username'] = account.username
			data['pk'] = account.pk
			token = Token.objects.get(user=account).key
			data['token'] = token
			return Response(data, status=status.HTTP_201_CREATED)
		else:
			data = serializer.errors
			return Response(data, status=status.HTTP_400_BAD_REQUEST)

def validate_email(email):
	account = None
	try:
		account = Account.objects.get(email=email)
	except Account.DoesNotExist:
		return None
	if account != None:
		return email

def validate_username(username):
	account = None
	try:
		account = Account.objects.get(username=username)
	except Account.DoesNotExist:
		return None
	if account != None:
		return username
  

# Account properties
# Response: https://gist.github.com/mitchtabian/4adaaaabc767df73c5001a44b4828ca5
# Url: http://127.0.0.1:8000/api/accounts/
# Headers: Authorization: Token <token>
@swagger_auto_schema(
	method='get',
	operation_description=description_messages['account_propierties'],
	responses={'200': AccountPropertiesSerializer,
				'404': openapi.Response(
							description='Token not found in database',
							examples={"application/json": 
										{
											"detail": "Invalid token."
										}
									}
										),})
@api_view(['GET', ])
@permission_classes((IsAuthenticated, ))
def account_properties_view(request):
    
    try:
        account = request.user
    except Account.DoesNotExist:
        return Response(status=status.HTTP_404_NOT_FOUND)
    
    if request.method == 'GET':
        serializer = AccountPropertiesSerializer(account)
        return Response(serializer.data, status=status.HTTP_200_OK)



# Account update properties
# Url: https://<your-domain>/api/account/properties/update
# Headers: Authorization: Token <token>
@swagger_auto_schema(
	method='put',
	operation_description=description_messages['update_account'],
	request_body=AccountPropertiesSerializer,
	responses={'200': openapi.Response(
							description='Update success',
							examples={"application/json": 
										{
											"response": "Account update success"
										}
									}
										),
				'400': 'bad or missing parameters or content-type not specified as application/json',
				'404': 'Token not found in database',})   
@api_view(['PUT', ])
@permission_classes((IsAuthenticated, ))
def update_account_view(request):
    
    try:
        account = request.user
    except Account.DoesNotExist:
        return Response(status=status.HTTP_404_NOT_FOUND)
    
    if request.method == 'PUT':
        serializer = AccountPropertiesSerializer(account, data=request.data)
        data = {}
        if serializer.is_valid():
            serializer.save()
            data['response'] = "Account update success"
            return Response(data=data, status=status.HTTP_200_OK)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

'''
# LOGIN
# URL: http://127.0.0.1:8000/api/accounts/login
class ObtainAuthTokenView(APIView):

	authentication_classes = []
	permission_classes = []

	@swagger_auto_schema(
		operation_description=description_messages['login'],
		request_body= LoginSerializer,
		responses={'200': openapi.Response(
							description='login was successful',
							examples={"application/json": 
										{
											"response": "Successfully authenticated.",
											"pk": 14,
											"email": "user10@lab.com",
											"token": "01505e913152ddfac3b170b48a44db0d5883b4f9"
										}
									}
										),
					'400': openapi.Response(
							description='bad or missing parameters or content-type not specified as application/json',
							examples={"application/json": 
										{
											"response": "Error",
											"error_message": "Invalid credentials"
										}
									}
										),
		}
	)
	def post(self, request):
		context = {}

		email = request.POST.get('email') 
		password = request.POST.get('password')
		account = authenticate(email=email, password=password)
		if account:
			try:
				token = Token.objects.get(user=account)
			except Token.DoesNotExist:
				token = Token.objects.create(user=account)
			context['response'] = 'Successfully authenticated.'
			context['pk'] = account.pk
			context['email'] = email.lower()
			context['token'] = token.key

			return Response(context, status=status.HTTP_200_OK)
		else:
			context['response'] = 'Error'
			context['error_message'] = 'Invalid credentials'

			return Response(context, status=status.HTTP_400_BAD_REQUEST)


@method_decorator(name='get', decorator=swagger_auto_schema(auto_schema=None))
@method_decorator(name='post', 
				decorator=swagger_auto_schema(
							operation_description=description_messages['logout'],
							responses={'200': openapi.Response(
												description='logout was successful',
												examples={"application/json": 
															{
																"detail": "Successfully logged out."
															}
														}
															),
										}
											)
					)
class LogoutView(LogoutView):
	
	authentication_classes = (TokenAuthentication,)
	permission_classes = (IsAuthenticated,)
'''


# LOGIN
# URL: http://127.0.0.1:8000/api/accounts/login
class LoginView(ObtainAuthToken):
	
	serializer_class = LoginSerializer

	@swagger_auto_schema(
		operation_description=description_messages['login'],
		#request_body= LoginSerializer,
		responses={'201': openapi.Response(
							description='login was successful',
							examples={"application/json": 
										{
											"token": "c89e8ab9abadfde6df61169fdc3ccc777a1dbf49",
											"user": {
												"email": "user9@lab.org",
												"username": "user9"
											},
											"message": "Successfully authenticated."
										}
									}
										),
					'400': openapi.Response(
							description='bad or missing field "email" / "password"',
							examples={"application/json": 
										{
											'error':'Unable to log in with provided credentials. or Must include "email" and "password".',
										}
									}
										),
					'401': openapi.Response(
							description='User is not activated',
							examples={"application/json": 
										{
											'error': 'This user cannot start session'
										}
									}
										),
		}
	)
	def post(self, request, *args, **kwargs):

		login_serializer = self.serializer_class(data=request.data, context={'request':request})
		#print(login_serializer.is_valid())

		if login_serializer.is_valid():
			user = login_serializer.validated_data['user']
			
			if user.is_active:
				token, created = Token.objects.get_or_create(user=user)
				user_serializer = UserTokenSerializer(user)
				if created:
					return Response({
						'token' : token.key,
						'user' : user_serializer.data,
						'message': 'Successfully authenticated.'
					}, status=status.HTTP_201_CREATED)
				else:
					#delete the actual token for security reasons
					token.delete()	
					token = Token.objects.create(user=user)
					return Response({
						'token' : token.key,
						'user' : user_serializer.data,
						'message': 'Successfully authenticated.'
					}, status=status.HTTP_201_CREATED)	
			else:
				return Response({'error': 'This user cannot start session'}, 
									status=status.HTTP_401_UNAUTHORIZED)
		else:
			return Response(login_serializer.errors, 
									status=status.HTTP_400_BAD_REQUEST)
		
# LOGOUT
# URL: http://127.0.0.1:8000/api/accounts/logout

@method_decorator(name='post', 
				decorator=swagger_auto_schema(
							operation_description=description_messages['logout'],
							request_body= openapi.Schema(
											type=openapi.TYPE_OBJECT,
											title="Logout request",
											required=["token"], 
											properties={
													'token': openapi.Schema(type=openapi.TYPE_STRING, 
																			#description='string', 
																			title="token",
																			),
														}
														),
							responses={'200': openapi.Response(
												description='logout was successful',
												examples={"application/json": 
															{
																'session_message': 'user sessions deleted',
																'token_message': 'Token deleted',
															}
														}
															),
										'400': openapi.Response(
												description='Invalid token in request',
												examples={"application/json": 
															{
																'error': 'User not founded with given credentials'
															}
														}
															),
										'409': openapi.Response(
												description='Missing token in request',
												examples={"application/json": 
															{
																'error': 'Token not founded in the request'
															}
														}
															),
										}
											)
					)
class LogoutView(APIView):
	
	def post(self, request, *args, **kwargs):
		
		try:
			token = request.POST.get('token')
			token = Token.objects.filter(key = token).first()

			if token:
				user = token.user
				#destroy token and session
				all_sessions = Session.objects.filter(expire_date__gte = datetime.now())
				if all_sessions.exists():
					for session in all_sessions:
						session_data = session.get_decoded()
						if user.id == int(session_data.get('_auth_user_id')):
							session.delete()
				token.delete()
				session_message = 'user sessions deleted'
				token_message = 'Token deleted'
				return Response({'token_message': token_message, 'session_message': session_message},
								status=status.HTTP_200_OK)
				
			return Response({'error': 'User not founded with given credentials'}, 
									status=status.HTTP_400_BAD_REQUEST)
		
		except:
			return Response({'error': 'Token not founded in the request'}, 
								status=status.HTTP_409_CONFLICT)




# CHANGE_PASSWORD
# URL: http://127.0.0.1:8000/api/accounts/change_password/

@method_decorator(name='patch', decorator=swagger_auto_schema(auto_schema=None))
@method_decorator(name='put', 
				decorator=swagger_auto_schema(
							operation_description=description_messages['change_password'],
							request_body= ChangePasswordSerializer,
							responses={'200': openapi.Response(
												description='password was changed successfully',
												examples={"application/json": 
															{
																"response": "successfully changed password",
															}
														}
															),
										'400': openapi.Response(
												description='bad or missing parameters or content-type not specified as application/json',
												examples={"application/json": 
															{
																"error":{"old_password": "Wrong password.",
																"new_password": "New passwords must match"}
															}
														}
															),
										}
											)
				)
class ChangePasswordView(UpdateAPIView):

	"""
	
	"""

	serializer_class = ChangePasswordSerializer
	model = Account
	permission_classes = (IsAuthenticated,)
	authentication_classes = (TokenAuthentication,)

	def get_object(self, queryset=None):
		obj = self.request.user
		return obj

	def update(self, request, *args, **kwargs):
		"""
		
		"""
		self.object = self.get_object()
		serializer = self.get_serializer(data=request.data)

		if serializer.is_valid():
			# Check old password
			if not self.object.check_password(serializer.data.get("old_password")):
				return Response({"old_password": "Wrong password."}, status=status.HTTP_400_BAD_REQUEST)

			# confirm the new passwords match
			new_password = serializer.data.get("new_password")
			confirm_new_password = serializer.data.get("confirm_new_password")
			if new_password != confirm_new_password:
				return Response({"new_password": "New passwords must match"}, status=status.HTTP_400_BAD_REQUEST)

			# set_password also hashes the password that the user will get
			self.object.set_password(serializer.data.get("new_password"))
			self.object.save()
			return Response({"response":"successfully changed password"}, status=status.HTTP_200_OK)

		return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)



@api_view(['GET', ])
@permission_classes([])
@authentication_classes([])
def does_account_exist_view(request):

	if request.method == 'GET':
		email = request.GET['email'].lower()
		data = {}
		try:
			account = Account.objects.get(email=email)
			data['response'] = email
		except Account.DoesNotExist:
			data['response'] = "Account does not exist"
		return Response(data)	