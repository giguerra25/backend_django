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
from django.contrib.auth import authenticate, logout
from accounts.api.serializers import (
                                    AccountPropertiesSerializer, 
                                        RegistrationSerializer,
                                        ChangePasswordSerializer,)
from accounts.models import Account
from rest_framework.authtoken.models import Token
from drf_yasg import openapi
from drf_yasg.utils import swagger_auto_schema



description_messages={
'register':"""This endpoint creates a new user. The client application should ensure the password is double checked to ensure
user does not enter mismatching password and also ensure the email address field is checked using regular
expressions to ensure it's an email address.""",
'account_propierties': "This endpoint requires log-in access. It's used to get data account of an user",
'update_account':"This endpoint updates a user's account",
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
	responses={'200': 'Not message implemented',
				'404': 'Not message implemented',})
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
    
@swagger_auto_schema(
	method='put',
	operation_description=description_messages['update_account'],
	request_body=AccountPropertiesSerializer,
	responses={'200': 'Account update success',
				'400': 'Not message implemented',
				'404': 'Not message implemented',})   
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


# LOGIN
# Response: https://gist.github.com/mitchtabian/8e1bde81b3be342853ddfcc45ec0df8a
# URL: http://127.0.0.1:8000/api/accounts/login
class ObtainAuthTokenView(APIView):

	authentication_classes = []
	permission_classes = []

	def post(self, request):
		context = {}

		email = request.POST.get('username')
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


class ChangePasswordView(UpdateAPIView):

	"""
	Classe ChangePasswordView
	"""

	serializer_class = ChangePasswordSerializer
	model = Account
	permission_classes = (IsAuthenticated,)
	authentication_classes = (TokenAuthentication,)

	def get_object(self, queryset=None):
		obj = self.request.user
		return obj

	def update(self, request, *args, **kwargs):

		"""Method put"""
		self.object = self.get_object()
		serializer = self.get_serializer(data=request.data)

		if serializer.is_valid():
			# Check old password
			if not self.object.check_password(serializer.data.get("old_password")):
				return Response({"old_password": ["Wrong password."]}, status=status.HTTP_400_BAD_REQUEST)

			# confirm the new passwords match
			new_password = serializer.data.get("new_password")
			confirm_new_password = serializer.data.get("confirm_new_password")
			if new_password != confirm_new_password:
				return Response({"new_password": ["New passwords must match"]}, status=status.HTTP_400_BAD_REQUEST)

			# set_password also hashes the password that the user will get
			self.object.set_password(serializer.data.get("new_password"))
			self.object.save()
			return Response({"response":"successfully changed password"}, status=status.HTTP_200_OK)

		return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)