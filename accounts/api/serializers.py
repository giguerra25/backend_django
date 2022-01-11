from rest_framework import serializers
from accounts.models import Account
from django.contrib.auth import authenticate


class RegistrationSerializer(serializers.ModelSerializer):
#this field is like confirm password

	password2 		= serializers.CharField(style={'input_type': 'password'}, write_only=True)
    
	class Meta:


		model = Account
		fields = ['email', 'username', 'password', 'password2']
		extra_kwargs = {
				'password': {'write_only': True}
		}

	def save(self):

		account = Account(
					email=self.validated_data['email'],
					username=self.validated_data['username']
		)
		password = self.validated_data['password']
		password2 = self.validated_data['password2']

		if password != password2:
			raise serializers.ValidationError({'password': 'Passwords must match.'})
		account.set_password(password)
		account.save()
		return account
	
 

class AccountPropertiesSerializer(serializers.ModelSerializer):

	class Meta:
		model = Account
		fields = ['pk', 'email', 'username', ]
  
  
class ChangePasswordSerializer(serializers.Serializer):

	old_password 				= serializers.CharField(required=True)
	new_password 				= serializers.CharField(required=True)
	confirm_new_password 		= serializers.CharField(required=True)

class LoginSerializer(serializers.Serializer):

	email 		= serializers.CharField(label=("email"),required=True)
	password 	= serializers.CharField(label=("password"),style={'input_type': 'password'},trim_whitespace=False,required=True)

	def validate(self, attrs):

		email = attrs.get('email')
		password = attrs.get('password')

		if email and password:
			user = authenticate(request=self.context.get('request'),
								email=email, password=password)

			if not user:
				#msg = _('Unable to log in with provided credentials.')
				#raise serializers.ValidationError(msg, code='authorization')
				raise serializers.ValidationError({'error':'Unable to log in with provided credentials.'})
		else:
			#msg = _('Must include "email" and "password".')
			#raise serializers.ValidationError(msg, code='authorization')
			raise serializers.ValidationError({'error':'Must include "email" and "password".'})

		attrs['user'] = user
		return attrs



class UserTokenSerializer(serializers.ModelSerializer):

	class Meta:
		model = Account
		fields = ['email', 'username', ]