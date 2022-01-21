from django.contrib import admin
from accounts.models import Account

#code added from https://github.com/jazzband/djangorestframework-simplejwt/issues/266#issuecomment-850985081
#problem: unable to delete accounts with outstanding tokens, lack of permissions
from rest_framework_simplejwt.token_blacklist import models
from rest_framework_simplejwt.token_blacklist.admin import OutstandingTokenAdmin

class NewOutstandingTokenAdmin(OutstandingTokenAdmin):
    def has_delete_permission(self, *args, **kwargs):
        return True
admin.site.unregister(models.OutstandingToken)
admin.site.register(models.OutstandingToken, NewOutstandingTokenAdmin)


# Register your models here.
admin.site.register(Account)