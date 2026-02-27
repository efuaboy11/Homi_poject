from django.contrib import admin
from .models import*
# Register your models here.
admin.site.site_header = ""
admin.site.register(Order)