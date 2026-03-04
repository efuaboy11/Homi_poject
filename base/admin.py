from django.contrib import admin
from .models import*
# Register your models here.
admin.site.site_header = "Homi_backend"
admin.site.register(Order)
admin.site.register(Cart)