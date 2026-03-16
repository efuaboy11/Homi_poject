from django.contrib import admin
from .models import*
# Register your models here.
admin.site.site_header = "Homi_backend"
admin.site.register(Order)
admin.site.register(Cart)
admin.site.register(Client)
admin.site.register(StoreOwners)
admin.site.register(Couriers)
admin.site.register(DisableAccount)
admin.site.register(ProductCategories)
admin.site.register(Email)