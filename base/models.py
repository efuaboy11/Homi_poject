from django.db import models
import random
import string
from django.contrib.auth.models import AbstractBaseUser, PermissionsMixin, BaseUserManager, Group, Permission
from django.utils import timezone
import uuid
import secrets
from django.contrib.contenttypes.models import ContentType
from django.contrib.contenttypes.fields import GenericForeignKey, GenericRelation
from django.utils.translation import gettext_lazy as _


class Role(models.TextChoices):
    ADMIN = 'admin', "admin",
    CLIENT = 'client', "client"
    STORE_OWNER = 'store_owner', 'store_owner'
    COURIER = 'courier', 'courier'
    
    
class CustomAccountManager(BaseUserManager):
    def create_user(self, first_name, last_name, email,  **extra_fields):
        if not email:
            return ValueError("The Email field must be set")
        email = self.normalize_email(email)
        extra_fields.setdefault('role', Role.CLIENT)
        user = self.model(first_name=first_name, last_name=last_name, email=email,  **extra_fields)
        user.set_password(user.password)
        user.save(using=self._db)
        return user
    
    def create_superuser(self, first_name, last_name, email, password,  **extra_fields):
        extra_fields.setdefault('is_staff', True)
        extra_fields.setdefault('is_superuser', True)
        extra_fields.setdefault('role', Role.ADMIN)
        
        return self.create_user(first_name, last_name, email,  password=password, **extra_fields)
    
    
    
class  Users(AbstractBaseUser, PermissionsMixin):
    ACCOUNT_STATUS = [
        ('active', 'ACTIVE'),
        ('disabled', 'DISABLED')
    ]
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False) 
    # REQUIRED LOGIN FIELD
    email = models.EmailField(_('email address'), unique=True)
    
    # EXTRA FIELDS
    first_name = models.CharField(max_length=50, null=True, blank=True)
    last_name = models.CharField(max_length=50, null=True, blank=True)
    current_lat = models.FloatField(null=True, blank=True)
    current_lng = models.FloatField(null=True, blank=True)
    role = models.CharField(max_length=20, choices=Role.choices, default=Role.CLIENT)
    account_status = models.CharField(
        max_length=10,
        choices=ACCOUNT_STATUS,
        default='active'
    )
    
    # REQUIRED FOR DJANGO ADMIN
    is_staff = models.BooleanField(default=False)
    is_active = models.BooleanField(default=True)
    date_joined = models.DateTimeField(default=timezone.now)
    
    USERNAME_FIELD = "email"
    REQUIRED_FIELDS = ["first_name", "last_name", "role"]
    objects = CustomAccountManager()
    
    def __str__(self):
        return self.first_name
    
    
    
class Client(Users):
    city =  models.CharField(max_length=50, null=True, blank=True)
    street =  models.CharField(max_length=50, null=True, blank=True)
    apartment =  models.CharField(max_length=100, null=True, blank=True)
    
    class Meta:
        verbose_name_plural = "Client"
        
    def __str__(self):
        return f"{self.first_name} {self.last_name}"
     
    
    
    
class StoreOwners(Users):
    store_name =  models.CharField(max_length=50, null=True, blank=True)
    address = models.CharField(max_length=50, null=True, blank=True)
    decriptions =  models.TextField(max_length=200, null=True, blank=True)
    
    class Meta:
        verbose_name_plural = "Store owner"
        
    def __str__(self):
        return f"{self.first_name} {self.last_name}"
    
    
class Couriers(Users):
    address = models.CharField(max_length=50, null=True, blank=True)
    phone_number =  models.CharField(max_length=50, null=True, blank=True)
    about =  models.TextField(max_length=200, null=True, blank=True)
    
    
    class Meta:
        verbose_name_plural = "Couriers"
        
    def __str__(self):
        return f"{self.first_name} {self.last_name}"
    
    
# Disable account 
class DisableAccount(models.Model):
    user = models.ForeignKey(Users, on_delete=models.CASCADE,)
    reason = models.TextField(max_length=200, null=True, blank=True)
    disabled_at = models.DateTimeField(default=timezone.now) 
    
    def save(self, *args, **kwargs):
        user = Users.objects.get(id=self.user.id)
        user.account_status = 'disabled'
        user.save()
        super(DisableAccount, self).save(*args, **kwargs)
       
       
       
class OTPGenerator(models.Model):
    user = models.ForeignKey(Users, on_delete=models.CASCADE, )
    otp = models.CharField(max_length=6)
    created_at = models.DateTimeField(auto_now_add=True)
    
    
    def generate_otp(self):
        self.otp = str(random.randint(100000, 999999))
        self.save()
    def __str__(self):
        return f'OTP for {self.user.email} generated on {self.created_at}'
 
class ProductCategories(models.Model):
    store_owner = models.ForeignKey(StoreOwners, on_delete=models.CASCADE)
    category_id = models.CharField(max_length=100, null=True, blank=True)
    name = models.CharField(max_length=100, unique=True)
    description = models.TextField(blank=True, null=True)
    is_active = models.BooleanField(default=True)
    created_at = models.DateTimeField(auto_now_add=True)
    
    def __str__(self):
        return self.name
    
    def generate_category_id(self):
        return secrets.token_hex(8).upper()
    
    def save(self, *args, **kwargs):
        if not self.category_id:
            self.category_id = self.generate_category_id()
        super(ProductCategories, self).save(*args, **kwargs) 
        


class Product(models.Model):
    store_owner = models.ForeignKey(StoreOwners, on_delete=models.CASCADE)
    product_id = models.CharField(max_length=100, null=True, blank=True)
    categories = models.ManyToManyField(ProductCategories, related_name='products', blank=True)
    name = models.CharField(max_length=200)
    description = models.TextField(blank=True, null=True)
    price = models.DecimalField(max_digits=10, decimal_places=2)
    image = models.ImageField(upload_to='product_images/', blank=True, null=True)
    
    is_active = models.BooleanField(default=True)
    created_at = models.DateTimeField(auto_now_add=True)
    
    def __str__(self):
        return self.name
    
    def generate_product_id(self):
        return secrets.token_hex(8).upper()
    
    def save(self, *args, **kwargs):
        if not self.product_id:
            self.product_id = self.generate_product_id()
        super(Product, self).save(*args, **kwargs) 
        
        
class Cart(models.Model):
    user = models.ForeignKey(Client,on_delete=models.CASCADE)
    product = models.ForeignKey(Product, on_delete=models.CASCADE)
    quantity = models.PositiveIntegerField(default=1)
    total_price = models.DecimalField(max_digits=10, decimal_places=2, null=True, blank=True)
    date = models.DateTimeField(auto_now_add=True)
    
    def __str__(self):
        return f"{self.quantity} of {self.product.name} in {self.user.userID}'s cart"
    
    def get_total_price(self):
        price = self.product.price
        return self.quantity * price
    
    def save(self, *args, **kwargs):
        self.total_price = self.get_total_price()
        super(Cart, self).save(*args, **kwargs)
    
    
class Order(models.Model):
    STATUS_CHOICES = [
        ('pending', 'pending'),
        ('confirmed', 'Confirmed'),
        ('courier_assigned', 'Curier Assigned'),
        ('delivering', 'Delivering'),
        ('completed', 'Completed'),
    ]
    
    user =models.ForeignKey(Client, on_delete=models.CASCADE)
    products = models.JSONField(default=list)
    store = models.ForeignKey(StoreOwners, on_delete=models.CASCADE, null=True, blank=True)
    address = models.CharField(max_length=100, null=True, blank=True)
    courier = models.ForeignKey(Couriers,on_delete=models.CASCADE, null=True, blank=True)
    total_amount = models.DecimalField(max_digits=10, decimal_places=2)
    status = models.CharField(max_length=20, choices=STATUS_CHOICES, default='pending')
    reference = models.CharField(max_length=255, unique=True, null=True, blank=True)
    created_at = models.DateTimeField(default=timezone.now)
    
    def __str__(self):
        return f"Order #{self.id} - {self.user.first_name}"
    
    
class Email(models.Model):
    STATUS_CHOICES = [
        ('pending', 'Pending'),
        ('failed', 'Failed'),
        ('delivered', 'Delivered'),
    ]
    
    to = models.EmailField(blank=True, null=True)
    subject = models.CharField(max_length=500, null=True, blank=True)
    body = models.TextField(null=True, blank=True)
    delivery_status =  models.CharField(max_length=10, choices=STATUS_CHOICES, default='pending')
    date = models.DateField(auto_now_add=True)

    def __str__(self):
        return f"Email to {self.to}"
