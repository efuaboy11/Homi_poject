from .models import *
from rest_framework import serializers
from decimal import Decimal
from rest_framework_simplejwt.serializers import TokenObtainPairSerializer, TokenRefreshSerializer
from rest_framework_simplejwt.tokens import RefreshToken
from rest_framework.exceptions import AuthenticationFailed
from django.contrib.contenttypes.models import ContentType

#------------------------------------ USER ACCOUNT -----------------------------------------



class UsersSerializer(serializers.ModelSerializer):
    class Meta:
        model = Users
        fields = [
            'id',
            'first_name',
            'last_name',
            'email',
            'password',       
            'current_lat',
            'current_lng',
            'role',
            'account_status',       
        ]
        extra_kwargs = {
            'password': {'write_only': True},  
        }

    def create(self, validated_data):
        # Use set_password to hash the password
        password = validated_data.pop('password', None)
        user = super().create(validated_data)
        if password:
            user.set_password(password)
            user.save()
        return user

    def update(self, instance, validated_data):
        # Handle password update correctly
        password = validated_data.pop('password', None)
        instance = super().update(instance, validated_data)
        if password:
            instance.set_password(password)
            instance.save()
        return instance
        
        
class ClientSerializer(UsersSerializer):
    class Meta(UsersSerializer.Meta):
        model = Client  
        fields = UsersSerializer.Meta.fields + [
            'city',
            'street',
            'apartment',
        ]
        
        
class StoreOwnersSerializer(UsersSerializer):
    class Meta(UsersSerializer.Meta):
        model = StoreOwners  
        fields = UsersSerializer.Meta.fields + [
            'store_name',
            'address',
            'decriptions',
        ]
        
class CouriersSerializer(UsersSerializer):
    class Meta(UsersSerializer.Meta):
        model = Couriers
        fields = UsersSerializer.Meta.fields + [
            'address',
            'phone_number',
            'about',
        ]
        
# -------------------------------------- AUTHENTICATION --------------------------------------

    

class CustomTokenObtainPairSerializer(TokenObtainPairSerializer):
    def validate(self, attrs):
        data = super().validate(attrs)
        user = self.user
        data['role'] = user.role
        data['user_id'] = user.id
        
        return data
    
    @classmethod
    def get_token(cls, user):
        token = super().get_token(user)
        token['role'] = user.role
        token['user_id'] = str(user.id)
        
        return token
    
    
class CustomTokenRefreshSerializer(TokenRefreshSerializer):
    def validate(self, attrs):
        data = super().validate(attrs)
        refresh = RefreshToken(attrs['refresh'])
        access = refresh.access_token
        
        data['refresh'] = str(refresh)
        data['access'] = str(access)
        user_id = refresh.get('user_id')
        
        
        
        if not user_id:
            raise AuthenticationFailed('Invalid token')
        
        try:
            user = Users.objects.get(id=user_id)
        except Users.DoesNotExist:
            raise AuthenticationFailed('User not found', code='user_not_found')
        
        
        data['user_id'] = str(user.id)
        data['role'] = user.role
        
        return data 
    
    
        
# LOGIN
class LoginSerializer(serializers.Serializer):
    email = serializers.CharField()
    otp = serializers.CharField(max_length=6)
    password = serializers.CharField(write_only=True, min_length=8)
    
    
#OTP
class RequestOTPSerializer(serializers.Serializer):
    email = serializers.EmailField()
    
#FORGOT PASSWORD
class ForgotPasswordSerializer(serializers.Serializer):
    email = serializers.EmailField()
    otp = serializers.CharField(max_length=6)
    new_password = serializers.CharField(write_only=True, min_length=8)
    
    
#LOGOUT
class LogoutSerializer(serializers.Serializer):
    refresh_token  = serializers.CharField()
    
    
class DisableAccountSerializer(serializers.ModelSerializer):
    user_details = serializers.SerializerMethodField()
    class Meta:
        model = DisableAccount
        fields = [
            'id',
            'user',
            'user_details',
            'reason',
            'disabled_at',
        ]
        
    def get_user_details(self, obj):
        user = obj.user
        serializer = UsersSerializer(instance=user, many=False)
        return serializer.data
    
    
class ProductCategoriesSerializer(serializers.ModelSerializer):
    store_owner_details = serializers.SerializerMethodField()
    class Meta:
        model = ProductCategories
        fields = [
            'id',
            'category_id',
            'store_owner',
            'store_owner_details',
            'name',
            'description',
            'is_active',
            'created_at'
        ]
    def get_store_owner_details(self, obj):
        store_onwer = obj.store_owner
        serializer = StoreOwnersSerializer(instance=store_onwer, many=False)
        return serializer.data
        
        
        
class ShortProductCategoriesSerializer(serializers.ModelSerializer):
    class Meta:
        model = ProductCategories
        fields = [
            'name',
            'is_active'
        ]
        
    
class ProductSerializer(serializers.ModelSerializer):
    categories_name = serializers.SerializerMethodField()
    store_owner_details = serializers.SerializerMethodField()
    class Meta:
        model = Product
        fields = [
            'id',
            'product_id',
            'store_owner',
            'store_owner_details',
            'categories',
            'categories_name',
            'name',
            'description',
            'price',
            'image',
            'is_active',
            'created_at',
        ]
        
    def get_categories_name(self, obj):  
        categories = obj.categories
        serializer = ShortProductCategoriesSerializer(instance=categories, many=True)
        return serializer.data
    
    def get_store_owner_details(self, obj):  
        store_owner = obj.store_owner
        serializer = StoreOwnersSerializer(instance=store_owner, many=False)
        return serializer.data
    
    
    
    
    
    
class CartSerializer(serializers.ModelSerializer):
    product_details = serializers.SerializerMethodField()
    class Meta:
        model = Cart
        fields = [
            'id',
            'user',
            'product',
            'product_details',
            'quantity',
            'total_price',
            'date',
        ]
        
    def get_product_details(self, obj):  
        product = obj.product
        serializer = ProductSerializer(instance=product, many=False, context=self.context)
        return serializer.data
        
        
    def get_product_details(self, obj):  
        product = obj.product
        serializer = ProductSerializer(instance=product, many=False, context=self.context)
        return serializer.data
    
    
class EditingCartItemSerializer(serializers.Serializer):
    product = serializers.IntegerField()
    
    
class OrderSerializer(serializers.ModelSerializer):
    user_details = serializers.SerializerMethodField()
    courier_details = serializers.SerializerMethodField()
    store_details = serializers.SerializerMethodField()

    class Meta:
        model = Order
        fields = [
            'id',
            'user',
            'user_details',
            'products',
            'address',
            'courier',
            'courier_details',
            'store',
            'store_details',
            'total_amount',
            'status',
            'reference',
            'created_at',
        ]
        
    def get_user_details(self, obj):
        user = obj.user
        serializer = UsersSerializer(instance=user, many=False)
        return serializer.data
    
    def get_courier_details(self, obj):
        courier = obj.courier
        serializer = CouriersSerializer(instance=courier, many=False)
        return serializer.data
    
    def get_store_details(self, obj):
        store = obj.store
        serializer = StoreOwnersSerializer(instance=store, many=False)
        return serializer.data
    
    
class CreateOrderSerializer(serializers.Serializer):
    delivery_address = serializers.CharField()
    
    
class AssignCourierSerializer(serializers.Serializer):
    courier_id = serializers.UUIDField()

    def validate_courier_id(self, value):
        try:
            courier = Couriers.objects.get(id=value)
        except Couriers.DoesNotExist:
            raise serializers.ValidationError("Courier not found.")
        return value
    
    
class UpdateOrderStatusSerializer(serializers.Serializer):
    status = serializers.ChoiceField(choices=Order.STATUS_CHOICES)
   
   
class DeleteMultipleIDSerializer(serializers.Serializer):
    ids = serializers.ListField(
        child=serializers.IntegerField(), 
        allow_empty=False
    )
    
    def validate_ids(self, value):
        if not value:
            raise serializers.ValidationError("This field may not be empty.")
        return value
    
    
class DeleteMultipleUUIDSerializer(serializers.Serializer):
    ids = serializers.ListField(
        child=serializers.UUIDField(),  # Use UUIDField if your ID is UUID
        allow_empty=False
    )
    
    def validate_ids(self, value):
        if not value:
            raise serializers.ValidationError("This field may not be empty.")
        return value
    
    
