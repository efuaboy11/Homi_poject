from rest_framework import status
from rest_framework.response import Response
from rest_framework.permissions import AllowAny
from .serializers import *
from rest_framework import generics, status, permissions
from .models import *
from .permission import *
from rest_framework.response import Response
from django.conf import settings
from .smpt import send_email, send_bulk_email
from datetime import timedelta
from rest_framework_simplejwt.tokens import RefreshToken
from .verification import authenticate
from rest_framework.permissions import IsAdminUser, IsAuthenticated
from rest_framework.decorators import api_view
from rest_framework.views import APIView
from rest_framework_simplejwt.views import TokenObtainPairView, TokenRefreshView  # type: ignore
from rest_framework import filters
from django.db.models import Sum, F, Q, Value
from django.db.models.functions import Coalesce
from django.template.loader import render_to_string
from datetime import datetime
from rest_framework.filters import SearchFilter
from .paystack import Paystack
@api_view(['GET'])
def endpoints(request):
    data = [
        "users/",
    ]
    return Response(data)


class ExactSearchFilter(SearchFilter):
    def get_search_terms(self, request):
        # Do not split the query by whitespace
        params = request.query_params.get(self.search_param, '')
        return [params]
    
    
    


class UsersViews(generics.ListCreateAPIView):
    permission_classes = [AllowAny]
    queryset = Users.objects.all()
    serializer_class = UsersSerializer
    filter_backends = [filters.SearchFilter]
    search_fields = ['email', 'user_name', 'full_name']
      

    def get_queryset(self):
        return Users.objects.filter(is_superuser=False)

    def post(self, request):
        reg_serializer = self.get_serializer(data=request.data)
        
        if not reg_serializer.is_valid():
            print(reg_serializer.errors)

        if reg_serializer.is_valid():
            # Access validated data only after calling .is_valid()
            email = reg_serializer.validated_data['email']
            first_name = reg_serializer.validated_data['first_name']
            
            newuser = reg_serializer.save()
            if newuser:
                return Response(reg_serializer.data, status=status.HTTP_201_CREATED)
            
            try:
                subject = "Successful Registration"
                html_content = render_to_string(
                    'email/successful_reg.html',
                    {
                        'user': first_name,
                        "login_url": "http://127.0.0.1:8000/login/",
                        "year": datetime.now().year
                    }
                )

                send_email(to_email=email, message=html_content, subject=subject)
            except Exception as e:
                return   Response(str(e), status=status.HTTP_400_BAD_REQUEST)
            
        return Response(reg_serializer.errors, status=status.HTTP_400_BAD_REQUEST)


# Update user details
class UpdateUserView(generics.RetrieveUpdateDestroyAPIView):
    queryset = Users.objects.all()
    serializer_class = UsersSerializer 
    permission_classes = [IsAuthenticated]
    lookup_field = 'id'

class ClientView(generics.CreateAPIView):
    serializer_class = ClientSerializer
    permission_classes = [AllowAny]
    queryset = Client.objects.all()
    
       
    
class StoreOwnerView(generics.ListCreateAPIView):
    serializer_class = StoreOwnersSerializer
    permission_classes = [AllowAny]
    filter_backends = [ExactSearchFilter]
    search_fields = ['store_name']
    queryset = StoreOwners.objects.all()
    


class CourierView(generics.CreateAPIView):
    serializer_class = CouriersSerializer
    filter_backends = [ExactSearchFilter]
    search_fields = ['first_name', 'last_name']
    queryset = Couriers.objects.all()
    permission_classes = [AllowAny]


    
#Request OTP
class RequestOTPView(generics.GenericAPIView):
    serializer_class = RequestOTPSerializer

    def post(self, request, *args, **kwargs):
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        email = serializer.validated_data['email']

        try:
            user = Users.objects.get(email=email)
            otp_instance = OTPGenerator.objects.create(user=user)
            otp_instance.generate_otp()
            
            subject = 'Your requested OTP code'
            user_email = user.email
            
            html_content = render_to_string(
                "email/otp.html",
                {
                    "user": user,
                    "otp_code": otp_instance.otp,
                    "expiry_minutes": 10,
                    "year": datetime.now().year
                }
            )
            
            
            success = send_email(message=html_content, to_email=user_email, subject=subject, )

            
            if success:
                return Response({'message': 'OTP sent to your email.'}, status=status.HTTP_200_OK)
            else:
                return Response({'error': 'Failed to send OTP email.'}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
        except Users.DoesNotExist:
            return Response({'error': 'User with this email does not exist.'}, status=status.HTTP_404_NOT_FOUND)





# Forgot password
class ForgotPasswordVIew(generics.GenericAPIView):
    serializer_class = ForgotPasswordSerializer

    def post(self, request, *args, **kwargs):
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)

        email = serializer.validated_data['email']
        otp = serializer.validated_data['otp']
        new_password = serializer.validated_data['new_password']

        try:
            user = Users.objects.get(email=email)
            otp_instance = OTPGenerator.objects.get(user=user, otp=otp)

            # Check if OTP has expired (older than 120 minutes)
            expiration_time = otp_instance.created_at + timedelta(minutes=120)
            if timezone.now() > expiration_time:
                return Response(
                    {'error': 'OTP has expired. Please request a new one.'},
                    status=status.HTTP_400_BAD_REQUEST
                )

            # Update user's password
            user.set_password(new_password)
            user.save()

            # Delete OTP after successful password reset
            otp_instance.delete()

        except Users.DoesNotExist:
            return Response(
                {'error': 'Invalid email or OTP.'},
                status=status.HTTP_404_NOT_FOUND
            )
        except OTPGenerator.DoesNotExist:
            return Response(
                {'error': 'Invalid OTP.'},
                status=status.HTTP_400_BAD_REQUEST
            )

        # Return success response
        return Response(
            {'message': 'Password has been reset successfully.'},
            status=status.HTTP_200_OK
        )
        
        
        
        
#Login
class LoginView(generics.GenericAPIView):
    serializer_class = LoginSerializer
    permission_classes = [AllowAny]
    authentication_classes = []
    
    def post(self, request, *args, **kwargs):
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        
        email = serializer.validated_data['email']
        otp = serializer.validated_data['otp']
        password = serializer.validated_data['password']
        
        try:
            user = Users.objects.get(email=email)
            otp_instance = OTPGenerator.objects.get(user=user, otp=otp)
            
            if DisableAccount.objects.filter(user=user).exists():
                return Response(f'Your account is disable. Please contact support ', status=status.HTTP_400_BAD_REQUEST)
            
            expiration_time = otp_instance.created_at + timedelta(minutes=120)
            if timezone.now() > expiration_time:
                return Response({'error': 'OTP has expired. Please request a new one.'}, status=status.HTTP_400_BAD_REQUEST)
            
            # Use email as the identifier for authentication
            user = authenticate(email=email, password=password)
            if user is None:
                return Response({'error': 'Invalid email or password.'}, status=status.HTTP_400_BAD_REQUEST)
            
            token_serializer = CustomTokenObtainPairSerializer(data={'email': email, 'password': password})
            token_serializer.is_valid(raise_exception=True)
            return Response(token_serializer.validated_data, status=status.HTTP_200_OK)
        except Users.DoesNotExist:
            return Response({'error': 'Invalid email or OTP.'}, status=status.HTTP_404_NOT_FOUND)
        except OTPGenerator.DoesNotExist:
            return Response({'error':  'Invalid OTP.'}, status=status.HTTP_400_BAD_REQUEST)
        
class CustomRefreshTokenView(TokenRefreshView):
    serializer_class = CustomTokenRefreshSerializer
    
    
class DisableAccountView(generics.ListCreateAPIView):
    serializer_class = DisableAccountSerializer
    permission_classes = [IsAdminUser]
    filter_backends = [ExactSearchFilter]
    search_fields = ['user__first_name', 'user__last_name', 'reason', 'disabled_at']
    
    def get_queryset(self):
        queryset = DisableAccount.objects.all()
        user_role = self.request.query_params.get('user_role')
        if(user_role):
            if(user_role == 'staff'):
                queryset = queryset.exclude(user__role__in=['student', 'hr'])
            else:
                queryset = queryset.filter(user__role=user_role)
        return queryset
    
class DisableAccountRetrieveDestory(generics.RetrieveDestroyAPIView):
    serializer_class = DisableAccountSerializer
    permission_classes = [IsAdminUser]
    queryset =   DisableAccount.objects.all()
    lookup_field = 'pk'
    
    def destroy(self, request, *args, **kwargs):
        instance = self.get_object()
        user = instance.user  # assuming DisableAccount has a ForeignKey to Users via `user`

        # Set account status back to active
        user.account_status = 'active'
        user.save()

        # Delete the DisableAccount record
        instance.delete()

        return Response({"message": "Account re-enabled and record deleted."}, status=status.HTTP_204_NO_CONTENT)
    

class ProductCategoriesView(generics.ListCreateAPIView):
    permission_classes = [AllowAny]
    serializer_class = ProductCategoriesSerializer
    filter_backends = [ExactSearchFilter]
    search_fields = ['name']
    
    def get_store_owner(self):
        """
        Helper method to fetch the Store owner instance from request.user.
        """
        user = self.request.user
        try:
            store_owner = StoreOwners.objects.get(id=user.id)  # Client inherits Users
        except StoreOwners.DoesNotExist:
            return None
        return store_owner
    
    def get_queryset(self):
        user = self.request.user
        store_owner = self.get_store_owner()
        queryset = ProductCategories.objects.all()
        store_filter = self.request.query_params.get('store_filter')
        category_filter = self.request.query_params.get('category_filter')

        # Always allow store filtering if provided
        if store_filter:
            queryset = queryset.filter(store_owner_id=store_filter)
        
        # Always allow category filtering if provided
        if category_filter:
            queryset = queryset.filter(categories_id=category_filter)

        # Role-based filtering
        if user.is_authenticated:
            if user.role == Role.STORE_OWNER:
                queryset = queryset.filter(store_owner=store_owner)
            elif user.role == Role.CLIENT:
                queryset = queryset.filter(is_active=True)
        else:
            # For anonymous users
            queryset = queryset.filter(is_active=True)

        return queryset
    
    def post(self, request, *args, **kwargs):
        user = request.user
        if not user.is_authenticated:
            return Response({"error": "You do not have permission"}, status=status.HTTP_403_FORBIDDEN)
        
        if(user.role == Role.STORE_OWNER):
            serializer = self.get_serializer(data=request.data)
            serializer.is_valid(raise_exception=True)
            serializer.save()
            return Response(serializer.data, status=status.HTTP_201_CREATED)
        else:
            return Response({"error": "You do not have permission."}, status=status.HTTP_403_FORBIDDEN)
        
        
class ProductCategoriesRetrieveUpdateDestroy(generics.RetrieveUpdateDestroyAPIView):
    serializer_class = ProductCategoriesSerializer
    permission_classes = [AllowAny]
    queryset = ProductCategories.objects.all()
    lookup_field = 'pk'
    
    
class DeleteMultipleProductCategoriesView(generics.GenericAPIView):
    permission_classes = [IsAdminOrStoreOwner]
    serializer_class = DeleteMultipleIDSerializer
    
    def post(self, request, *args, **kwargs):
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        ids = serializer.validated_data['ids']
        deleted_count, _ = ProductCategories.objects.filter(id__in=ids).delete()
        return Response({"message": f"{deleted_count} data deleted successfully."}, status=status.HTTP_204_NO_CONTENT)
    
    
    
class ProductView(generics.ListCreateAPIView):
    permission_classes = [AllowAny]
    serializer_class = ProductSerializer
    filter_backends = [ExactSearchFilter]
    search_fields = ['name', 'product_id', 'categories__name', 'store_owner__store_name', 'price',]
    
    def get_store_owner(self):
        """
        Helper method to fetch the Store owner instance from request.user.
        """
        user = self.request.user
        try:
            store_owner = StoreOwners.objects.get(id=user.id)  # Client inherits Users
        except StoreOwners.DoesNotExist:
            return None
        return store_owner
    
    
    def get_queryset(self):
        user = self.request.user
        store_filter = self.request.query_params.get('store_filter')
        queryset = Product.objects.all()
        store_owner = self.get_store_owner()
        if store_filter:
            queryset = queryset.filter(store_owner_id=store_filter)


        
        # Role-based filtering
        if user.is_authenticated:
            if user.role == Role.STORE_OWNER:
                queryset = queryset.filter(store_owner=store_owner)
            elif user.role == Role.CLIENT:
                queryset = queryset.filter(is_active=True)
        else:
            # For anonymous users
            queryset = queryset.filter(is_active=True)

        return queryset
    
    
    
    def post(self, request, *args, **kwargs):
        user = self.request.user
        if not user.is_authenticated:
            return Response({"error": "You do not have permission"}, status=status.HTTP_403_FORBIDDEN)
        
        
        if(user.role == Role.STORE_OWNER):
            serializer = self.get_serializer(data=request.data)
            serializer.is_valid(raise_exception=True)
            serializer.save()
            return Response(serializer.data, status=status.HTTP_201_CREATED)
        else:
            return Response({"error": "You do not have permission to create a notification."}, status=status.HTTP_403_FORBIDDEN)
        
        
class ProductRetrieveUpdateDestroy(generics.RetrieveUpdateDestroyAPIView):
    serializer_class = ProductSerializer
    permission_classes = [IsAdminOrStoreOwner]
    queryset = Product.objects.all()
    lookup_field = 'pk'
    
    
class DeleteMultipleProductView(generics.GenericAPIView):
    permission_classes = [IsAdminOrStoreOwner]
    serializer_class = DeleteMultipleIDSerializer
    
    def post(self, request, *args, **kwargs):
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        ids = serializer.validated_data['ids']
        deleted_count, _ = Product.objects.filter(id__in=ids).delete()
        return Response({"message": f"{deleted_count} data deleted successfully."}, status=status.HTTP_204_NO_CONTENT)

   
   
class CartView(generics.ListCreateAPIView):
    permission_classes = [IsClient]
    serializer_class = CartSerializer
    queryset = Cart.objects.all()

    def get_client(self):
        """
        Helper method to fetch the Client instance from request.user.
        """
        user = self.request.user
        try:
            client = Client.objects.get(id=user.id)  # Client inherits Users
        except Client.DoesNotExist:
            return None
        return client

    def get_queryset(self):
        client = self.get_client()
        if not client:
            return Cart.objects.none()  # Return empty queryset if not a client
        return Cart.objects.filter(user=client)

    def post(self, request, *args, **kwargs):
        client = self.get_client()
        if not client:
            return Response(
                {"error": "Only clients can add products to cart."},
                status=status.HTTP_400_BAD_REQUEST
            )

        product_id = request.data.get('product')

        if Cart.objects.filter(user=client, product_id=product_id).exists():
            return Response(
                {"error": "Product already in cart."},
                status=status.HTTP_400_BAD_REQUEST
            )

        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        serializer.save(user=client)  
        return Response(serializer.data, status=status.HTTP_201_CREATED)
    
    
class CartRetrieveUpdateDestroy(generics.RetrieveUpdateDestroyAPIView):
    permission_classes = [IsClient] 
    serializer_class = CartSerializer
    queryset = Cart.objects.all()
    lookup_field = 'pk' 
    
    
class IncreaseCartProductQuantityView(generics.GenericAPIView):
    permission_classes = [IsClient]       
    serializer_class = EditingCartItemSerializer
    
    def post(self, request, *args, **kwargs):
        user = request.user
        product_id = request.data.get('product') 
        
        try:  
            cart = Cart.objects.get(user=user, product=product_id)
            cart.quantity += 1
            cart.save()
            return Response({"message": "Product quantity increased successfully."}, status=status.HTTP_200_OK)
        except Cart.DoesNotExist:
            Cart.objects.create(user=user, product=product_id, quantity=1)
            return Response({"error": "Product added to cart"}, status=status.HTTP_200_OK)
             
    
class DecreaseCartProductQuantityView(generics.GenericAPIView):
    permission_classes = [IsClient]       
    serializer_class = EditingCartItemSerializer
    
    def post(self, request, *args, **kwargs):
        user = request.user
        product_id = request.data.get('product') 
        
        try:
            cart = Cart.objects.get(user=user,  product=product_id)
        except Cart.DoesNotExist:
            return Response({"error": "Cart item not found."}, status=status.HTTP_404_NOT_FOUND)
        
        if cart.quantity > 1:
            cart.quantity -= 1
            cart.save()
        else:
            cart.delete()
            
        return Response({"message": "Product quantity decreased successfully."}, status=status.HTTP_200_OK)
                                                                                                                                                                                      
class RemoveCartProductView(generics.GenericAPIView):
    permission_classes = [IsClient]       
    serializer_class = EditingCartItemSerializer
    
    def post(self, request, *args, **kwargs):
        user = request.user
        product_id = request.data.get('product') 
        
        try:
            cart = Cart.objects.get(user=user,  product=product_id)
        except Cart.DoesNotExist:
            return Response({"error": "Cart item not found."}, status=status.HTTP_404_NOT_FOUND)
        
        cart.delete()
        
        return Response({"message": "Product removed from cart successfully."}, status=status.HTTP_200_OK)                                                                                                                                                                                                                                
      
      
      
class CreateOrderView(APIView):
    permission_classes = [IsClient]
    
    def get_client(self):
        """
        Helper method to fetch the Client instance from request.user.
        """
        user = self.request.user
        try:
            client = Client.objects.get(id=user.id)  # Client inherits Users
        except Client.DoesNotExist:
            return None
        return client

    def post(self, request):
        serializer = CreateOrderSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)

        delivery_address = serializer.validated_data["delivery_address"]
        
        client = self.get_client()   
        cart_items = Cart.objects.filter(user=client)

        if not cart_items.exists():
            return Response(
                {"error": "Cart is empty"},
                status=status.HTTP_400_BAD_REQUEST
            )
            
        # ✅ Enforce single-store rule
        stores = cart_items.values_list('product__store_owner', flat=True).distinct()

        if stores.count() > 1:
            return Response(
                {"error": "You can only order from one store at a time"},
                status=status.HTTP_400_BAD_REQUEST
            )
            
        store_id = stores.first()
        
        store = StoreOwners.objects.get(id=store_id)

        product_data = []
        total_amount = 0

        for item in cart_items:
            price = item.product.price
            total = item.total_price

            product_data.append({
                "product_id": item.product.product_id,
                "name": item.product.name,
                "quantity": item.quantity,
                "price": float(price),
                "total_price": float(total),
            })

            total_amount += total

        reference = str(uuid.uuid4())
        email = client.email

        # ✅ Convert Naira → Kobo ONLY ONCE
        amount_in_kobo = int(total_amount * 100)

        # try:
        #     paystack_response = Paystack.initialize_payment(
        #         email=email,
        #         amount=amount_in_kobo,
        #         reference=reference
        #     )
        # except Exception as e:
        #     return Response(
        #         {"error": "Payment initialization failed", "details": str(e)},
        #         status=status.HTTP_502_BAD_GATEWAY
        #     )

        # ✅ Create order only after successful Paystack initialization
        order = Order.objects.create(
            user=client,
            products=product_data,
            total_amount=total_amount,
            status='pending',
            store= store,
            address=delivery_address,
            reference=reference,
        )

        # Optional: delete cart AFTER order created
        cart_items.delete()

        return Response({
            "message": "Order created successfully",
            "order_id": order.id,
            # "payment_url": paystack_response["data"]["authorization_url"],
            # "reference": reference,
            # "public_key": settings.PAYSTACK_PUBLIC_KEY
        
        }, status=status.HTTP_201_CREATED)     
        
        

class OrderView(generics.ListAPIView):
    permission_classes = [IsAuthenticated]
    serializer_class = OrderSerializer

    def get_queryset(self):
        user = self.request.user
        
        print("Logged in user:", self.request.user)
        print("User ID:", self.request.user.id)
        print("User role:", self.request.user.role)
        print("All Orders:", Order.objects.values("id", "user_id"))


        # CLIENT
        if user.role == "client":
            try:
                client = Client.objects.get(id=user.id)
                return Order.objects.filter(user=client)
            except Client.DoesNotExist:
                return Order.objects.none()

        # STORE OWNER
        elif user.role == "store_owner":
            try:
                store = StoreOwners.objects.get(id=user.id)
                return Order.objects.filter(store=store)
            except StoreOwners.DoesNotExist:
                return Order.objects.none()

        # COURIER
        elif user.role == "courier":
            try:
                courier = Couriers.objects.get(id=user.id)
                return Order.objects.filter(courier=courier)
            except Couriers.DoesNotExist:
                return Order.objects.none()

        # ADMIN
        elif user.role == "admin":
            return Order.objects.all()

        return Order.objects.none()
    

class AssignCourierView(generics.UpdateAPIView):
    permission_classes = [IsAdminOrStoreOwnerOrCourier]
    serializer_class = AssignCourierSerializer
    queryset = Order.objects.all()
    lookup_field = "pk"

    def update(self, request, *args, **kwargs):
        order = self.get_object()

        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)

        courier_id = serializer.validated_data["courier_id"]

        try:
            courier = Couriers.objects.get(id=courier_id)
        except Couriers.DoesNotExist:
            return Response(
                {"error": "Courier not found."},
                status=status.HTTP_404_NOT_FOUND
            )

        # ✅ Assign courier
        order.courier = courier
        order.status = "courier_assigned"
        order.save()

        return Response(
            {
                "message": "Courier assigned successfully.",
                "order_id": order.id,
                "courier_id": courier.id,
                "status": order.status,
            },
            status=status.HTTP_200_OK
        )
        
        
class UpdateOrderStatusView(generics.UpdateAPIView):
    permission_classes = [IsAdminOrStoreOwnerOrCourier]
    serializer_class = UpdateOrderStatusSerializer
    queryset = Order.objects.all()
    lookup_field = "pk"

    def update(self, request, *args, **kwargs):
        order = self.get_object()

        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)

        new_status = serializer.validated_data["status"]

        # Optional: Restrict who can update status
        if request.user.role not in ["admin", "store", "courier"]:
            return Response(
                {"error": "You do not have permission to update order status."},
                status=status.HTTP_403_FORBIDDEN
            )

        # Optional: Enforce logical status flow
        allowed_transitions = {
            "pending": ["confirmed"],
            "confirmed": ["courier_assigned"],
            "courier_assigned": ["delivering"],
            "delivering": ["completed"],
            "completed": [],
        }

        if new_status not in allowed_transitions[order.status]:
            return Response(
                {
                    "error": f"Cannot change status from '{order.status}' to '{new_status}'"
                },
                status=status.HTTP_400_BAD_REQUEST,
            )

        order.status = new_status
        order.save()

        return Response(
            {
                "message": "Order status updated successfully.",
                "order_id": order.id,
                "old_status": order.status,
                "new_status": new_status,
            },
            status=status.HTTP_200_OK,
        )