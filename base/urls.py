from django.urls import path
from . import views

app_name = 'base'

urlpatterns = [
    path('', views.endpoints, name='endpoints'),
    path('users/', views.UsersViews.as_view(), name='users'),
    path('users/<uuid:id>/', views.UpdateUserView.as_view(), name='user_details'),
    path('request-otp/', views.RequestOTPView.as_view(), name='request-otp'),
    path('forget-password/', views.ForgotPasswordVIew.as_view(), name='verify-otp'),
    path('login/', views.LoginView.as_view(), name='login'),
    path('token/refresh/', views.CustomRefreshTokenView.as_view(), name="token_refresh"),
    path('disable-account/', views.DisableAccountView.as_view(), name='disable-account'),
    path('disable-account/<int:pk>/', views.DisableAccountRetrieveDestory.as_view(), name='disable-account-delete'),
    path('couriers/', views.CourierView.as_view(), name='couriers'),
    path('clients/', views.ClientView.as_view(), name='couriers'),
    path('store-owner/', views.StoreOwnerView.as_view(), name='couriers'),
    
    
    # Product Categories
    path('product-categories/', views.ProductCategoriesView.as_view(), name='product-categories'),
    path('product-categories/<str:pk>/', views.ProductCategoriesRetrieveUpdateDestroy.as_view(), name='individual-product-categories'),
    path('delete-multiple-product-categories/', views.DeleteMultipleProductCategoriesView.as_view(), name='delete-multiple-product-categories'),
    
    # Products
    path('product/', views.ProductView.as_view(), name='product'),
    path('product/<str:pk>/', views.ProductRetrieveUpdateDestroy.as_view(), name='individual-product'),
    path('delete-multiple-product/', views.DeleteMultipleProductView.as_view(), name='delete-multiple-product'),
    
    
    #Cart
    path('cart/', views.CartView.as_view(), name='cart'),
    path('cart/<str:pk>/', views.CartRetrieveUpdateDestroy.as_view(), name='individual-cart'),
    path('increase-cart-product-quantity/', views.IncreaseCartProductQuantityView.as_view(), name='increase-cart-product-quantity'),
    path('decrease-cart-product-quantity/', views.DecreaseCartProductQuantityView.as_view(), name='decrease-cart-product-quantity'),
    path('remove-cart-product/', views.RemoveCartProductView.as_view(), name='remove-cart-product'),
    
    #Order
    path('create-order/', views.CreateOrderView.as_view(), name='create-order'),
    path('order/', views.OrderView.as_view(), name='order'), 
    path('assign-courier/<int:pk>/', views.AssignCourierView.as_view(), name='assign-courier'), 
    path("update-order-status/<int:pk>/", views.UpdateOrderStatusView.as_view(), name="update-order-status"),
    
]
