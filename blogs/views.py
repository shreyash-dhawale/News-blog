from django.shortcuts import render,HttpResponse
from django.http import JsonResponse
import requests
import random
from . models import Post
from django.shortcuts import redirect
from django.core.mail import send_mail
from django.contrib.auth.hashers import make_password
from django.conf import settings
from django.contrib.auth.models import User
from django.contrib.auth import logout as django_logout
from django.contrib.auth import login, authenticate, logout
from django.contrib.auth.decorators import login_required
from django.contrib.auth.views import LoginView
from rest_framework import generics
from rest_framework.permissions import IsAdminUser
from .serializers import BlogSerializer
from rest_framework.response import Response
from rest_framework import status
from django.contrib import messages
def digipay(request):
    return render(request,'digipay.html')
def documentation(request):
    return render(request,'documentation.html')
class BlogListAPIView(generics.ListAPIView):
    queryset = Post.objects.all()
    serializer_class = BlogSerializer
    permission_classes = [IsAdminUser]
class BlogCreateAPIView(generics.CreateAPIView):
    queryset = Post.objects.all()
    serializer_class = BlogSerializer
    permission_classes = [IsAdminUser]

    def create(self, request, *args, **kwargs):
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)

        if self.request.user.is_authenticated:
            user = self.request.user
            serializer.save(user=user, username=user.username)
            return Response(serializer.data, status=status.HTTP_201_CREATED)
        else:
            return Response({"error": "You are not logged in"}, status=status.HTTP_401_UNAUTHORIZED)
class BlogUpdateAPIView(generics.UpdateAPIView):
    queryset = Post.objects.all()
    serializer_class = BlogSerializer
    permission_classes = [IsAdminUser]
    def perform_update(self, serializer):
        serializer.save()
class BlogDeleteAPIView(generics.DestroyAPIView):
    queryset = Post.objects.all()
    serializer_class = BlogSerializer
    permission_classes = [IsAdminUser]

def index(request):
    if request.user.is_authenticated :
        isAuthenticated = True
    else:
        isAuthenticated = False
    return render(request,'index.html',{'isAuthenticated':isAuthenticated})
def custom_login(request):

    isAuthenticated = request.user.is_authenticated
    if (isAuthenticated):
        return redirect('/')
    else:
        return render(request,'login.html')
def logout(request):
    django_logout(request)
    return render(request, 'index.html', {'message': 'Logged Out Successfully'})
def login_check(request):
    global username

    if request.method == "POST":
        recaptcha_response = request.POST.get('g-recaptcha-response')
        secret_key = '6Le0RJgoAAAAAGVPLP8z_zbyuQn-Kwyo4frr_t41'
        data = {
            'secret': secret_key,
            'response': recaptcha_response
        }
        response = requests.post('https://www.google.com/recaptcha/api/siteverify', data=data)
        result = response.json()

        if not result['success']:
            return render(request, 'login.html', {'message': 'Captcha Verification Failed'})


        username = request.POST.get('username').lower()
        password = request.POST.get('password')
        try:
            user = authenticate(request,username=username , password=password)
            if user is not None:
                if user.is_staff:
                    return render(request, 'login.html', {'message': 'Administrative user, please use the admin login portal for access.'})
                login(request, user)
                first_name = user.first_name
                return redirect('/dashboard')
            else:
                return render(request, 'login.html', {'message': 'Invalid Credentials'})
        except User.DoesNotExist:
            return render(request, 'login.html', {'message': 'Invalid UserName or Password.'})
    return render(request, 'login.html')
def signup(request):
    return render(request,'signup.html')
def register(request):

    if request.method == 'POST':
        recaptcha_response = request.POST.get('g-recaptcha-response')
        secret_key = '6Le0RJgoAAAAAGVPLP8z_zbyuQn-Kwyo4frr_t41'
        data = {
            'secret': secret_key,
            'response': recaptcha_response
        }
        response = requests.post('https://www.google.com/recaptcha/api/siteverify', data=data)
        result = response.json()

        if not result['success']:
            return render(request, 'signup.html', {'error': 'Captcha Verification Failed'})
        username = request.POST['username']
        password = request.POST['password']
        confpassword = request.POST['confirm_password']
        firstname = request.POST['first_name']
        lastname = request.POST['last_name']
        email = request.POST['email'].lower()

        if User.objects.filter(username=username).exists():
            return render(request, 'signup.html', {'error': 'Username Already Taken'})
        if User.objects.filter(email=email).exists():
            return render(request,'signup.html',{'error':'Email Already Exists'})


        if password == confpassword:
            # Create a new user using Django's User model
            otp = generate_otp()

        # Send OTP via email
            send_otp_email(email, otp)

        # Add OTP to session for verification
            request.session['otp'] = otp
            request.session['user_data'] = {
                'username': username,
                'password': password,
                'confpassword': confpassword,
                'firstname': firstname,
                'lastname': lastname,
                'email': email,
            }

            return render(request, 'verify_otp.html', {'email': email})

        else:
            return render(request,'signup.html',{'error':'Password and Confirm Password Fields Must Match'})
    return redirect('signup')

@login_required
def dashboard(request):
    isAuthenticated=True
    user = request.user
    firstname= user.first_name
    return render(request, 'dashboard.html', {'user': user,'first_name':firstname ,'isAuthenticated': isAuthenticated})
@login_required
def get_news(request):
    api_key = '4d52f84a8edb45efa12c23904c53c223'
    api_url = 'https://newsapi.org/v2/top-headlines'
    params = {
        'apiKey': api_key,
        'country': 'us',
    }
    try:
        # Make the request to NewsAPI.
        response = requests.get(api_url, params=params)
        data = response.json()

        # Check if the request was successful and pass the data to the template.
        if response.status_code == 200:
            return render(request, 'get_news.html', {'news_data': data})
        else:
            # Handle any errors here, such as logging or returning an error response.
            return JsonResponse({'error': 'Failed to fetch news'}, status=500)
    except Exception as e:
        # Handle exceptions here.
        return JsonResponse({'error': str(e)}, status=500)
def verify_otp(request):

    user_data = request.session.get('user_data', {})
    email = user_data.get('email', '')
    stored_otp = request.session.get('otp')

    if request.method == 'POST':
        entered_otp = request.POST.get('otp')

        if stored_otp == entered_otp:
            username = user_data.get('username', '')
            password = user_data.get('password', '')
            firstname = user_data.get('firstname', '')
            lastname = user_data.get('lastname', '')


            user = User.objects.create_user(username, email, password)
            user.first_name = firstname
            user.last_name = lastname
            user.save()
            send_otp_reg(email,username)



            # Clear the session data
            request.session.pop('user_data', None)
            request.session.pop('otp', None)

            return render(request, 'login.html', {'message': 'User Created Successfully'})

        else:
            return render(request, 'verify_otp.html', {'email': email, 'error': 'Invalid OTP'})

    return render(request, 'verify_otp.html', {'email': email})

def send_otp_email(email, otp):
    subject = 'Account Verification OTP '
    message = f'Your OTP for account verification on Daily News and Blogs is: {otp}  Do not share it with anyone.'
    from_email = 'Daily News and Blogs '+settings.EMAIL_HOST_USER
    send_mail(subject, message, from_email, [email])
def generate_otp():
    return str(random.randint(100000, 999999))
@login_required
def allblogs(request):
    posts = Post.objects.all()
    return render(request, 'blogs.html', {"posts" : posts})
@login_required
def createblog(request):
    username=request.user
    return render(request,'create_blog.html',{"username":username})
@login_required
def addblog(request):
    if request.method =="POST":
        title = request.POST.get('title')
        content = request.POST.get('content')
        username = request.POST.get('username')
        user = request.user.first_name
        post = Post(title=title,body=content,username=username,user=user)
        post.save()
        messages.success(request, 'Blog added successfully')
        return redirect('my-blogs')

    return redirect('create-blog.html')
@login_required
def posts(request, pk):
    posts = Post.objects.get(id=pk)
    return render(request, 'post_ext.html', {'posts' : posts})
@login_required
def myblogs(request):
    user = request.user
    posts = Post.objects.filter(username=user)
    return render(request, 'myblogs.html', {'posts': posts})
@login_required
def delete_blog(request, post_id):
    post = Post.objects.get(pk=post_id)
    post.delete()
    messages.success(request, 'Blog deleted successfully')
    return redirect('my-blogs')
def forgotpwd(request):
    return render(request,'forgot_password.html')
def forgotpwd_verify(request):

    if request.method =='POST':
        email = request.POST['email'].lower()
    if User.objects.filter(email=email).exists():
        otp = generate_otp()

        # Send OTP via email
        send_otp_email(email, otp)

        # Add OTP to session for verification
        request.session['otp_forgot'] = otp
        request.session['user_data_forgot'] = {
            'email': email,
        }
        return render(request,'verify_otp_forgot.html', {'email': email})
    else:
        return render(request,'forgot_password.html',{'message':'We can not find any account with the provided email'})

def verify_otp_forgot(request):

    user_data = request.session.get('user_data_forgot', {})
    email = user_data.get('email', '')
    stored_otp = request.session.get('otp_forgot')

    if request.method == 'POST':
        entered_otp = request.POST.get('otp')

        if stored_otp == entered_otp:

            request.session.pop('otp', None)

            return render(request, 'change_password.html', {'message': 'Verification Successfull Create New Password'})

        else:
            return render(request, 'verify_otp_forgot.html', {'email': email, 'error': 'Invalid OTP entered'})

    return render(request, 'verify_otp_forgot.html', {'email': email})
def change_password(request):

    user_data = request.session.get('user_data_forgot', {})
    email = user_data.get('email', '')
    name = user_data.get('first_name','')
    print(email)
    if request.method == 'POST':
        password = request.POST['new_password']
        confirm_password = request.POST['confirm_password']
        print(password)
        if password==confirm_password:

            user = User.objects.get(email=email)
            user.set_password(password)
            user.save()
            send_password_change_mail(email,name)

            return render(request,'login.html',{'message':'Password Successfully Changed'})
        else:
            return render(request,'change_password.html',{'message':'Password and Confirm Password should match'})
    return render(request,'login.html')
def send_password_change_mail(email,name):
    subject = 'Account Password Changed '
    message = f'Hi {name},\n Your Account Password Changed Successfully '
    from_email = 'Daily News and Blogs '+settings.EMAIL_HOST_USER
    send_mail(subject, message, from_email, [email])
def send_otp_reg(email,username):
    subject = 'Welcome ! Registration Successfull'
    message =f' Hi ,\n\n\n Your Registration is successfull with username {username} \n\n\n Thanks & Regards \n\n Vansh Raghav'
    from_email = 'Daily News and Blogs '+settings.EMAIL_HOST_USER
    send_mail(subject,message,from_email,[email])