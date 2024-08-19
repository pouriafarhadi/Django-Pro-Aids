# first write external modules installed on
import jwt
from rest_framework_simplejwt.tokens import RefreshToken
from jwt.exceptions import ExpiredSignatureError, InvalidSignatureError
from django.conf import settings
from django.contrib.sites.shortcuts import get_current_site
from django.http import HttpRequest
from django.urls import reverse
from rest_framework import generics, mixins
from rest_framework.response import Response
from rest_framework import status
from rest_framework.authtoken.views import ObtainAuthToken
from rest_framework.authtoken.models import Token
from rest_framework.permissions import IsAuthenticated
from rest_framework.views import APIView
from rest_framework_simplejwt.views import TokenObtainPairView
from django.contrib.auth import get_user_model

# then write internal (locally imports)
from ...models import Profile
from django.shortcuts import get_object_or_404
from ..utils import Util
from .serializers import (
    RegistrationSerializer,
    CustomAuthTokenSerializer,
    CustomTokenObtainPairSerializer,
    ChangePasswordSerialier,
    ProfileSerializer,
    ActivationResendSerializer,
    PasswordResetRequestEmailSerializer,
    PasswordResetTokenVerificationSerializer,
    SetNewPasswordSerializer,
)

User = get_user_model()


class RegistrationApiView(generics.GenericAPIView):
    """register a new user using email, password and password confirmation."""

    serializer_class = RegistrationSerializer

    def post(self, request, *args, **kwargs):
        serializer = RegistrationSerializer(data=request.data)
        if serializer.is_valid():
            serializer.save()
            email = serializer.validated_data["email"]
            data = {"email": email}
            user_obj = get_object_or_404(User, email=email)
            token = self.get_tokens_for_user(user_obj)
            # __ sending email __
            email_template = "email/activation_email.tpl"
            email_context = {"token": token}
            email_subject = "activate your account"
            email_from = "admin@admin.com"
            email_to = email
            Util.send_templated_email(
                template_path=email_template,
                data=email_context,
                from_email=email_from,
                to=email_to,
                subject=email_subject,
            )
            return Response(data, status=status.HTTP_201_CREATED)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

    def get_tokens_for_user(self, user):
        refresh = RefreshToken.for_user(user)
        return str(refresh.access_token)


class CustomObtainAuthToken(ObtainAuthToken):
    """
    custom CBV for getting token (parent class only returns token key)
    I wanted to get
    1.token
    2.user id
    3.email
    """

    serializer_class = CustomAuthTokenSerializer

    def post(self, request, *args, **kwargs):
        serializer = self.serializer_class(
            data=request.data, context={"request": request}
        )
        serializer.is_valid(raise_exception=True)
        user = serializer.validated_data["user"]
        token, created = Token.objects.get_or_create(user=user)
        return Response({"token": token.key, "user_id": user.pk, "email": user.email})


class CustomDiscardAuthToken(APIView):
    """
    deleting token key when user want to LOG OUT
    """

    permission_classes = [IsAuthenticated]

    def post(self, request):
        request.user.auth_token.delete()
        return Response(status=status.HTTP_204_NO_CONTENT)


class CustomTokenObtainPairView(TokenObtainPairView):
    """
    custom view for creating JWT using custom serializer
    """

    serializer_class = CustomTokenObtainPairSerializer


class ChangePasswordApiView(generics.GenericAPIView):
    """
    change password view
    """

    model = User
    permission_classes = [IsAuthenticated]
    serializer_class = ChangePasswordSerialier

    def get_object(self, queryset=None):
        obj = self.request.user
        return obj

    def put(self, request, *args, **kwargs):
        """
        check the old password and setting new password
        """
        self.object = self.get_object()
        serializer = self.get_serializer(data=request.data)
        if serializer.is_valid():
            # Check old password
            if not self.object.check_password(serializer.data.get("old_password")):
                return Response(
                    {"old_password": ["Wrong password."]},
                    status=status.HTTP_400_BAD_REQUEST,
                )
            # set_password also hashes the password that the user will get
            self.object.set_password(serializer.data.get("new_password"))
            self.object.save()
            return Response(
                {"details": "password changed successfully"},
                status=status.HTTP_200_OK,
            )
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


class PasswordResetRequestEmailApiView(generics.GenericAPIView):
    """
    This view gets the email from user and send an email with a link to reset password
    """

    serializer_class = PasswordResetRequestEmailSerializer

    def post(self, request, *args, **kwargs):
        serializer = self.serializer_class(data=request.data)
        serializer.is_valid(raise_exception=True)
        user = serializer.validated_data["user"]
        token = RefreshToken.for_user(user).access_token
        relativeLink = reverse("accounts:reset-password-validate")
        current_site = get_current_site(request=request).domain
        absurl = "http://" + current_site + relativeLink + "?token=" + str(token)
        # __ sending email __
        data = {"email": user.email, "link": absurl, "site": current_site}
        Util.send_templated_email(
            template_path="email/reset_password_template.tpl",
            data=data,
            subject="reset_password",
            from_email="admin@admin.com",
            to=user.email,
        )
        return Response(
            {"success": "We have sent you a link to reset your password"},
            status=status.HTTP_200_OK,
        )


class PasswordResetTokenValidateApiView(generics.GenericAPIView):
    """
    check if the token is valid for reset password
    """

    serializer_class = PasswordResetTokenVerificationSerializer

    def get(self, request: HttpRequest, *args, **kwargs):
        token = request.GET.get("token")

        serializer = self.serializer_class(data={"token": token})
        serializer.is_valid(raise_exception=True)
        # user = serializer.validated_data["user"]
        # print(user)
        return Response({"details": "token is valid"}, status=status.HTTP_200_OK)


class PasswordResetSetNewApiView(generics.GenericAPIView):
    """This view receive the token and new password to implement changes"""

    serializer_class = SetNewPasswordSerializer

    def patch(self, request):
        serializer = self.serializer_class(data=request.data)
        serializer.is_valid(raise_exception=True)
        return Response(
            {"detail": "Password reset successfully"}, status=status.HTTP_200_OK
        )


class ProfileApiView(generics.RetrieveUpdateAPIView):
    """
    retrieving and updating profile view
    """

    serializer_class = ProfileSerializer
    queryset = Profile.objects.all()
    permission_classes = [IsAuthenticated]

    def get_object(self):
        queryset = self.get_queryset()
        obj = get_object_or_404(queryset, user=self.request.user)
        return obj


class TestEmailSend(generics.GenericAPIView):
    """
    This is a test class for sending email using static email address (can be modified to get the email dynamically)
    Using Thread to create multiple processing in python file
    This is testing, though the read usage is in the registration CBV in this python file (RegistrationApiView)
    """

    def get(self, request, *args, **kwargs):
        self.email = "pouria.f8410@gmail.com"
        user_obj = get_object_or_404(User, email=self.email)
        token = self.get_tokens_for_user(user_obj)
        email_template = "email/hello.tpl"
        email_context = {"token": token}
        email_subject = "test email"
        email_from = "admin@admin.com"
        email_to = self.email
        Util.send_templated_email(
            template_path=email_template,
            data=email_context,
            from_email=email_from,
            to=email_to,
            subject=email_subject,
        )
        return Response("email sent")

    def get_tokens_for_user(self, user):
        refresh = RefreshToken.for_user(user)
        return str(refresh.access_token)


class ActivationApiView(APIView):
    """
    this view verifies the user
    """

    def get(self, request, token, *args, **kwargs):
        try:
            token = jwt.decode(token, settings.SECRET_KEY, algorithms=["HS256"])
            user_id = token.get("user_id")
        except ExpiredSignatureError:
            return Response(
                {"details": "token has been expired"},
                status=status.HTTP_400_BAD_REQUEST,
            )
        except InvalidSignatureError:
            return Response(
                {"details": "token is not valid"},
                status=status.HTTP_400_BAD_REQUEST,
            )
        user_obj = User.objects.get(pk=user_id)

        if user_obj.is_verified:
            return Response({"details": "your account has already been verified"})
        user_obj.is_verified = True
        user_obj.save()
        return Response(
            {"details": "your account have been verified and activated successfully"}
        )


class ActivationResendApiView(generics.GenericAPIView):
    """
    resending token for verification user
    """

    serializer_class = ActivationResendSerializer

    def post(self, request, *args, **kwargs):
        serializer = ActivationResendSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        user_obj = serializer.validated_data["user"]
        token = self.get_tokens_for_user(user_obj)
        # __ sending email __
        email_template = "email/activation_email.tpl"
        email_context = {"token": token}
        email_subject = "activate your account"
        email_from = "admin@admin.com"
        email_to = user_obj.email
        Util.send_templated_email(
            template_path=email_template,
            data=email_context,
            from_email=email_from,
            to=email_to,
            subject=email_subject,
        )
        return Response(
            {"details": "user activation resend successfully"},
            status=status.HTTP_200_OK,
        )

    def get_tokens_for_user(self, user):
        refresh = RefreshToken.for_user(user)
        return str(refresh.access_token)
