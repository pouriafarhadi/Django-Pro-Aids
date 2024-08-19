from rest_framework import serializers
from rest_framework.exceptions import ValidationError, AuthenticationFailed

from ...models import User, Profile
from django.contrib.auth.password_validation import validate_password
from django.core import exceptions
from django.contrib.auth import authenticate
from django.utils.translation import gettext_lazy as _
from rest_framework_simplejwt.serializers import TokenObtainPairSerializer
import jwt
from django.conf import settings


class RegistrationSerializer(serializers.ModelSerializer):
    """
    serializer for registering new user
    """

    password1 = serializers.CharField(max_length=255, write_only=True)

    class Meta:
        model = User
        fields = ["email", "password", "password1"]

    def validate(self, attrs):
        if attrs.get("password") != attrs.get("password1"):
            raise serializers.ValidationError({"detail": "passswords doesnt match"})

        try:
            validate_password(attrs.get("password"))
        except exceptions.ValidationError as e:
            raise serializers.ValidationError({"password": list(e.messages)})

        return super().validate(attrs)

    def create(self, validated_data):
        """
        overriding create method because there is no need for password1 in create_user
        """
        validated_data.pop("password1", None)
        return User.objects.create_user(**validated_data)


class CustomAuthTokenSerializer(serializers.Serializer):
    """
    overriding AuthTokenSerializer which is used in ObtainAuthToken
    (view which uses this serializer uses ObtainAuthToken as its parent class which used AuthTokenSerializer)
    the purpose is to allow users to log in with their own EMAIL ADDRESS not username.
    """

    email = serializers.CharField(label=_("Email"), write_only=True)
    password = serializers.CharField(
        label=_("Password"),
        style={"input_type": "password"},
        trim_whitespace=False,
        write_only=True,
    )
    token = serializers.CharField(label=_("Token"), read_only=True)

    def validate(self, attrs):
        username = attrs.get("email")
        password = attrs.get("password")

        if username and password:
            user = authenticate(
                request=self.context.get("request"),
                username=username,
                password=password,
            )

            # The authenticate call simply returns None for is_active=False
            # users. (Assuming the default ModelBackend authentication
            # backend.)
            if not user:
                msg = _("Unable to log in with provided credentials.")
                raise serializers.ValidationError(msg, code="authorization")
            if not user.is_verified:
                raise serializers.ValidationError({"details": "user is not verified"})
        else:
            msg = _('Must include "username" and "password".')
            raise serializers.ValidationError(msg, code="authorization")

        attrs["user"] = user
        return attrs


class CustomTokenObtainPairSerializer(TokenObtainPairSerializer):
    """
    using custom serializer to add some extra data to validated data as well as checking if the user is verified
    """

    def validate(self, attrs):
        validated_data = super().validate(attrs)
        if not self.user.is_verified:
            raise serializers.ValidationError({"details": "user is not verified"})
        validated_data["email"] = self.user.email
        validated_data["user_id"] = self.user.id
        return validated_data


class ChangePasswordSerialier(serializers.Serializer):
    """
    serializer for changing password and validate new password
    """

    old_password = serializers.CharField(required=True)
    new_password = serializers.CharField(required=True)
    new_password1 = serializers.CharField(required=True)

    def validate(self, attrs):
        if attrs.get("new_password") != attrs.get("new_password1"):
            raise serializers.ValidationError({"detail": "passswords doesnt match"})

        try:
            validate_password(attrs.get("new_password"))
        except exceptions.ValidationError as e:
            raise serializers.ValidationError({"new_password": list(e.messages)})

        return super().validate(attrs)


class ProfileSerializer(serializers.ModelSerializer):
    """
    serializer for profile view
    """

    email = serializers.CharField(source="user.email", read_only=True)

    class Meta:
        model = Profile
        fields = (
            "id",
            "email",
            "first_name",
            "last_name",
            "image",
            "description",
        )
        read_only_fields = ["email"]


class ActivationResendSerializer(serializers.Serializer):
    """
    using serializer for validating the email and manage browsable API
    """

    email = serializers.EmailField(required=True)

    def validate(self, attrs):
        email = attrs.get("email")
        try:
            user_obj = User.objects.get(email=email)
        except User.DoesNotExist:
            raise serializers.ValidationError({"detail": "user does not exist"})
        if user_obj.is_verified:
            raise serializers.ValidationError(
                {"detail": "user is already activated and verified"}
            )
        attrs["user"] = user_obj
        return super().validate(attrs)


class PasswordResetRequestEmailSerializer(serializers.Serializer):
    """
    serializer to validate the email whether if the related user exists
    """

    email = serializers.EmailField(min_length=2)

    class Meta:
        fields = ["email"]

    def validate(self, attrs):
        try:
            user = User.objects.get(email=attrs["email"])
        except User.DoesNotExist:
            raise ValidationError({"detail": "There is no user with provided email"})
        attrs["user"] = user
        return super().validate(attrs)


class PasswordResetTokenVerificationSerializer(serializers.ModelSerializer):
    """
    serializer for validating changing password token (provided in email which is sent before)
    """

    token = serializers.CharField(max_length=600)

    class Meta:
        model = User
        fields = ["token"]

    def validate(self, attrs):
        token = attrs["token"]
        try:
            payload = jwt.decode(token, settings.SECRET_KEY, algorithms=["HS256"])
            user = User.objects.get(id=payload["user_id"])
        except jwt.ExpiredSignatureError:
            return ValidationError({"detail": "Token expired"})
        except jwt.exceptions.DecodeError:
            raise ValidationError({"detail": "Token invalid"})

        attrs["user"] = user
        return super().validate(attrs)


class SetNewPasswordSerializer(serializers.Serializer):
    """
    Serializer for setting new password
    """

    token = serializers.CharField(max_length=600)
    password = serializers.CharField(min_length=6, max_length=68, write_only=True)
    password1 = serializers.CharField(min_length=6, max_length=68, write_only=True)

    class Meta:
        fields = ["password", "password1", "token"]

    def validate(self, attrs):
        if attrs["password"] != attrs["password1"]:
            raise serializers.ValidationError({"details": "Passwords does not match"})
        try:
            password = attrs.get("password")
            token = attrs.get("token")
            payload = jwt.decode(token, settings.SECRET_KEY, algorithms=["HS256"])
            user = User.objects.get(id=payload["user_id"])
            user.set_password(password)
            user.save()

            return super().validate(attrs)
        except Exception:
            raise AuthenticationFailed("The reset link is invalid", 401)
