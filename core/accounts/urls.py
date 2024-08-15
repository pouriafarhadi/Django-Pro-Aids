from django.urls import path, include
from . import views

app_name = "accounts"

urlpatterns = [
    path("", include("django.contrib.auth.urls")),
    path("send-email/", views.send_email, name="send-email"),
    path("test/", views.test, name="test"),
    path(
        "api/v1/", include("accounts.api.v1.urls")
    ),  # This url contains urls for the custom version of authentication
    path(
        "api/v2/", include("djoser.urls")
    ),  # This url contains urls which we considered as v2 and it uses third-party djoser
    path("api/v2/", include("djoser.urls.jwt")),  # djoser JWT urls
]
