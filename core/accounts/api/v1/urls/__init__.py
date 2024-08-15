from django.urls import path, include

"""
combining two url fields (.py files in this directory)
"""
urlpatterns = [
    path("", include("accounts.api.v1.urls.accounts")),
    path("profile/", include("accounts.api.v1.urls.profiles")),
]
