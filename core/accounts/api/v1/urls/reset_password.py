from django.urls import path
from .. import views

urlpatterns = [
    # get user email to change the password
    path(
        "",
        views.PasswordResetRequestEmailApiView.as_view(),
        name="reset-password-request",
    ),
    # verifying token provided in the email which sent to user earlier
    path(
        "validate-token/",
        views.PasswordResetTokenValidateApiView.as_view(),
        name="reset-password-validate",
    ),
    path(
        "set-password/",
        views.PasswordResetSetNewApiView.as_view(),
        name="reset-password-confirm",
    ),
]
