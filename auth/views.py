from rest_framework import views, status
from rest_framework.response import Response
from rest_framework_simplejwt.tokens import RefreshToken

from django.contrib.auth import get_user_model, authenticate, login, logout
from django.utils.http import urlsafe_base64_decode
from django.utils.encoding import force_bytes
from django.shortcuts import redirect
from django.conf import settings
from django.urls import reverse

from writers.serializers import WriterSerializer, SignupSerializer
from writers.views import message

from auth.token import email_auth_token
from auth.utils import send_email


class SignUpView(views.APIView):
    def post(self, request, *args, **kwargs):
        serializer = SignupSerializer(data=request.data)
        if serializer.is_valid():
            user = serializer.save()
            user.name = user.name.title()
            user.is_active = False
            user.save()
            message(f"{user.name} ({user.pk}) created an account.")

            # START: send email auth mail
            token = RefreshToken.for_user(user).access_token
            link = f"""{settings.API_URL}{reverse("verify_email")}?token={token}"""
            status_code = send_email(
                {
                    "email_subject": "Confirm your email",
                    "email_file": "mails/confirm_mail.html",
                    "email_data": {"token_link": link},
                },
                user,
                "Email auth",
            )
            if not status_code == 201:
                user.is_active = True
                user.save()
            return Response(status=status_code)
            # END: send email auth mail

        message(serializer.errors)
        return Response(
            data=serializer.errors, status=status.HTTP_203_NON_AUTHORITATIVE_INFORMATION
        )


class SignInView(views.APIView):
    def post(self, request, *args, **kwargs):
        data = request.data
        user = authenticate(
            username=data.get("email", None), password=data.get("password", None)
        )
        if user is not None:
            login(request, user)
            message(f"{user.name} ({user.pk}) logged in.")
            serializer = WriterSerializer(user)
            return Response(status=status.HTTP_200_OK, data=serializer.data)
        message("User not found.")
        return Response(status=status.HTTP_203_NON_AUTHORITATIVE_INFORMATION)


class SignOutView(views.APIView):
    def get(self, request, **kwargs):
        user = get_user_model().objects.get(pk=kwargs["pk"])
        message(f"{user.name} ({user.pk}) logged out. ")
        logout(request)
        return Response(status=status.HTTP_200_OK)


class VerifyEmailView(views.APIView):
    def get(self, request, *args, **kwargs):
        try:
            uid = force_bytes(urlsafe_base64_decode(kwargs["uidb64"]))
            print(int.from_bytes(urlsafe_base64_decode(kwargs["uidb64"])))
            user = get_user_model().objects.get(pk=uid)
        except (TypeError, ValueError, OverflowError, get_user_model().DoesNotExist):
            user = None
        if user is not None and email_auth_token.check_token(user, kwargs["token"]):
            user.is_active = True
            message(f"{user.name} ({user.pk}) activated their account.")
            user.save()
            link = f"{settings.CLIENT_URL}/emailverify/success/{user.pk}/"
            return redirect(link)
        message("Invalid email verification link recieved.")
        link = f"{settings.CLIENT_URL}/emailverify/error/"
        return redirect(link)
