from rest_framework import generics, serializers, views, status
from rest_framework.response import Response
from django.shortcuts import redirect
from django.contrib.auth import get_user_model, authenticate, login, logout
from django.db.models import Q

# Email sending and auth requirements
from django.utils.encoding import force_bytes
from django.utils.http import urlsafe_base64_decode, urlsafe_base64_encode
from django.contrib.sites.shortcuts import get_current_site
from django.template.loader import render_to_string
from django.core.mail import EmailMessage

# dev tools
from colorama import Fore, Style
import smtplib

# local
from writers.serializers import (
    SignupSerializer,
    WriterSerializer,
    FollowWriterSerializer,
    EmailUsernameSerializer,
    SearchWriterSerializer,
)
from writers.token import email_auth_token


def message(msg):
    print(Fore.MAGENTA, Style.BRIGHT, "\b\b[#]", Fore.RED, msg, Style.RESET_ALL)


class LoginWriterAPI(views.APIView):
    def post(self, request, *args, **kwargs):
        data = request.data
        user = authenticate(
            email=data.get("email", None), password=data.get("password", None)
        )
        if user is not None:
            login(request, user)
            message(f"{user.name} ({user.pk}) logged in.")
            serializer = WriterSerializer(user)
            return Response(status=status.HTTP_200_OK, data=serializer.data)
        message("User not found.")
        return Response(status=status.HTTP_203_NON_AUTHORITATIVE_INFORMATION)


class LogoutWriterAPI(views.APIView):
    def get(self, request, **kwargs):
        user = get_user_model().objects.get(pk=kwargs["pk"])
        message(f"{user.name} ({user.pk}) logged out. ")
        logout(request)
        return Response(status=status.HTTP_200_OK)


class UsernameAndEmails(views.APIView):
    def get(self, request, **kwargs):
        serializer = EmailUsernameSerializer(get_user_model().objects.all(), many=True)
        return Response(status=200, data=serializer.data)


class CreateWriterAPI(views.APIView):
    def post(self, request, *args, **kwargs):
        serializer = SignupSerializer(data=request.data)
        if serializer.is_valid():
            user = serializer.save()
            user.name = user.name.title()
            user.is_active = False
            user.save()
            message(f"{user.name} ({user.pk}) created an account.")

            ##### Sending Email verification mail #####
            site = get_current_site(request)
            uid = urlsafe_base64_encode(force_bytes(user.id))
            token = email_auth_token.make_token(user)
            link = "http://{}/api/writer/activate/{}/{}".format(site.domain, uid, token)
            email_subject = "Confirm your account"
            mail = render_to_string("activateMail.html", {"link": link, "user": user})
            to_email = user.email
            email = EmailMessage(
                email_subject, mail, from_email="Key Blogs", to=[to_email]
            )
            email.content_subtype = "html"
            try:
                email.send()
                message(f"Auth Email send to {user.name} ({user.pk})")
            except smtplib.SMTPAuthenticationError:
                user.is_active = True
                user.save()
                message(f"Auth Email sending failed for {user.name} ({user.pk})")
                return Response(status=status.HTTP_204_NO_CONTENT)
            return Response(status=status.HTTP_201_CREATED)
        message(serializer.errors)
        return Response(
            data=serializer.errors, status=status.HTTP_203_NON_AUTHORITATIVE_INFORMATION
        )


class ActivateWriterAPI(views.APIView):
    def get(self, request, *args, **kwargs):
        uidb64 = kwargs["uidb64"]
        token = kwargs["token"]
        try:
            uid = force_bytes(urlsafe_base64_decode(uidb64))
            user = get_user_model().objects.get(pk=uid)
        except (TypeError, ValueError, OverflowError, get_user_model().DoesNotExist):
            user = None
        if user is not None and email_auth_token.check_token(user, token):
            user.is_active = True
            message(f"{user.name} ({user.pk}) activated their account.")
            user.save()
            link = "https://blogbook.web.app/writer/setup/{}".format(user.pk)
            return redirect(link)
        message("Invalid email verification link recieved.")
        link = "https://blogbook.web.app/invalid"
        return redirect(link)


class SetupWriterAPI(views.APIView):
    def post(self, request, *args, **kwargs):
        user = get_user_model().objects.get(pk=kwargs["pk"])
        try:
            check = get_user_model().objects.get(username=request.data.get("username"))
        except (TypeError, ValueError, OverflowError, get_user_model().DoesNotExist):
            check = None
        if check is not None:
            return Response(
                status=status.HTTP_203_NON_AUTHORITATIVE_INFORMATION,
                data={"error": "Pen Name already taken."},
            )
        user.username = request.data.get("username")
        user.save()
        return Response(status=status.HTTP_200_OK)


class ManageWriterAPI(generics.RetrieveUpdateAPIView):
    serializer_class = WriterSerializer
    queryset = get_user_model().objects.all()
    lookup_field = "pk"


class DeleteWriterAPI(views.APIView):
    def post(self, request, *args, **kwargs):
        email = get_user_model().objects.get(pk=kwargs["pk"]).email
        password = request.data.get("password", None)
        user = authenticate(email=email, password=password)
        if user is not None:
            message(f"{user.name} ({user.pk}) deleted their account.")
            user.delete()
            return Response(status=status.HTTP_204_NO_CONTENT)
        return Response(status=status.HTTP_203_NON_AUTHORITATIVE_INFORMATION)


class FollowWriterAPI(views.APIView):
    def get(self, request, *args, **kwargs):
        user = get_user_model().objects.get(pk=kwargs["user_pk"])
        writer = get_user_model().objects.get(pk=kwargs["writer_pk"])
        if user in writer.followers.all():
            writer.followers.remove(user)
            user.following.remove(writer)
            message(f"{user.name} ({user.pk}) unfollowed {writer.name} ({writer.pk})")
        else:
            writer.followers.add(user)
            user.following.add(writer)
            message(f"{user.name} ({user.pk}) followed {writer.name} ({writer.pk})")
        serializer = FollowWriterSerializer(writer)
        return Response(status=status.HTTP_200_OK, data=serializer.data)


class SearchWriterAPI(views.APIView):
    def post(self, request, **kwargs):
        writer = request.data.get("username")
        bloggers = get_user_model().objects.filter(
            Q(username__contains=writer) | Q(name__contains=writer)
        )
        serializer = SearchWriterSerializer(bloggers, many=True)
        return Response(status=status.HTTP_200_OK, data=serializer.data)

    def get(self, request, **kwargs):
        bloggers = get_user_model().objects.all()
        serializer = SearchWriterSerializer(bloggers, many=True)
        return Response(status=status.HTTP_200_OK, data=serializer.data)
