from django.shortcuts import render
from rest_framework.generics import GenericAPIView
from rest_framework.response import responses
from authentication.serializers import RegisterSerializer, LoginSerializer
from rest_framework import response, status, permissions
from django.contrib.auth import authenticate
from rest_framework.authentication import BasicAuthentication, SessionAuthentication

# Create your views here.


class AuthUserAPIView(GenericAPIView):

    # authentication_classes = [SessionAuthentication, BasicAuthentication]
    permission_classes = (permissions.IsAuthenticated,)

    def get(self, request):
        user = request.user
        serializer = RegisterSerializer(user)
        return response.Response({'user': serializer.data})


class RegisterAPIView(GenericAPIView):
    authentication_classes = []
    serializer_class = RegisterSerializer
    # permission_classes = []

    def post(self, request):
        user = request.data
        serializer = self.serializer_class(data=user)
        # serializer.is_valid(raise_exception=True)
        if serializer.is_valid():
            serializer.save()
            return response.Response(serializer.data, status=status.HTTP_201_CREATED)
        return response.Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


class LoginAPIView(GenericAPIView):
    serializer_class = LoginSerializer
    authentication_classes = []

    def post(self, request):
        email = request.data.get('email', '')
        password = request.data.get('password', '')

        user = authenticate(username=email, password=password)

        if user:
            serializer = self.serializer_class(user)

            return response.Response(serializer.data, status=status.HTTP_200_OK)
        return response.Response({'error': 'Invalid credentials'}, status=status.HTTP_400_BAD_REQUEST)
