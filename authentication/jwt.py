from rest_framework.authentication import get_authorization_header, BaseAuthentication, exceptions
from django.conf import settings
import jwt
from authentication.models import User


class JWTAuthentication(BaseAuthentication):

    def authenticate(self, request):
        auth_header = get_authorization_header(request)
        auth_data = auth_header.decode('utf-8')
        auth_token = auth_data.split(' ')

        # chaeck if token length is 2
        if len(auth_token) != 2:
            raise exceptions.AuthenticationFailed('Invalid token header')
        token = auth_token[1]

        try:
            payload = jwt.decode(
                token, 'secret', algorithms='HS256')
            username = payload['username']
            user = User.objects.get(username=username)
            return (user, token)
        except jwt.ExpiredSignatureError as e:
            raise exceptions.AuthenticationFailed('Token expired')
        except jwt.DecodeError as e:
            raise exceptions.AuthenticationFailed('Invalid token')

        return super().authenticate(request)

#define a jwt decodor


@staticmethod
def jwt_decoder(token):
    payload = jwt.decode(token, settings.SECRET_KEY)
    return payload
