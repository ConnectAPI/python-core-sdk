from urllib.parse import urljoin
from requests import Session, Response

from .singleton import SingletonMeta
from .exceptions import BadTokenException


AUTH_HEADER = "x-access-token"


class Client(metaclass=SingletonMeta):
    def __init__(self, url: str, token: str, refresh_token: str, **kwargs):
        self.__url = url
        self.__token = token
        self.__refresh_token = refresh_token
        self.__session = Session()

    def _refresh_token(self):
        url = urljoin(self.__url, 'internal/auth/refresh')
        response = self.__session.post(url, params={"refresh_token": self.__refresh_token})
        if response.status_code == 401:
            raise BadTokenException(response.json()["detail"])
        self.__token = response.text

    def request(self, method: str, service_path_prefix: str, path, **kwargs) -> Response:
        headers = kwargs.get("headers", {})
        headers.update({AUTH_HEADER: self.__token})
        kwargs["headers"] = headers
        response = self.__session.request(method, service_path_prefix, path, **kwargs)
        if response.headers.get("x-auth-exception", None) == "Expired":
            self._refresh_token()
            kwargs["headers"][AUTH_HEADER] = self.__token
            response = self.__session.request(method, service_path_prefix, path, **kwargs)
        elif response.headers.get("x-auth-exception", None) == "Invalid":
            raise BadTokenException("invalid token")
        elif response.headers.get("x-auth-exception", None) == "Not Authorized":
            required_permission = response.headers.get("x-required-scope", None)
            raise BadTokenException(
                f"you do not have to permissions to make that request (required permission: {required_permission})"
            )
        return response
