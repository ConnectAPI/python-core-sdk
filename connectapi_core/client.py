from urllib.parse import urljoin
from requests import Session, Response

from .singleton import SingletonMeta
from .exceptions import BadTokenException


AUTH_HEADER = "x-access-token"


class Client(metaclass=SingletonMeta):
    __token: str = None
    __refresh_token: str = None
    __url: str = None
    __session = Session()

    @classmethod
    def set_token(cls, token: str):
        cls.__refresh_token = token

    @classmethod
    def set_url(cls, url: str):
        cls.__url = url

    @classmethod
    def _refresh_token(cls):
        url = urljoin(cls.__url, 'internal/auth/token/refresh')
        response = cls.__session.post(url, params={"refresh_token": cls.__refresh_token})
        if response.status_code == 401:
            raise BadTokenException(response.json()["detail"])
        cls.__token = response.text[1:-1]

    def request(self, method: str, service_path_prefix: str, path, query, body, headers, **kwargs) -> Response:
        if self.__class__.__url is None:
            raise RuntimeError(
                "Can't use uninitialized client set url and token first "
                "(Client.set_url('...'), Client.set_token('...'))"
            )
        if self.__class__.__token is None:
            self.__class__._refresh_token()

        url = urljoin(self.__url, service_path_prefix)
        url = url + path
        headers.update({AUTH_HEADER: self.__token})
        response = self.__session.request(method, url, params=query, json=body, headers=headers, **kwargs)
        if response.headers.get("x-auth-exception", None) == "Expired":
            self.__class__._refresh_token()
            headers.update({AUTH_HEADER: self.__token})
            response = self.__session.request(method, url, params=query, json=body, headers=headers, **kwargs)
        elif response.headers.get("x-auth-exception", None) == "Invalid":
            raise BadTokenException("invalid token")
        elif response.headers.get("x-auth-exception", None) == "Not Authorized":
            required_permission = response.headers.get("x-required-scope", None)
            raise BadTokenException(
                f"you do not have to permissions to make that request (required permission: {required_permission})"
            )
        return response
