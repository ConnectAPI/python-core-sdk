from urllib.parse import urljoin
from requests import Session, Response

from .singleton import SingletonMeta
from .exceptions import BadTokenException, ClientException


class Client(metaclass=SingletonMeta):
    def __init__(self, url: str, token: str, refresh_token: str, **kwargs):
        self.__url = url
        self.__token = token
        self.__refresh_token = refresh_token
        self.__session = Session()

    def __get_refreshed_token(self):
        url = urljoin(self.__url, 'internal/auth/refresh')
        response = self.__session.post(url, params={"refresh_token": self.__refresh_token})
        if response.status_code == 401:
            raise BadTokenException(response.json()["detail"])
        self.__token = response.text

    def request(self, method: str, service_path_prefix: str, path, **kwargs) -> Response:
        response = self.__session.request(method, service_path_prefix, path, **kwargs)
        if response.status_code == 401 and response.headers.get("WWW-Authenticate", None) == "Bearer":
            self.__get_refreshed_token()
            response = self.__session.request(method, service_path_prefix, path, **kwargs)

        if response.status_code >= 300:
            raise ClientException(f'{response.status_code} {response.text}')
        return response
