import http
import urllib.parse
from random import randrange

import pytest
import requests

ENDPOINT = "http://localhost:8000"
UA = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36"


def get_url(path: str) -> str:
    return urllib.parse.urljoin(ENDPOINT, path)


@pytest.fixture
def user_agent():
    return {"User-Agent": UA}


@pytest.fixture
def request_kwargs(user_agent):
    return {"headers": user_agent, "timeout": 10}


def test_generic_form_1(request_kwargs):
    """Both form fields are legit and WAF should not block them"""
    data = {
        f"column[{randrange(10)}][field]": "id_addr",
        f"column[{randrange(10)}][field]": "pwd",
    }
    response = requests.post(get_url("/logs"), data=data, **request_kwargs)
    assert response.status_code == http.HTTPStatus.OK


def test_password_form_1(request_kwargs):
    """Any password should be allowed. Ensure this does not get blocked"""
    data = {"username": "admin", "password": "whoami2you?"}
    response = requests.post(get_url("/login"), data=data, **request_kwargs)
    assert response.status_code == http.HTTPStatus.OK


def test_password_form_2(request_kwargs):
    """Any password should be allowed. Ensure this does not get blocked"""
    data = {"username": "admin", "password": "Bob's 1'=password"}
    response = requests.post(get_url("/login"), data=data, **request_kwargs)
    assert response.status_code == http.HTTPStatus.OK


def test_password_form_3(request_kwargs):
    """Any password should be allowed. Ensure this does not get blocked"""
    data = {"username": "admin' or '99'='99", "password": "Admin123!"}
    response = requests.post(get_url("/login"), data=data, **request_kwargs)
    assert response.status_code == http.HTTPStatus.FORBIDDEN


def test_password_json_1(request_kwargs):
    """Any password should be allowed. Ensure this does not get blocked"""
    data = {"username": "admin", "password": "whoami2you?"}
    response = requests.post(get_url("/api/login"), json=data, **request_kwargs)
    assert response.status_code == http.HTTPStatus.OK


def test_password_json_2(request_kwargs):
    """Any password should be allowed. Ensure this does not get blocked"""
    data = {"username": "admin", "password": "Bob's 2='passwd"}
    response = requests.post(get_url("/api/login"), json=data, **request_kwargs)
    assert response.status_code == http.HTTPStatus.OK


def test_password_json_3(request_kwargs):
    """Username parameter must be secured against SQLi"""
    data = {"username": "admin' or '1337'='1337", "password": "Admin123!"}
    response = requests.post(get_url("/api/login"), json=data, **request_kwargs)
    assert response.status_code == http.HTTPStatus.FORBIDDEN


def test_cookie_1(user_agent):
    """As an example, this cookie is considered safe and WAF should not block it"""
    cookie = "yummy_cookie=uname-it; tasty_cookie=strawberry"
    headers = {**user_agent, "Cookie": cookie}
    response = requests.get(get_url("/cookies"), headers=headers)
    assert response.status_code == http.HTTPStatus.OK


def test_cookie_2(user_agent):
    """Create custom rule to detect use of `username` cookie and prevent use of it"""
    cookie = "username=admin; session-id=73101f80-727c-4c4d-b812-9023d40e8510"
    headers = {**user_agent, "Cookie": cookie}
    response = requests.get(get_url("/cookies"), headers=headers)
    assert response.status_code == http.HTTPStatus.FORBIDDEN


def test_cookie_3(user_agent):
    """Lets assume this is a legit cookie and needs to be allowed"""
    cookie = 'SESSION=a:2:{i:0;s:4:"bob";i:1;s:33:"admin\'istrator\'=";}'
    headers = {**user_agent, "Cookie": cookie}
    response = requests.get(get_url("/cookies"), headers=headers)
    assert response.status_code == http.HTTPStatus.OK


def test_get_params_1(request_kwargs):
    """This get parameter should not be blocked"""
    response = requests.get(get_url("/status") + "?action=netstat", **request_kwargs)
    assert response.status_code == http.HTTPStatus.OK


def test_get_params_2(request_kwargs):
    """The below activity should be blocked"""
    response = requests.get(get_url("/status") + "?cmd=whoami", **request_kwargs)
    assert response.status_code == http.HTTPStatus.FORBIDDEN


def test_user_agent_1():
    """The below user-agent should not be blocked"""
    headers = {
        "User-Agent": "Mozilla/5.0 (Linux; Android 10; id) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/123.0.0.0 Mobile Safari/537.3"
    }
    response = requests.get(get_url("/ua"), headers=headers)
    assert response.status_code == http.HTTPStatus.OK
