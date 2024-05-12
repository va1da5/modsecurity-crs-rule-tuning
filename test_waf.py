import http
import urllib.parse
import uuid
from random import randrange

import pytest
import requests

ENDPOINT = "http://localhost:8000"
UA = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36"


def get_url(path: str) -> str:
    return urllib.parse.urljoin(ENDPOINT, path)


def url_encode_all(string):
    return "".join("%{0:0>2x}".format(ord(char)) for char in string)


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


def test_nosql_1(request_kwargs):
    """This should work as it uses NOSQL"""
    data = {}
    data[str(uuid.uuid1())] = "test' or '1'='1"
    response = requests.post(get_url("/nosql/update"), data=data, **request_kwargs)
    assert response.status_code == http.HTTPStatus.OK


def test_nosql_2(request_kwargs):
    """NOSQL exploitation attempts should be blocked"""
    data = {"username": {"$eq": "admin"}, "password": {"$regex": "^mdp"}}
    response = requests.post(get_url("/nosql/update"), json=data, **request_kwargs)
    assert response.status_code == http.HTTPStatus.FORBIDDEN


def test_cookie_1(user_agent):
    """These cookies are considered safe and WAF should not block it"""
    cookie = "yummy_cookie=banana; tasty_cookie=strawberry"
    headers = {**user_agent, "Cookie": cookie}
    response = requests.get(get_url("/cookies"), headers=headers)
    assert response.status_code == http.HTTPStatus.OK


def test_cookie_2(user_agent):
    """As an example, this cookie is considered safe and WAF should not block it"""
    cookie = "delicious_cookie=uname-it; tasty_cookie=strawberry"
    headers = {**user_agent, "Cookie": cookie}
    response = requests.get(get_url("/cookies"), headers=headers)
    assert response.status_code == http.HTTPStatus.OK


def test_cookie_3(user_agent):
    """Create custom rule to detect use of `username` cookie and prevent use of it"""
    cookie = "username=admin; session-id=73101f80-727c-4c4d-b812-9023d40e8510"
    headers = {**user_agent, "Cookie": cookie}
    response = requests.get(get_url("/cookies"), headers=headers)
    assert response.status_code == http.HTTPStatus.FORBIDDEN


def test_cookie_4(user_agent):
    """Lets assume this is a legit cookie and needs to be allowed"""
    cookie = 'SESSION=O:13:"ConvisoPerson":5:{s:8:"username";s:6:"Antony";s:4:"team";s:5:"PTaaS";s:3:"age";i:17;s:6:"office";s:6:"Intern";s:12:"accountAdmin";b:0;}'
    headers = {**user_agent, "Cookie": cookie}
    response = requests.get(get_url("/cookies"), headers=headers)
    assert response.status_code == http.HTTPStatus.OK


def test_cookie_5(user_agent):
    """Lets assume this is a legit cookie and needs to be allowed"""
    cookie = f"SESSION={str(uuid.uuid1())}|uname -a"
    headers = {**user_agent, "Cookie": cookie}
    response = requests.get(get_url("/cookies"), headers=headers)
    assert response.status_code == http.HTTPStatus.FORBIDDEN


def test_get_params_1(request_kwargs):
    """This get parameter value is considered safe and should not be blocked"""
    response = requests.get(get_url("/status") + "?action=netstat", **request_kwargs)
    assert response.status_code == http.HTTPStatus.OK


@pytest.mark.parametrize(
    "cmd",
    ["whoami", "uname", "netcat", "wget"],
)
def test_get_params_2(cmd: str, request_kwargs):
    """This and any other potential RCE attack parameter values should be blocked"""
    response = requests.get(get_url("/status") + f"?action={cmd}", **request_kwargs)
    assert response.status_code == http.HTTPStatus.FORBIDDEN


def test_get_params_3(request_kwargs):
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


def test_user_agent_2():
    """The below user-agent includes RCE attack attempt and must be blocked"""
    headers = {
        "User-Agent": 'Mozilla/5.0 (Linux; Android 10; id) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/123.0.0.0 Mobile Safari/537.3; echo "<h1>Defaced</h1>" > /var/www/html/public/index.php'
    }
    response = requests.get(get_url("/ua"), headers=headers)
    assert response.status_code == http.HTTPStatus.FORBIDDEN


@pytest.mark.parametrize(
    "filename",
    ["backup.sql", "dump.sql", "backup.old", "HEAD", "settings.xml", "config.json"],
)
def test_file_1(
    filename: str,
):
    """Prevent users from accessing sensitive files anywhere on the server"""
    path = f"/{str(uuid.uuid1())}/{filename}"
    response = requests.get(get_url(path))
    assert response.status_code == http.HTTPStatus.NOT_FOUND


@pytest.mark.parametrize(
    "filename",
    [
        "jquery.js",
        "index.css",
        "latin-wght-normal.woff2",
    ],
)
def test_file_2(filename: str, request_kwargs):
    """Allow to download static content"""
    path = f"/{str(uuid.uuid1())}/{filename}"
    response = requests.get(get_url(path), **request_kwargs)
    assert response.status_code == http.HTTPStatus.OK


@pytest.mark.parametrize(
    "path",
    [
        "/var/www/html/config.json",
        "/var/www/html/public/index.php",
        "/etc/passwd",
        "/proc/self/environ",
        "/var/log/nginx/access.log",
    ],
)
def test_file_3(path: str, request_kwargs):
    """Prevent users from accessing files outside /home/* directory"""
    response = requests.get(
        get_url("/file/api") + f"?path={url_encode_all(path)}", **request_kwargs
    )
    assert response.status_code == http.HTTPStatus.NOT_FOUND


@pytest.mark.parametrize(
    "path",
    [
        "/etc/passwd",
        "/proc/self/environ",
    ],
)
def test_file_4(path: str, request_kwargs):
    """Requests for system files should be blocked in general"""
    response = requests.get(
        get_url("/system/manage") + f"?path={url_encode_all(path)}", **request_kwargs
    )
    assert response.status_code == http.HTTPStatus.FORBIDDEN


@pytest.mark.parametrize(
    "filename",
    [
        "report.pdf",
        "notes.txt",
        "index.php",
    ],
)
def test_file_5(filename: str, request_kwargs):
    """Allow accessing specific files"""
    response = requests.get(
        get_url("/file/api") + f"?path=/home/{str(uuid.uuid1())}/{filename}",
        **request_kwargs,
    )
    assert response.status_code == http.HTTPStatus.OK
