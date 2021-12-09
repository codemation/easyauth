import pytest

"""
curl 'http://0.0.0.0:8520/login' \
  -H 'Connection: keep-alive' \
  -H 'Cache-Control: max-age=0' \
  -H 'Upgrade-Insecure-Requests: 1' \
  -H 'Origin: http://0.0.0.0:8520' \
  -H 'Content-Type: application/x-www-form-urlencoded' \
  -H 'User-Agent: Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/95.0.4638.69 Safari/537.36' \
  -H 'Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9' \
  -H 'Referer: http://0.0.0.0:8520/login' \
  -H 'Accept-Language: en-US,en;q=0.9' \
  -H 'Cookie: token=INVALID' \
  --data-raw 'username=admin&password=easyauth' \
  --compressed \
  --insecure
"""


def test_server_authentication(auth_test_client):
    test_client = auth_test_client

    # verify endpoint access fails without token

    response = test_client.get("/actions")
    assert response.status_code == 401, f"{response.text} - {response.status_code}"

    # verify token generation with bad credentials
    login_headers = {
        "Accept": "text/html,application",
        "Content-Type": "application/x-www-form-urlencoded",
    }

    response = test_client.post(
        "/login", data="username=admin&password=BAD", headers=login_headers
    )

    assert response.status_code == 401, f"- {response.status_code}"

    response = test_client.post(
        "/login",
        data="username=admin&password=easyauth",
        headers=login_headers,
        allow_redirects=False,
    )

    token = response.cookies["token"]

    # verify endpoint access while using token

    headers = {"Authorization": f"Bearer {token}"}

    response = test_client.get("/actions", headers=headers)
    assert response.status_code == 200, f"{response.status_code}"
