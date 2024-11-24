import base64
import os
from typing import Final
from urllib.parse import unquote_plus

import requests
import uvicorn
from attr import dataclass
from dotenv import load_dotenv
from fastapi import FastAPI
from fastapi.requests import Request
from fastapi.responses import RedirectResponse
from nicegui import Client, app, ui

load_dotenv()
main = FastAPI()

GITHUB_AUTHORIZE_URL: Final[str] = "https://github.com/login/oauth/authorize"
GITHUB_ACCESS_TOKEN_URL: Final[str] = "https://github.com/login/oauth/access_token"
GITHUB_USER_INFO_URL: Final[str] = "https://api.github.com/user"
LOGIN_PATH: Final[str] = "/login"
DEFAULT_PORT = 5000


@dataclass
class Config:
    client_id: str | None
    client_secret: str | None
    redirect_uri: str | None
    storage_secret: str | None
    enable_ssl: bool = False
    ssl_certfile: str | None = None
    ssl_keyfile: str | None = None
    port: int = DEFAULT_PORT

    @property
    def fixed_redirect_uri(self) -> str:
        if not self.redirect_uri:
            raise ValueError("Redirect URI is not set")
        if self.enable_ssl:
            return self.redirect_uri.replace("http", "https")
        return self.redirect_uri.replace("https", "http")

    @property
    def redirect_uri_path(self) -> str:
        if not self.redirect_uri:
            raise ValueError("Redirect URI is not set")
        return self.redirect_uri.split("://")[1]


config = Config(
    client_id=os.getenv("CLIENT_ID"),
    client_secret=os.getenv("CLIENT_SECRET"),
    redirect_uri=os.getenv("REDIRECT_URI"),
    storage_secret=os.getenv("STORAGE_SECRET"),
    enable_ssl=os.getenv("SSL_ENABLED", "False") == "True",
    ssl_certfile=os.getenv("SSL_CERTFILE", None),
    ssl_keyfile=os.getenv("SSL_KEYFILE", None),
    port=int(os.getenv("PORT", DEFAULT_PORT)),
)


def get_authorization_url() -> str:
    """
    Returns the authorization URL for GitHub
    :return: The authorization URL"""
    state = unquote_plus(base64.b64encode(os.urandom(16)).decode("utf-8"))
    app.storage.user["state"] = state
    return (
        f"{GITHUB_AUTHORIZE_URL}?client_id={config.client_id}&redirect_uri={config.redirect_uri}"
        + f"&scope=user&state={state}"
    )


def fetch_access_token(code: str) -> str:
    """
    Fetches the access token from the GitHub API
    :param code: The code from GitHub
    :return: The access token"""
    data = {
        "client_id": config.client_id,
        "client_secret": config.client_secret,
        "code": code,
        "redirect_uri": config.fixed_redirect_uri,
    }
    response = requests.post(GITHUB_ACCESS_TOKEN_URL, data=data)
    response_data = response.text.split("&")
    return response_data[0].split("=")[1]


def fetch_user_data(access_token: str) -> dict:
    """
    Fetches the user data from the GitHub API
    :param access_token: The access token
    :return: The user data"""
    headers = {"Authorization": f"token {access_token}"}
    response = requests.get(GITHUB_USER_INFO_URL, headers=headers)
    print(response.text)
    return response.json()


@ui.page(config.redirect_uri_path)
async def api_gh_callback(request: Request):
    """
    Handles the callback from GitHub
    :param request: The request from GitHub"""
    code = request.query_params.get("code", "")
    state = request.query_params.get("state", "")
    if state != app.storage.user["state"]:
        ui.notify(message=f"Invalid state: {state}")
        return
    access_token = fetch_access_token(code)
    if user_data := fetch_user_data(access_token):
        app.storage.user["authenticated"] = True
        app.storage.user["data"] = user_data
        return RedirectResponse("/")
    else:
        return RedirectResponse(LOGIN_PATH)


@ui.page(LOGIN_PATH)
async def ui_login(client: Client):
    """
    Handles the login page"""
    await client.connected()
    with ui.card().classes("fixed-center"):
        ui.label(text="Login").classes("font-bold text-2xl")
        ui.input(label="Username").classes("w-full")
        ui.input(label="Password", password=True, password_toggle_button=True).classes("w-full")
        with ui.row().classes("w-full"):
            ui.button("Login", on_click=lambda: 1).props("flat").classes("disabled")
            ui.button(
                "Login with Github", on_click=lambda: ui.navigate.to(target=get_authorization_url(), new_tab=True)
            ).props("flat")


@ui.page("/")
def ui_index():
    """
    Handles the index page"""
    if not app.storage.user.get("authenticated", False):
        return RedirectResponse(url=LOGIN_PATH)

    with ui.header():
        ui.label("NiceGHLogin").classes("font-bold text-2xl")
        with ui.image(source=app.storage.user["data"].get("avatar_url", "")).classes(
            "w-8 rounded-full ml-auto mt-auto mb-auto cursor-pointer"
        ), ui.menu():
            ui.menu_item(
                "Logout",
                on_click=lambda: (
                    app.storage.user.update({"authenticated": False}),
                    app.storage.user.update({"data": {}}),
                    ui.navigate.to(LOGIN_PATH),
                ),
            )
    ui.label(text=f"Hello {app.storage.user['data']['name']}")


if __name__ in {"__main__", "__mp_main__"}:
    ui.run_with(main, storage_secret=config.storage_secret)
    if config.enable_ssl:
        import ssl

        if not config.ssl_certfile or not config.ssl_keyfile:
            raise ValueError("SSL enabled but no certificate or key file provided.")
        ssl_context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ssl_context.load_cert_chain(certfile=config.ssl_certfile, keyfile=config.ssl_keyfile)
        uvicorn.run(
            app, host="127.0.0.1", port=config.port, ssl_keyfile=config.ssl_certfile, ssl_certfile=config.ssl_keyfile
        )
    else:
        uvicorn.run(app, host="127.0.0.1", port=config.port)
