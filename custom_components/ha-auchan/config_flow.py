"""Config flow pour l'intégration Auchan."""
from __future__ import annotations

import asyncio
import logging
import re
import uuid
from typing import Any

import aiohttp
import voluptuous as vol
from aiohttp import web

from homeassistant import config_entries
from homeassistant.components.http import HomeAssistantView
from homeassistant.core import HomeAssistant
from homeassistant.data_entry_flow import FlowResult

from .const import DOMAIN, REALM_URL, CLIENT_ID

_LOGGER = logging.getLogger(__name__)

PROXY_PATH = "/api/auchan_auth_proxy"
LOGIN_TIMEOUT = 300  # 5 minutes pour que l'utilisateur se connecte


class CannotConnect(Exception):
    """Erreur réseau vers Auchan."""


class InvalidAuth(Exception):
    """Échange du code / login invalide."""


class LoginTimeout(Exception):
    """L'utilisateur n'a pas terminé le login à temps."""


class AuchanAuthProxyView(HomeAssistantView):
    """Reverse proxy en direct vers compte.auchan.fr pour capturer le code OAuth."""

    url = f"{PROXY_PATH}/{{path:.*}}"
    name = "api:auchan_auth_proxy"
    requires_auth = False

    def __init__(self, on_code_captured, expected_state: str) -> None:
        self._on_code_captured = on_code_captured
        self._expected_state = expected_state
        self._session: aiohttp.ClientSession | None = None
        self._cookie_jar = aiohttp.CookieJar(unsafe=True)

    async def _get_session(self) -> aiohttp.ClientSession:
        if self._session is None or self._session.closed:
            self._session = aiohttp.ClientSession(cookie_jar=self._cookie_jar)
        return self._session

    async def get(self, request: web.Request, path: str) -> web.Response:
        return await self._proxy(request, path, "GET")

    async def post(self, request: web.Request, path: str) -> web.Response:
        return await self._proxy(request, path, "POST")

    async def _proxy(self, request: web.Request, path: str, method: str) -> web.Response:
        target_url = f"https://compte.auchan.fr/{path}"
        if request.query_string:
            target_url += f"?{request.query_string}"

        _LOGGER.debug("Proxy %s %s", method, path)

        session = await self._get_session()
        data = await request.read() if method == "POST" else None
        headers = {
            k: v
            for k, v in request.headers.items()
            if k.lower() not in ("host", "content-length", "cookie")
        }

        try:
            async with session.request(
                method,
                target_url,
                data=data,
                headers=headers,
                allow_redirects=False,
            ) as resp:
                location = resp.headers.get("Location", "")

                if "code=" in location and f"state={self._expected_state}" in location:
                    match = re.search(r"code=([^&]+)", location)
                    if match:
                        _LOGGER.info("Code OAuth Auchan capturé")
                        await self._on_code_captured(match.group(1))
                        return web.Response(
                            text=(
                                "<html><body style='font-family:sans-serif;"
                                "text-align:center;margin-top:20%'>"
                                "<h2>✅ Connexion Auchan réussie</h2>"
                                "<p>Tu peux fermer cet onglet et revenir sur "
                                "Home Assistant.</p></body></html>"
                            ),
                            content_type="text/html",
                        )

                body = await resp.read()
                resp_headers = dict(resp.headers)

                if resp.status in (301, 302, 303, 307, 308) and location:
                    resp_headers["Location"] = self._rewrite(location)

                for h in ("Content-Encoding", "Content-Length", "Transfer-Encoding"):
                    resp_headers.pop(h, None)

                content_type = resp.headers.get("Content-Type", "")
                if "text/html" in content_type:
                    text = body.decode("utf-8", errors="ignore")
                    text = text.replace("https://compte.auchan.fr", PROXY_PATH)
                    body = text.encode("utf-8")

                return web.Response(body=body, status=resp.status, headers=resp_headers)

        except aiohttp.ClientError as err:
            _LOGGER.error("Erreur proxy vers Auchan: %s", err)
            return web.Response(status=502, text="Erreur de connexion vers Auchan")

    def _rewrite(self, url: str) -> str:
        if url.startswith("https://compte.auchan.fr"):
            return url.replace("https://compte.auchan.fr", PROXY_PATH)
        return url

    async def async_close(self) -> None:
        if self._session and not self._session.closed:
            await self._session.close()


class AuchanConfigFlow(config_entries.ConfigFlow, domain=DOMAIN):
    """Config flow Auchan."""

    VERSION = 1

    def __init__(self) -> None:
        self._state: str | None = None
        self._view: AuchanAuthProxyView | None = None
        self._code_future: asyncio.Future[str] | None = None
        self._task: asyncio.Task | None = None
        self._auth_url: str | None = None

    async def async_step_user(
        self, user_input: dict[str, Any] | None = None
    ) -> FlowResult:
        if self._task is None:
            self._state = str(uuid.uuid4())
            self._code_future = self.hass.loop.create_future()
            self._view = AuchanAuthProxyView(self._on_code_captured, self._state)
            self.hass.http.register_view(self._view)

            redirect_uri = (
                "https://www.auchan.fr/auth/login/"
                "68747470733a2f2f7777772e61756368616e2e66722f?auth_callback=1"
            )
            self._auth_url = (
                f"{PROXY_PATH}/auth/realms/auchan.fr/protocol/openid-connect/auth"
                f"?client_id={CLIENT_ID}&state={self._state}"
                f"&redirect_uri={redirect_uri}"
                f"&scope=openid&response_type=code"
            )

            self._task = self.hass.async_create_task(self._await_login())

            return self.async_show_progress(
                step_id="user",
                progress_action="waiting_for_login",
                description_placeholders={"auth_url": self._auth_url},
                progress_task=self._task,
            )

        # Le task s'est terminé (succès, erreur ou timeout)
        try:
            code = self._task.result()
        except LoginTimeout:
            await self._cleanup()
            return self.async_show_progress_done(next_step_id="timeout")
        except Exception:
            _LOGGER.exception("Erreur pendant l'attente du login Auchan")
            await self._cleanup()
            return self.async_show_progress_done(next_step_id="login_failed")

        try:
            tokens = await self._exchange_code(code)
        except InvalidAuth:
            await self._cleanup()
            return self.async_show_progress_done(next_step_id="login_failed")
        except CannotConnect:
            await self._cleanup()
            return self.async_show_progress_done(next_step_id="cannot_connect")

        await self._cleanup()
        self._tokens = tokens

        await self.async_set_unique_id(f"auchan_{self._state}")
        return self.async_show_progress_done(next_step_id="finish")

    async def async_step_finish(self, user_input=None) -> FlowResult:
        return self.async_create_entry(
            title="Auchan",
            data={
                "refresh_token": self._tokens["refresh_token"],
                "access_token": self._tokens["access_token"],
            },
        )

    async def async_step_timeout(self, user_input=None) -> FlowResult:
        if user_input is not None:
            self._task = None
            return await self.async_step_user()
        return self.async_show_form(step_id="timeout")

    async def async_step_login_failed(self, user_input=None) -> FlowResult:
        if user_input is not None:
            self._task = None
            return await self.async_step_user()
        return self.async_show_form(step_id="login_failed")

    async def async_step_cannot_connect(self, user_input=None) -> FlowResult:
        if user_input is not None:
            self._task = None
            return await self.async_step_user()
        return self.async_show_form(step_id="cannot_connect")

    async def _on_code_captured(self, code: str) -> None:
        if self._code_future and not self._code_future.done():
            self._code_future.set_result(code)

    async def _await_login(self) -> str:
        try:
            return await asyncio.wait_for(self._code_future, timeout=LOGIN_TIMEOUT)
        except asyncio.TimeoutError as err:
            raise LoginTimeout from err

    async def _exchange_code(self, code: str) -> dict:
        redirect_uri = (
            "https://www.auchan.fr/auth/login/"
            "68747470733a2f2f7777772e61756368616e2e66722f?auth_callback=1"
        )
        session = aiohttp.ClientSession()
        try:
            async with session.post(
                f"{REALM_URL}/protocol/openid-connect/token",
                data={
                    "grant_type": "authorization_code",
                    "code": code,
                    "client_id": CLIENT_ID,
                    "redirect_uri": redirect_uri,
                },
            ) as resp:
                if resp.status != 200:
                    body = await resp.text()
                    _LOGGER.error("Échange de code échoué (%s): %s", resp.status, body)
                    raise InvalidAuth
                return await resp.json()
        except aiohttp.ClientError as err:
            raise CannotConnect from err
        finally:
            await session.close()

    async def _cleanup(self) -> None:
        if self._view:
            await self._view.async_close()
            self._view = None