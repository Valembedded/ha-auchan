"""OAuth support for Auchan."""

import json
import logging
from pathlib import Path
import secrets
from typing import Any, Final, override

from aiohttp import web
from yarl import URL

from homeassistant import data_entry_flow
from homeassistant.components.http import KEY_HASS, HomeAssistantView
from homeassistant.core import HomeAssistant, callback
from homeassistant.helpers import config_entry_oauth2_flow
from homeassistant.helpers.config_entry_oauth2_flow import LocalOAuth2Implementation
from homeassistant.helpers.network import get_url

from .const import DOMAIN

_LOGGER = logging.getLogger(__name__)


CLIENT_ID: Final = "lark-crest"

AUTHORIZE_URL: Final = (
    "https://compte.auchan.fr/auth/realms/auchan.fr/protocol/openid-connect/auth"
)

TOKEN_URL: Final = (
    "https://compte.auchan.fr/auth/realms/auchan.fr/protocol/openid-connect/token"
)

AUCHAN_LOGIN_URL: Final = "https://www.auchan.fr/auth/login"

OAUTH_CALLBACK_PATH: Final = "/api/auchan/oauth/callback"

OAUTH_CALLBACK_NAME: Final = "api:auchan:oauth_callback"

DATA_CALLBACK_REGISTERED: Final = "auchan_oauth_callback_registered"

DATA_IMPLEMENTATION_REGISTERED: Final = "auchan_oauth_implementation_registered"


class AuchanOAuth2Implementation(LocalOAuth2Implementation):
    """Auchan OAuth2 implementation."""

    def __init__(
        self,
        hass: HomeAssistant,
    ) -> None:
        """Initialize OAuth implementation."""

        super().__init__(
            hass=hass,
            domain=DOMAIN,
            client_id=CLIENT_ID,
            client_secret="",
            authorize_url=AUTHORIZE_URL,
            token_url=TOKEN_URL,
        )

        #
        # These two values are only used during
        # the interactive OAuth config flow.
        #
        self.expected_state: str | None = None
        self.oauth_redirect_uri: str | None = None

    @property
    @override
    def name(self) -> str:
        """Return implementation name."""

        return "Auchan"

    @override
    async def async_generate_authorize_url(
        self,
        flow_id: str,
    ) -> str:
        """Generate Auchan authorization URL."""

        hass_url = get_url(
            self.hass,
            require_current_request=True,
        ).rstrip("/")

        #
        # Home Assistant callback URL.
        #
        bridge_url = str(
            URL(f"{hass_url}{OAUTH_CALLBACK_PATH}").with_query(
                {
                    "flow_id": flow_id,
                }
            )
        )

        #
        # Auchan expects the callback URL encoded
        # inside its /auth/login URL.
        #
        encoded_bridge_url = bridge_url.encode("utf-8").hex()

        self.oauth_redirect_uri = (
            f"{AUCHAN_LOGIN_URL}/{encoded_bridge_url}?auth_callback=1"
        )

        #
        # OAuth CSRF protection.
        #
        self.expected_state = secrets.token_urlsafe(32)

        authorize_url = URL(AUTHORIZE_URL).with_query(
            {
                "client_id": CLIENT_ID,
                "redirect_uri": self.oauth_redirect_uri,
                "scope": "openid",
                "response_type": "code",
                "response_mode": "fragment",
                "state": self.expected_state,
            }
        )

        _LOGGER.debug(
            "Generated Auchan OAuth URL for flow %s",
            flow_id,
        )

        return str(authorize_url)

    @override
    async def async_resolve_external_data(
        self,
        external_data: Any,
    ) -> dict:
        """Exchange authorization code for tokens."""

        if self.oauth_redirect_uri is None:
            raise RuntimeError("Auchan OAuth redirect URI is missing")

        code = external_data.get("code")

        if not code:
            raise ValueError("OAuth authorization code missing")

        return await self._token_request(
            {
                "grant_type": "authorization_code",
                "code": code,
                "redirect_uri": self.oauth_redirect_uri,
            }
        )


class AuchanOAuthCallbackView(HomeAssistantView):
    """Bridge OAuth URL fragment to Home Assistant config flow."""

    url = OAUTH_CALLBACK_PATH
    name = OAUTH_CALLBACK_NAME

    requires_auth = False

    async def get(
        self,
        request: web.Request,
    ) -> web.Response:
        """Serve fragment-to-POST bridge."""

        base_dir = Path(__file__).parent

        html = (base_dir / "landing.html").read_text(encoding="utf-8")

        return web.Response(
            text=html,
            content_type="text/html",
            headers={
                "Cache-Control": "no-store, max-age=0",
                "Pragma": "no-cache",
                "Referrer-Policy": "no-referrer",
                "X-Content-Type-Options": "nosniff",
                "Content-Security-Policy": (
                    "default-src 'none'; "
                    "style-src 'unsafe-inline'; "
                    "script-src 'unsafe-inline'; "
                    "connect-src 'self'; "
                    "frame-ancestors 'none'; "
                    "base-uri 'none'"
                ),
            },
        )

    async def post(
        self,
        request: web.Request,
    ) -> web.Response:
        """Resume Home Assistant config flow."""

        hass: HomeAssistant = request.app[KEY_HASS]

        try:
            data = await request.json()

        except json.JSONDecodeError, UnicodeDecodeError:
            return web.json_response(
                {
                    "error": "invalid_json",
                },
                status=400,
            )

        flow_id = data.get("flow_id")
        state = data.get("state")
        code = data.get("code")
        error = data.get("error")

        if not flow_id:
            return web.json_response(
                {
                    "error": "missing_flow_id",
                },
                status=400,
            )

        if not state:
            return web.json_response(
                {
                    "error": "missing_state",
                },
                status=400,
            )

        user_input: dict[str, Any] = {
            "state": state,
        }

        if code:
            user_input["code"] = code

        elif error:
            user_input["error"] = error

            error_description = data.get("error_description")

            if error_description:
                user_input["error_description"] = error_description

        else:
            return web.json_response(
                {
                    "error": "missing_code",
                },
                status=400,
            )

        try:
            await hass.config_entries.flow.async_configure(
                flow_id=flow_id,
                user_input=user_input,
            )

        except data_entry_flow.UnknownFlow:
            _LOGGER.warning(
                "OAuth callback received for unknown/expired flow %s",
                flow_id,
            )

            return web.json_response(
                {
                    "error": "unknown_or_expired_flow",
                },
                status=410,
            )

        except Exception:
            _LOGGER.exception(
                "Error while resuming Auchan config flow %s",
                flow_id,
            )

            return web.json_response(
                {
                    "error": "flow_error",
                },
                status=500,
            )

        return web.json_response(
            {
                "success": True,
            }
        )


@callback
def async_register_oauth_callback(
    hass: HomeAssistant,
) -> None:
    """Register OAuth callback once."""

    if hass.data.get(DATA_CALLBACK_REGISTERED):
        return

    hass.http.register_view(AuchanOAuthCallbackView)

    hass.data[DATA_CALLBACK_REGISTERED] = True


@callback
def async_register_oauth_implementation(
    hass: HomeAssistant,
) -> None:
    """Register Auchan OAuth implementation for runtime."""

    if hass.data.get(DATA_IMPLEMENTATION_REGISTERED):
        return

    #
    # Runtime OAuth implementation.
    #
    # This instance will be used by OAuth2Session,
    # especially for token refresh.
    #
    implementation = AuchanOAuth2Implementation(hass)

    config_entry_oauth2_flow.async_register_implementation(
        hass,
        DOMAIN,
        implementation,
    )

    hass.data[DATA_IMPLEMENTATION_REGISTERED] = True
