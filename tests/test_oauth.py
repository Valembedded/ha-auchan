"""Tests for Auchan OAuth support."""

import json
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from custom_components.auchan.const import DOMAIN
from custom_components.auchan.oauth import (
    AUCHAN_LOGIN_URL,
    AUTHORIZE_URL,
    CLIENT_ID,
    DATA_CALLBACK_REGISTERED,
    DATA_IMPLEMENTATION_REGISTERED,
    OAUTH_CALLBACK_NAME,
    OAUTH_CALLBACK_PATH,
    AuchanOAuth2Implementation,
    AuchanOAuthCallbackView,
    async_register_oauth_callback,
    async_register_oauth_implementation,
)
from homeassistant import data_entry_flow
from homeassistant.components.http import KEY_HASS
from homeassistant.core import HomeAssistant
from yarl import URL


def create_request(
    hass: HomeAssistant,
    payload: dict | None = None,
    *,
    error: Exception | None = None,
) -> MagicMock:
    """Create a mocked aiohttp request."""

    request = MagicMock()

    request.app = {
        KEY_HASS: hass,
    }

    if error is not None:
        request.json = AsyncMock(side_effect=error)
    else:
        request.json = AsyncMock(return_value=payload)

    return request


def get_json(response) -> dict:
    """Decode JSON response."""

    return json.loads(response.text)


#
# OAuth implementation
#


def test_oauth_implementation_name(
    hass: HomeAssistant,
) -> None:
    """Test OAuth implementation name."""

    implementation = AuchanOAuth2Implementation(hass)

    assert implementation.name == "Auchan"

    assert implementation.expected_state is None
    assert implementation.oauth_redirect_uri is None


async def test_generate_authorize_url(
    hass: HomeAssistant,
) -> None:
    """Test OAuth authorization URL generation."""

    implementation = AuchanOAuth2Implementation(hass)

    flow_id = "test-flow-id"

    fake_state = "fake-oauth-state"

    with (
        patch(
            "custom_components.auchan.oauth.get_url",
            return_value="https://homeassistant.example/",
        ) as mock_get_url,
        patch(
            "custom_components.auchan.oauth.secrets.token_urlsafe",
            return_value=fake_state,
        ) as mock_token_urlsafe,
    ):
        result = await implementation.async_generate_authorize_url(flow_id)

    #
    # Home Assistant base URL retrieval
    #
    mock_get_url.assert_called_once_with(
        hass,
        require_current_request=True,
    )

    #
    # CSRF state generation
    #
    mock_token_urlsafe.assert_called_once_with(32)

    assert implementation.expected_state == fake_state

    #
    # Expected bridge callback
    #
    bridge_url = f"https://homeassistant.example{OAUTH_CALLBACK_PATH}?flow_id={flow_id}"

    encoded_bridge_url = bridge_url.encode("utf-8").hex()

    expected_redirect_uri = f"{AUCHAN_LOGIN_URL}/{encoded_bridge_url}?auth_callback=1"

    assert implementation.oauth_redirect_uri == expected_redirect_uri

    #
    # Check final Auchan authorization URL.
    #
    authorize_url = URL(result)

    expected_authorize_url = URL(AUTHORIZE_URL)

    assert authorize_url.scheme == expected_authorize_url.scheme

    assert authorize_url.host == expected_authorize_url.host

    assert authorize_url.path == expected_authorize_url.path

    query = authorize_url.query

    assert query["client_id"] == CLIENT_ID
    assert query["redirect_uri"] == expected_redirect_uri
    assert query["scope"] == "openid"
    assert query["response_type"] == "code"
    assert query["response_mode"] == "fragment"
    assert query["state"] == fake_state


async def test_resolve_external_data(
    hass: HomeAssistant,
) -> None:
    """Test authorization code exchange."""

    implementation = AuchanOAuth2Implementation(hass)

    implementation.oauth_redirect_uri = "https://example.com/oauth/callback"

    token_data = {
        "access_token": "access-token",
        "refresh_token": "refresh-token",
        "expires_in": 3600,
    }

    with patch.object(
        implementation,
        "_token_request",
        new=AsyncMock(return_value=token_data),
    ) as mock_token_request:
        result = await implementation.async_resolve_external_data(
            {
                "code": "authorization-code",
                "state": "state",
            }
        )

    assert result == token_data

    mock_token_request.assert_awaited_once_with(
        {
            "grant_type": "authorization_code",
            "code": "authorization-code",
            "redirect_uri": ("https://example.com/oauth/callback"),
        }
    )


async def test_resolve_external_data_without_redirect_uri(
    hass: HomeAssistant,
) -> None:
    """Test missing OAuth redirect URI."""

    implementation = AuchanOAuth2Implementation(hass)

    assert implementation.oauth_redirect_uri is None

    with pytest.raises(
        RuntimeError,
        match="Auchan OAuth redirect URI is missing",
    ):
        await implementation.async_resolve_external_data(
            {
                "code": "authorization-code",
            }
        )


async def test_resolve_external_data_without_code(
    hass: HomeAssistant,
) -> None:
    """Test missing OAuth authorization code."""

    implementation = AuchanOAuth2Implementation(hass)

    implementation.oauth_redirect_uri = "https://example.com/oauth/callback"

    with pytest.raises(
        ValueError,
        match="OAuth authorization code missing",
    ):
        await implementation.async_resolve_external_data({})


#
# OAuth callback GET
#


async def test_oauth_callback_get() -> None:
    """Test OAuth landing page."""

    view = AuchanOAuthCallbackView()

    request = MagicMock()

    html = """
    <!DOCTYPE html>
    <html>
        <body>
            Auchan OAuth
        </body>
    </html>
    """

    with patch(
        "custom_components.auchan.oauth.Path.read_text",
        return_value=html,
    ) as mock_read_text:
        response = await view.get(request)

    assert response.status == 200

    assert response.content_type == "text/html"

    assert response.text == html

    mock_read_text.assert_called_once_with(encoding="utf-8")

    #
    # Security / cache headers
    #
    assert response.headers["Cache-Control"] == "no-store, max-age=0"

    assert response.headers["Pragma"] == "no-cache"

    assert response.headers["Referrer-Policy"] == "no-referrer"

    assert response.headers["X-Content-Type-Options"] == "nosniff"

    assert "default-src 'none'" in response.headers["Content-Security-Policy"]


def test_oauth_callback_view_configuration() -> None:
    """Test OAuth callback view configuration."""

    assert AuchanOAuthCallbackView.url == OAUTH_CALLBACK_PATH

    assert AuchanOAuthCallbackView.name == OAUTH_CALLBACK_NAME

    assert AuchanOAuthCallbackView.requires_auth is False


#
# OAuth callback POST validation
#


async def test_oauth_callback_invalid_json(
    hass: HomeAssistant,
) -> None:
    """Test malformed callback JSON."""

    view = AuchanOAuthCallbackView()

    request = create_request(
        hass,
        error=json.JSONDecodeError(
            "Invalid JSON",
            "",
            0,
        ),
    )

    response = await view.post(request)

    assert response.status == 400

    assert get_json(response) == {
        "error": "invalid_json",
    }


@pytest.mark.parametrize(
    (
        "payload",
        "expected_error",
    ),
    [
        (
            {
                "state": "state",
                "code": "code",
            },
            "missing_flow_id",
        ),
        (
            {
                "flow_id": "flow-id",
                "code": "code",
            },
            "missing_state",
        ),
        (
            {
                "flow_id": "flow-id",
                "state": "state",
            },
            "missing_code",
        ),
    ],
)
async def test_oauth_callback_missing_data(
    hass: HomeAssistant,
    payload: dict,
    expected_error: str,
) -> None:
    """Test missing OAuth callback parameters."""

    view = AuchanOAuthCallbackView()

    request = create_request(
        hass,
        payload,
    )

    response = await view.post(request)

    assert response.status == 400

    assert get_json(response) == {
        "error": expected_error,
    }


#
# Successful OAuth callback
#


async def test_oauth_callback_success(
    hass: HomeAssistant,
) -> None:
    """Test successful OAuth callback."""

    view = AuchanOAuthCallbackView()

    request = create_request(
        hass,
        {
            "flow_id": "flow-id",
            "state": "oauth-state",
            "code": "authorization-code",
        },
    )

    with patch.object(
        hass.config_entries.flow,
        "async_configure",
        new=AsyncMock(),
    ) as mock_configure:
        response = await view.post(request)

    assert response.status == 200

    assert get_json(response) == {
        "success": True,
    }

    mock_configure.assert_awaited_once_with(
        flow_id="flow-id",
        user_input={
            "state": "oauth-state",
            "code": "authorization-code",
        },
    )


#
# OAuth callback containing an OAuth error
#


async def test_oauth_callback_oauth_error(
    hass: HomeAssistant,
) -> None:
    """Test OAuth provider error callback."""

    view = AuchanOAuthCallbackView()

    request = create_request(
        hass,
        {
            "flow_id": "flow-id",
            "state": "oauth-state",
            "error": "access_denied",
            "error_description": ("User cancelled login"),
        },
    )

    with patch.object(
        hass.config_entries.flow,
        "async_configure",
        new=AsyncMock(),
    ) as mock_configure:
        response = await view.post(request)

    assert response.status == 200

    assert get_json(response) == {
        "success": True,
    }

    mock_configure.assert_awaited_once_with(
        flow_id="flow-id",
        user_input={
            "state": "oauth-state",
            "error": "access_denied",
            "error_description": ("User cancelled login"),
        },
    )


async def test_oauth_callback_error_without_description(
    hass: HomeAssistant,
) -> None:
    """Test OAuth error without description."""

    view = AuchanOAuthCallbackView()

    request = create_request(
        hass,
        {
            "flow_id": "flow-id",
            "state": "oauth-state",
            "error": "access_denied",
        },
    )

    with patch.object(
        hass.config_entries.flow,
        "async_configure",
        new=AsyncMock(),
    ) as mock_configure:
        response = await view.post(request)

    assert response.status == 200

    mock_configure.assert_awaited_once_with(
        flow_id="flow-id",
        user_input={
            "state": "oauth-state",
            "error": "access_denied",
        },
    )


#
# Unknown / expired flow
#


async def test_oauth_callback_unknown_flow(
    hass: HomeAssistant,
) -> None:
    """Test callback for unknown or expired flow."""

    view = AuchanOAuthCallbackView()

    request = create_request(
        hass,
        {
            "flow_id": "expired-flow",
            "state": "oauth-state",
            "code": "authorization-code",
        },
    )

    with patch.object(
        hass.config_entries.flow,
        "async_configure",
        new=AsyncMock(side_effect=data_entry_flow.UnknownFlow),
    ):
        response = await view.post(request)

    assert response.status == 410

    assert get_json(response) == {
        "error": "unknown_or_expired_flow",
    }


#
# Unexpected flow error
#


async def test_oauth_callback_flow_error(
    hass: HomeAssistant,
) -> None:
    """Test unexpected config flow failure."""

    view = AuchanOAuthCallbackView()

    request = create_request(
        hass,
        {
            "flow_id": "flow-id",
            "state": "oauth-state",
            "code": "authorization-code",
        },
    )

    with patch.object(
        hass.config_entries.flow,
        "async_configure",
        new=AsyncMock(side_effect=RuntimeError("Something went wrong")),
    ):
        response = await view.post(request)

    assert response.status == 500

    assert get_json(response) == {
        "error": "flow_error",
    }


#
# Callback registration
#


def test_register_oauth_callback() -> None:
    """Test OAuth callback registration."""

    hass = MagicMock()

    hass.data = {}

    hass.http = MagicMock()

    async_register_oauth_callback(hass)

    hass.http.register_view.assert_called_once_with(AuchanOAuthCallbackView)

    assert hass.data[DATA_CALLBACK_REGISTERED] is True


def test_register_oauth_callback_only_once() -> None:
    """Test OAuth callback is only registered once."""

    hass = MagicMock()

    hass.data = {}

    hass.http = MagicMock()

    async_register_oauth_callback(hass)
    async_register_oauth_callback(hass)

    hass.http.register_view.assert_called_once_with(AuchanOAuthCallbackView)

    assert hass.data[DATA_CALLBACK_REGISTERED] is True


#
# OAuth implementation registration
#


def test_register_oauth_implementation() -> None:
    """Test runtime OAuth implementation registration."""

    hass = MagicMock()

    hass.data = {}

    implementation = MagicMock()

    with (
        patch(
            "custom_components.auchan.oauth.AuchanOAuth2Implementation",
            return_value=implementation,
        ) as mock_implementation,
        patch(
            "custom_components.auchan.oauth."
            "config_entry_oauth2_flow."
            "async_register_implementation"
        ) as mock_register,
    ):
        async_register_oauth_implementation(hass)

    mock_implementation.assert_called_once_with(hass)

    mock_register.assert_called_once_with(
        hass,
        DOMAIN,
        implementation,
    )

    assert hass.data[DATA_IMPLEMENTATION_REGISTERED] is True


def test_register_oauth_implementation_only_once() -> None:
    """Test OAuth implementation registration is idempotent."""

    hass = MagicMock()

    hass.data = {}

    implementation = MagicMock()

    with (
        patch(
            "custom_components.auchan.oauth.AuchanOAuth2Implementation",
            return_value=implementation,
        ) as mock_implementation,
        patch(
            "custom_components.auchan.oauth."
            "config_entry_oauth2_flow."
            "async_register_implementation"
        ) as mock_register,
    ):
        async_register_oauth_implementation(hass)

        async_register_oauth_implementation(hass)

    mock_implementation.assert_called_once_with(hass)

    mock_register.assert_called_once_with(
        hass,
        DOMAIN,
        implementation,
    )

    assert hass.data[DATA_IMPLEMENTATION_REGISTERED] is True
