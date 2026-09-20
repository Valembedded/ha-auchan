"""Tests for the Auchan config flow."""

from unittest.mock import AsyncMock, MagicMock, patch

from aiohttp import ClientError
from custom_components.auchan.config_flow import AuchanConfigFlow
from custom_components.auchan.const import DOMAIN
from homeassistant.config_entries import SOURCE_REAUTH, SOURCE_USER
from homeassistant.core import HomeAssistant
from homeassistant.data_entry_flow import FlowResultType
from homeassistant.helpers import config_entry_oauth2_flow
from pytest_homeassistant_custom_component.common import MockConfigEntry

OAUTH_DATA = {
    "auth_implementation": DOMAIN,
    "token": {
        "access_token": "fake_access_token",
        "refresh_token": "fake_refresh_token",
        "expires_in": 3600,
        "expires_at": 9999999999,
        "token_type": "Bearer",
    },
}


PROFILE = {
    "authenticated": True,
    "given_name": "Jean",
    "email": "jean@example.com",
    "rcw_id": "123456789",
}


def create_flow(
    hass: HomeAssistant,
    source: str = SOURCE_USER,
) -> AuchanConfigFlow:
    """Create an Auchan config flow for tests."""

    flow = AuchanConfigFlow()

    flow.hass = hass
    flow.context = {
        "source": source,
    }

    return flow


async def test_user_starts_oauth(
    hass: HomeAssistant,
) -> None:
    """Test starting OAuth from the user step."""

    flow = create_flow(hass)

    expected_result = {
        "test": "oauth_started",
    }

    with patch.object(
        flow,
        "_async_start_oauth",
        new=AsyncMock(return_value=expected_result),
    ) as mock_start_oauth:
        result = await flow.async_step_user()

    assert result == expected_result

    mock_start_oauth.assert_awaited_once_with()


async def test_user_aborts_if_account_already_configured(
    hass: HomeAssistant,
) -> None:
    """Test only one Auchan account can be configured."""

    entry = MockConfigEntry(
        domain=DOMAIN,
        title="Existing Auchan account",
        data=OAUTH_DATA,
    )

    entry.add_to_hass(hass)

    flow = create_flow(hass)

    result = await flow.async_step_user()

    assert result["type"] is FlowResultType.ABORT
    assert result["reason"] == "account_already_configured"


async def test_start_oauth(
    hass: HomeAssistant,
) -> None:
    """Test Auchan OAuth initialization."""

    flow = create_flow(hass)

    implementation = MagicMock()

    expected_result = {
        "test": "auth_step",
    }

    with (
        patch(
            "custom_components.auchan.config_flow.async_register_oauth_callback"
        ) as mock_register_callback,
        patch(
            "custom_components.auchan.config_flow.AuchanOAuth2Implementation",
            return_value=implementation,
        ) as mock_implementation_class,
        patch.object(
            flow,
            "async_step_auth",
            new=AsyncMock(return_value=expected_result),
        ) as mock_auth,
    ):
        result = await flow._async_start_oauth()

    assert result == expected_result

    mock_register_callback.assert_called_once_with(hass)

    mock_implementation_class.assert_called_once_with(hass)

    assert flow.flow_impl is implementation

    mock_auth.assert_awaited_once_with()


async def test_auth_rejects_invalid_state(
    hass: HomeAssistant,
) -> None:
    """Test OAuth callback with invalid state."""

    flow = create_flow(hass)

    implementation = MagicMock()
    implementation.expected_state = "correct_state"

    flow.flow_impl = implementation

    result = await flow.async_step_auth(
        {
            "code": "fake_code",
            "state": "wrong_state",
        }
    )

    assert result["type"] is FlowResultType.ABORT
    assert result["reason"] == "oauth_failed"


async def test_auth_rejects_missing_state(
    hass: HomeAssistant,
) -> None:
    """Test OAuth callback without state."""

    flow = create_flow(hass)

    implementation = MagicMock()
    implementation.expected_state = "correct_state"

    flow.flow_impl = implementation

    result = await flow.async_step_auth(
        {
            "code": "fake_code",
        }
    )

    assert result["type"] is FlowResultType.ABORT
    assert result["reason"] == "oauth_failed"


async def test_auth_accepts_valid_state(
    hass: HomeAssistant,
) -> None:
    """Test OAuth callback with valid state."""

    flow = create_flow(hass)

    implementation = MagicMock()
    implementation.expected_state = "correct_state"

    flow.flow_impl = implementation

    user_input = {
        "code": "fake_code",
        "state": "correct_state",
    }

    expected_result = {
        "test": "home_assistant_oauth",
    }

    with patch.object(
        config_entry_oauth2_flow.AbstractOAuth2FlowHandler,
        "async_step_auth",
        autospec=True,
        return_value=expected_result,
    ) as mock_super_auth:
        result = await flow.async_step_auth(user_input)

    assert result == expected_result

    mock_super_auth.assert_awaited_once_with(
        flow,
        user_input,
    )


async def test_oauth_create_entry_without_token(
    hass: HomeAssistant,
) -> None:
    """Test OAuth response without token data."""

    flow = create_flow(hass)

    data = {
        "auth_implementation": DOMAIN,
    }

    result = await flow.async_oauth_create_entry(data)

    assert result["type"] is FlowResultType.ABORT
    assert result["reason"] == "oauth_failed"

    assert flow._oauth_data == data


async def test_oauth_create_entry_without_access_token(
    hass: HomeAssistant,
) -> None:
    """Test OAuth response without access token."""

    flow = create_flow(hass)

    data = {
        "auth_implementation": DOMAIN,
        "token": {
            "refresh_token": "fake_refresh_token",
        },
    }

    result = await flow.async_oauth_create_entry(data)

    assert result["type"] is FlowResultType.ABORT
    assert result["reason"] == "oauth_failed"


async def test_oauth_create_entry_profile_connection_error(
    hass: HomeAssistant,
) -> None:
    """Test error while retrieving Auchan profile."""

    flow = create_flow(hass)

    session = MagicMock()

    with (
        patch(
            "custom_components.auchan.config_flow.async_get_clientsession",
            return_value=session,
        ),
        patch(
            "custom_components.auchan.config_flow.async_get_user_info_for_setup",
            new=AsyncMock(side_effect=ClientError()),
        ) as mock_get_profile,
    ):
        result = await flow.async_oauth_create_entry(OAUTH_DATA)

    assert result["type"] is FlowResultType.ABORT
    assert result["reason"] == "cannot_connect"

    mock_get_profile.assert_awaited_once_with(
        session,
        "fake_access_token",
    )


async def test_oauth_create_entry_invalid_profile(
    hass: HomeAssistant,
) -> None:
    """Test invalid Auchan profile response."""

    flow = create_flow(hass)

    session = MagicMock()

    with (
        patch(
            "custom_components.auchan.config_flow.async_get_clientsession",
            return_value=session,
        ),
        patch(
            "custom_components.auchan.config_flow.async_get_user_info_for_setup",
            new=AsyncMock(side_effect=ValueError()),
        ),
    ):
        result = await flow.async_oauth_create_entry(OAUTH_DATA)

    assert result["type"] is FlowResultType.ABORT
    assert result["reason"] == "cannot_connect"


async def test_oauth_create_entry_not_authenticated(
    hass: HomeAssistant,
) -> None:
    """Test Auchan profile reports user not authenticated."""

    flow = create_flow(hass)

    session = MagicMock()

    profile = {
        "authenticated": False,
    }

    with (
        patch(
            "custom_components.auchan.config_flow.async_get_clientsession",
            return_value=session,
        ),
        patch(
            "custom_components.auchan.config_flow.async_get_user_info_for_setup",
            new=AsyncMock(return_value=profile),
        ),
    ):
        result = await flow.async_oauth_create_entry(OAUTH_DATA)

    assert result["type"] is FlowResultType.ABORT
    assert result["reason"] == "oauth_failed"


async def test_oauth_create_entry_success(
    hass: HomeAssistant,
) -> None:
    """Test successful Auchan authentication."""

    flow = create_flow(hass)

    session = MagicMock()

    with (
        patch(
            "custom_components.auchan.config_flow.async_get_clientsession",
            return_value=session,
        ),
        patch(
            "custom_components.auchan.config_flow.async_get_user_info_for_setup",
            new=AsyncMock(return_value=PROFILE),
        ) as mock_get_profile,
    ):
        result = await flow.async_oauth_create_entry(OAUTH_DATA)

    #
    # Profile request
    #
    mock_get_profile.assert_awaited_once_with(
        session,
        "fake_access_token",
    )

    #
    # OAuth data stored until welcome confirmation.
    #
    assert flow._oauth_data == OAUTH_DATA

    #
    # Profile information
    #
    assert flow._display_name == "Jean"
    assert flow._email == "jean@example.com"
    assert flow._rcw_id == "123456789"

    #
    # Config Entry title
    #
    assert flow._entry_title == "123456789 - jean@example.com"

    #
    # Unique ID
    #
    assert flow.unique_id == "123456789"

    #
    # Welcome screen
    #
    assert result["type"] is FlowResultType.FORM
    assert result["step_id"] == "welcome"

    assert result["description_placeholders"] == {
        "name": "Jean",
        "email": "jean@example.com",
        "rcw_id": "123456789",
    }

    assert result["last_step"] is True


async def test_welcome_creates_entry(
    hass: HomeAssistant,
) -> None:
    """Test welcome confirmation creates config entry."""

    flow = create_flow(hass)

    flow._oauth_data = OAUTH_DATA
    flow._entry_title = "123456789 - jean@example.com"

    result = await flow.async_step_welcome({})

    assert result["type"] is FlowResultType.CREATE_ENTRY

    assert result["title"] == ("123456789 - jean@example.com")

    assert result["data"] == OAUTH_DATA


async def test_welcome_without_oauth_data(
    hass: HomeAssistant,
) -> None:
    """Test welcome without stored OAuth data."""

    flow = create_flow(hass)

    result = await flow.async_step_welcome({})

    assert result["type"] is FlowResultType.ABORT
    assert result["reason"] == "oauth_failed"


async def test_reauth_starts_oauth(
    hass: HomeAssistant,
) -> None:
    """Test reauthentication starts OAuth again."""

    flow = create_flow(
        hass,
        source=SOURCE_REAUTH,
    )

    expected_result = {
        "test": "oauth_started",
    }

    with patch.object(
        flow,
        "_async_start_oauth",
        new=AsyncMock(return_value=expected_result),
    ) as mock_start_oauth:
        result = await flow.async_step_reauth(OAUTH_DATA)

    assert result == expected_result

    mock_start_oauth.assert_awaited_once_with()


async def test_welcome_reauth_success(
    hass: HomeAssistant,
) -> None:
    """Test successful reauthentication."""

    entry = MockConfigEntry(
        domain=DOMAIN,
        title="Old title",
        unique_id="123456789",
        data={
            "old": "data",
        },
    )

    entry.add_to_hass(hass)

    flow = create_flow(
        hass,
        source=SOURCE_REAUTH,
    )

    flow.context["entry_id"] = entry.entry_id

    flow._oauth_data = OAUTH_DATA
    flow._entry_title = "123456789 - jean@example.com"

    expected_result = {
        "type": FlowResultType.ABORT,
        "reason": "reauth_successful",
    }

    with patch.object(
        flow,
        "async_update_reload_and_abort",
        return_value=expected_result,
    ) as mock_update:
        result = await flow.async_step_welcome({})

    assert result == expected_result

    #
    # Title updated.
    #
    assert entry.title == ("123456789 - jean@example.com")

    #
    # OAuth data passed for ConfigEntry update.
    #
    mock_update.assert_called_once_with(
        entry,
        data_updates=OAUTH_DATA,
        reason="reauth_successful",
    )
