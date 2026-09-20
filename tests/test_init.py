"""Tests for the Auchan integration setup."""

from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from custom_components.auchan import async_setup, async_setup_entry
from custom_components.auchan.const import DOMAIN
from homeassistant.core import HomeAssistant
from pytest_homeassistant_custom_component.common import MockConfigEntry


@pytest.fixture
def mock_config_entry() -> MockConfigEntry:
    """Return a mocked Auchan config entry."""

    return MockConfigEntry(
        domain=DOMAIN,
        title="Compte Auchan",
        unique_id="test@example.com",
        data={
            "auth_implementation": DOMAIN,
            "token": {
                "access_token": "fake_access_token",
                "refresh_token": "fake_refresh_token",
                "expires_in": 3600,
                "expires_at": 9999999999,
                "token_type": "Bearer",
            },
        },
    )


async def test_async_setup(
    hass: HomeAssistant,
) -> None:
    """Test Auchan global setup."""

    with patch(
        "custom_components.auchan.async_register_oauth_implementation"
    ) as mock_register:
        result = await async_setup(
            hass,
            {},
        )

    assert result is True

    mock_register.assert_called_once_with(hass)


async def test_async_setup_entry(
    hass: HomeAssistant,
    mock_config_entry: MockConfigEntry,
) -> None:
    """Test Auchan config entry setup."""

    mock_config_entry.add_to_hass(hass)

    mock_implementation = MagicMock(name="AuchanOAuthImplementation")

    mock_oauth_session = MagicMock(name="OAuth2Session")

    mock_api = MagicMock(name="AuchanApiClient")

    with (
        patch(
            "custom_components.auchan.async_register_oauth_implementation"
        ) as mock_register,
        patch(
            "custom_components.auchan."
            "config_entry_oauth2_flow."
            "async_get_config_entry_implementation",
            new=AsyncMock(return_value=mock_implementation),
        ) as mock_get_implementation,
        patch(
            "custom_components.auchan.config_entry_oauth2_flow.OAuth2Session",
            return_value=mock_oauth_session,
        ) as mock_oauth_session_class,
        patch(
            "custom_components.auchan.AuchanApiClient",
            return_value=mock_api,
        ) as mock_api_class,
    ):
        result = await async_setup_entry(
            hass,
            mock_config_entry,
        )

    #
    # Setup succeeded.
    #
    assert result is True

    #
    # OAuth implementation was registered.
    #
    mock_register.assert_called_once_with(hass)

    #
    # HA retrieved the implementation specified by
    # entry.data["auth_implementation"].
    #
    mock_get_implementation.assert_awaited_once_with(
        hass,
        mock_config_entry,
    )

    #
    # OAuth2Session was created with the correct
    # Home Assistant instance, ConfigEntry and
    # OAuth implementation.
    #
    mock_oauth_session_class.assert_called_once_with(
        hass,
        mock_config_entry,
        mock_implementation,
    )

    #
    # AuchanApiClient received the OAuth2Session.
    #
    mock_api_class.assert_called_once_with(mock_oauth_session)

    #
    # The API client is stored as runtime data.
    #
    assert mock_config_entry.runtime_data is mock_api
