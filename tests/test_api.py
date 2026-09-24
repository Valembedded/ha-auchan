"""Tests for the Auchan API client."""

from unittest.mock import AsyncMock, MagicMock

from custom_components.auchan.api import (
    AuchanApiClient,
    async_get_user_info_for_setup,
)
from custom_components.auchan.const import AUCHAN_USER_INFO_URL


async def test_async_get_user_info() -> None:
    """Test retrieving user information with OAuth2Session."""

    expected_data = {
        "email": "test@example.com",
        "firstName": "Test",
        "lastName": "User",
    }

    #
    # Mock HTTP response
    #
    response = MagicMock()
    response.raise_for_status = MagicMock()
    response.json = AsyncMock(return_value=expected_data)

    #
    # Mock Home Assistant OAuth2Session
    #
    oauth_session = MagicMock()
    oauth_session.async_request = AsyncMock(return_value=response)

    #
    # Create API client
    #
    client = AuchanApiClient(oauth_session)

    result = await client.async_get_user_info()

    #
    # Verify result
    #
    assert result == expected_data

    #
    # Verify HTTP request
    #
    oauth_session.async_request.assert_awaited_once_with(
        "GET",
        AUCHAN_USER_INFO_URL,
        headers={
            "Accept": "application/json",
        },
    )

    #
    # Verify HTTP status was checked
    #
    response.raise_for_status.assert_called_once()

    #
    # Verify JSON was read
    #
    response.json.assert_awaited_once()


async def test_async_get_user_info_for_setup() -> None:
    """Test retrieving user information during OAuth setup."""

    access_token = "fake_access_token"

    expected_data = {
        "email": "test@example.com",
        "firstName": "Test",
        "lastName": "User",
    }

    #
    # Mock HTTP response
    #
    response = MagicMock()
    response.raise_for_status = MagicMock()
    response.json = AsyncMock(return_value=expected_data)

    #
    # Mock aiohttp ClientSession
    #
    session = MagicMock()
    session.get = AsyncMock(return_value=response)

    result = await async_get_user_info_for_setup(
        session,
        access_token,
    )

    #
    # Verify result
    #
    assert result == expected_data

    #
    # Verify request
    #
    session.get.assert_awaited_once_with(
        AUCHAN_USER_INFO_URL,
        headers={
            "Authorization": "Bearer fake_access_token",
            "Accept": "application/json",
        },
    )

    #
    # Verify HTTP status
    #
    response.raise_for_status.assert_called_once()

    #
    # Verify JSON
    #
    response.json.assert_awaited_once()
