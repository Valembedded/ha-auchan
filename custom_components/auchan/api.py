"""Auchan API client."""

from typing import Any

from aiohttp import ClientSession

from homeassistant.helpers.config_entry_oauth2_flow import OAuth2Session

from .const import AUCHAN_USER_INFO_URL


class AuchanApiClient:
    """Auchan API client."""

    def __init__(
        self,
        session: OAuth2Session,
    ) -> None:
        """Initialize Auchan API client."""

        self._session = session

    async def async_get_user_info(
        self,
    ) -> dict[str, Any]:
        """Retrieve Auchan user information."""

        response = await self._session.async_request(
            "GET",
            AUCHAN_USER_INFO_URL,
            headers={
                "Accept": "application/json",
            },
        )

        response.raise_for_status()

        return await response.json()


async def async_get_user_info_for_setup(
    session: ClientSession,
    access_token: str,
) -> dict[str, Any]:
    """Retrieve user information during initial OAuth setup."""

    response = await session.get(
        AUCHAN_USER_INFO_URL,
        headers={
            "Authorization": (f"Bearer {access_token}"),
            "Accept": "application/json",
        },
    )

    response.raise_for_status()

    return await response.json()
