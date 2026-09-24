"""The Auchan integration."""

from homeassistant.config_entries import ConfigEntry
from homeassistant.core import HomeAssistant
from homeassistant.helpers import config_entry_oauth2_flow
from homeassistant.helpers.typing import ConfigType

from .api import AuchanApiClient
from .oauth import async_register_oauth_implementation


async def async_setup(
    hass: HomeAssistant,
    config: ConfigType,
) -> bool:
    """Set up the Auchan integration."""

    #
    # Register the OAuth implementation globally
    # so HA can retrieve it later using the
    # auth_implementation stored in ConfigEntry.
    #
    async_register_oauth_implementation(hass)

    return True


async def async_setup_entry(
    hass: HomeAssistant,
    entry: ConfigEntry,
) -> bool:
    """Set up Auchan from a config entry."""

    #
    # Defensive registration.
    #
    # async_register_oauth_implementation()
    # is idempotent.
    #
    async_register_oauth_implementation(hass)

    #
    # Retrieve the OAuth implementation referenced
    # by entry.data["auth_implementation"].
    #
    implementation = (
        await config_entry_oauth2_flow.async_get_config_entry_implementation(
            hass,
            entry,
        )
    )

    #
    # Home Assistant OAuth session.
    #
    # From this point on HA handles:
    #
    # - access_token
    # - expiration
    # - refresh_token
    # - ConfigEntry token updates
    # - Authorization: Bearer ...
    #
    oauth_session = config_entry_oauth2_flow.OAuth2Session(
        hass,
        entry,
        implementation,
    )

    #
    # Auchan API client.
    #
    api = AuchanApiClient(oauth_session)

    #
    # Store API client as runtime data.
    #
    entry.runtime_data = api

    return True
