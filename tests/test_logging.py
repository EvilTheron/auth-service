import logging

import pytest
from httpx import AsyncClient

from tests.helpers import PASSWORD, login, refresh, register


async def test_response_has_request_id(client: AsyncClient):
    response = await client.get("/health")
    assert len(response.headers["X-Request-ID"]) == 12


async def test_passwords_and_tokens_are_not_logged(
    client: AsyncClient, caplog: pytest.LogCaptureFixture
):
    caplog.set_level(logging.DEBUG)
    await register(client)
    tokens = (await login(client)).json()
    assert PASSWORD not in caplog.text
    assert tokens["access_token"] not in caplog.text
    assert tokens["refresh_token"] not in caplog.text


async def test_refresh_reuse_is_logged_as_warning(
    client: AsyncClient, caplog: pytest.LogCaptureFixture
):
    await register(client)
    tokens = (await login(client)).json()
    await refresh(client, tokens["refresh_token"])
    with caplog.at_level(logging.WARNING):
        await refresh(client, tokens["refresh_token"])
    assert "reuse detected" in caplog.text
