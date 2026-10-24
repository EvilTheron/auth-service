from httpx import AsyncClient

from auth_service.api.deps import get_password_filter
from auth_service.main import app
from tests.helpers import make_filter, register


async def test_register_rejects_leaked_password(client: AsyncClient):
    app.dependency_overrides[get_password_filter] = lambda: make_filter("password123")
    response = await register(client, password="password123")
    assert response.status_code == 400


async def test_register_accepts_password_not_in_filter(client: AsyncClient):
    app.dependency_overrides[get_password_filter] = lambda: make_filter("password123")
    response = await register(client, password="correct-horse-battery")
    assert response.status_code == 201
