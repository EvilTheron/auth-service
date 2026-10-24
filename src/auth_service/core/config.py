from functools import lru_cache

from pydantic import SecretStr, field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict
from sqlalchemy.engine import URL


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", extra="ignore")

    postgres_user: str
    postgres_password: SecretStr
    postgres_db: str
    postgres_host: str = "127.0.0.1"
    postgres_port: int = 5432

    redis_host: str = "127.0.0.1"
    redis_port: int = 6379
    redis_password: SecretStr | None = None

    jwt_secret: SecretStr
    jwt_algorithm: str = "HS256"
    access_token_expire_minutes: int = 15
    refresh_token_expire_days: int = 30

    leaked_passwords_filter_path: str = "data/leaked_passwords.bloom"

    log_level: str = "INFO"
    docs_enabled: bool = True

    @property
    def redis_password_value(self) -> str | None:
        return self.redis_password.get_secret_value() if self.redis_password else None

    @property
    def database_url(self) -> URL:
        return URL.create(
            "postgresql+asyncpg",
            username=self.postgres_user,
            password=self.postgres_password.get_secret_value(),
            host=self.postgres_host,
            port=self.postgres_port,
            database=self.postgres_db,
        )

    @field_validator("jwt_secret")
    @classmethod
    def jwt_secret_must_be_strong(cls, value: SecretStr) -> SecretStr:
        if len(value.get_secret_value()) < 32:
            raise ValueError("JWT_SECRET must be at least 32 characters long")
        return value


@lru_cache
def get_settings() -> Settings:
    return Settings()
