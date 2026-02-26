from pydantic import Field, field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict

class DjangoSettings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=".env",
        extra="ignore",
    )

    DJANGO_SECRET_KEY: str
    FERNET_SECRET_KEY: str


class DatabaseSettings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
    )

    DB_NAME: str = Field(..., min_length=1)
    DB_USER: str = Field(..., min_length=1)
    DB_PASSWORD: str = Field(..., min_length=1)
    DB_HOST: str = Field(..., min_length=1)
    DB_PORT: int = Field(..., ge=1, le=65535)

    @field_validator("DB_HOST")
    @classmethod
    def validate_host(cls, v: str) -> str:
        if v.startswith("http"):
            raise ValueError("DB_HOST should not include protocol (http/https)")
        return v


class JWTSettings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=".env",
        extra="ignore",
    )

    SIGNING_KEY: str
    ACCESS_TOKEN_MINUTES: int = 15
    REFRESH_TOKEN_DAYS: int = 7
    ALGORITHM: str = "HS256"
    USER_ID_FIELD: str = "id"
    USER_ID_CLAIM: str = "user_id"
    LEEWAY: int = 5