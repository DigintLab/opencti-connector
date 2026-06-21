from typing import TypeAlias

from pydantic import (
    BaseModel,
    ConfigDict,
    Field,
    JsonValue,
    RootModel,
    StrictStr,
    field_validator,
)

DepApiItem: TypeAlias = dict[str, JsonValue]


class CognitoAuthenticationResult(BaseModel):
    model_config = ConfigDict(extra="ignore", populate_by_name=True)

    id_token: StrictStr = Field(alias="IdToken")

    @field_validator("id_token")
    @classmethod
    def require_non_empty_token(cls, value: str) -> str:
        if not value:
            error = "Unable to retrieve IdToken from authentication response"
            raise ValueError(error)
        return value


class CognitoAuthResponse(BaseModel):
    model_config = ConfigDict(extra="ignore", populate_by_name=True)

    authentication_result: CognitoAuthenticationResult = Field(
        alias="AuthenticationResult"
    )


class DepApiResponse(RootModel[list[DepApiItem]]):
    pass
