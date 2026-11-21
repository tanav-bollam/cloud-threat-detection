"""pydantic model of the CloudTrail record (management + S3 data events), modelled on the AWS
"CloudTrail record contents" documentation. extra="forbid" so the generator cannot invent fields."""
from __future__ import annotations

import re
from typing import Any, Literal, Optional

from pydantic import BaseModel, ConfigDict, field_validator

_TIME = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$")
_UUID = re.compile(r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$")
_IP = re.compile(r"^(\d{1,3}\.){3}\d{1,3}$")


class _Strict(BaseModel):
    model_config = ConfigDict(extra="forbid")


class SessionIssuer(_Strict):
    type: str
    principalId: str
    arn: str
    accountId: str
    userName: str


class SessionContext(_Strict):
    attributes: dict[str, Any]
    sessionIssuer: Optional[SessionIssuer] = None


class UserIdentity(_Strict):
    type: Literal["IAMUser", "AssumedRole", "Root", "AWSService"]
    principalId: str
    arn: str
    accountId: str
    accessKeyId: Optional[str] = None
    userName: Optional[str] = None
    invokedBy: Optional[str] = None
    sessionContext: Optional[SessionContext] = None

    @field_validator("arn")
    @classmethod
    def _arn(cls, v: str) -> str:
        if not v.startswith("arn:aws:"):
            raise ValueError("bad arn")
        return v

    @field_validator("accessKeyId")
    @classmethod
    def _akid(cls, v: Optional[str]) -> Optional[str]:
        if v and not re.match(r"^(AKIA|ASIA)[A-Z0-9]{16}$", v):
            raise ValueError(f"bad access key id {v}")
        return v


class CloudTrailRecord(_Strict):
    eventVersion: str
    userIdentity: UserIdentity
    eventTime: str
    eventSource: str
    eventName: str
    awsRegion: str
    sourceIPAddress: str
    userAgent: str
    errorCode: Optional[str] = None
    errorMessage: Optional[str] = None
    requestParameters: Optional[dict[str, Any]] = None
    responseElements: Optional[dict[str, Any]] = None
    additionalEventData: Optional[dict[str, Any]] = None
    requestID: str
    eventID: str
    readOnly: bool
    resources: Optional[list[dict[str, Any]]] = None
    eventType: Literal["AwsApiCall", "AwsConsoleSignIn", "AwsServiceEvent"]
    managementEvent: bool
    recipientAccountId: str
    eventCategory: Literal["Management", "Data"]

    @field_validator("eventTime")
    @classmethod
    def _time(cls, v: str) -> str:
        if not _TIME.match(v):
            raise ValueError("eventTime must be YYYY-MM-DDTHH:MM:SSZ")
        return v

    @field_validator("eventID")
    @classmethod
    def _eid(cls, v: str) -> str:
        if not _UUID.match(v):
            raise ValueError("eventID must be a lowercase uuid")
        return v

    @field_validator("sourceIPAddress")
    @classmethod
    def _ip(cls, v: str) -> str:
        if not (_IP.match(v) or v.endswith(".amazonaws.com")):
            raise ValueError("sourceIPAddress must be IPv4 or a service name")
        return v

    @field_validator("eventSource")
    @classmethod
    def _src(cls, v: str) -> str:
        if not v.endswith(".amazonaws.com"):
            raise ValueError("eventSource must end with .amazonaws.com")
        return v


def validate_record(rec: dict) -> CloudTrailRecord:
    return CloudTrailRecord.model_validate(rec)
