"""Schemas for lab controls and configuration."""

from pydantic import BaseModel, Field


class LabModeResponse(BaseModel):
    mode: str = Field(
        ...,
        description="Currently active lab operational mode ('vulnerable' or 'fixed')",
        examples=["vulnerable"],
    )
    message: str = Field(
        ...,
        description="Description and status of the active mode",
        examples=["Current lab mode is 'vulnerable'. Vulnerabilities are actively exploitable."],
    )

    model_config = {
        "json_schema_extra": {
            "example": {
                "mode": "vulnerable",
                "message": "Current lab mode is 'vulnerable'. Vulnerabilities are actively exploitable.",
            }
        }
    }


class LabModeUpdateRequest(BaseModel):
    mode: str = Field(
        ...,
        description="Target lab mode ('vulnerable' or 'fixed')",
        examples=["fixed"],
    )

    model_config = {
        "json_schema_extra": {
            "example": {
                "mode": "fixed",
            }
        }
    }


class LabModeUpdateResponse(BaseModel):
    status: str = Field(..., description="Operation status ('success')", examples=["success"])
    mode: str = Field(..., description="Active lab mode after the switch", examples=["fixed"])
    message: str = Field(
        ...,
        description="Status message confirming the applied change",
        examples=["Lab mode successfully switched to 'fixed'."],
    )

    model_config = {
        "json_schema_extra": {
            "example": {
                "status": "success",
                "mode": "fixed",
                "message": "Lab mode successfully switched to 'fixed'.",
            }
        }
    }
