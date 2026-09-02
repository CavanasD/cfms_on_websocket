"""Preserve Thesis extension JSON Schema contracts on CFMS 26's model boundary."""

from typing import ClassVar

from jsonschema import Draft7Validator
from pydantic import ConfigDict, model_validator

from include.transport.request_handler import RequestDataModel, RequestHandler


class ThesisRequestDataModel(RequestDataModel):
    model_config = ConfigDict(strict=True, extra="allow")
    validator: ClassVar[Draft7Validator]

    @model_validator(mode="before")
    @classmethod
    def validate_contract(cls, value):
        error = next(cls.validator.iter_errors(value), None)
        if error is not None:
            # Do not include submitted credentials or attachment contents in errors.
            raise ValueError(f"Invalid extension parameter ({error.validator})")
        return value


class ThesisRequestHandler(RequestHandler):
    def __init_subclass__(cls, **kwargs):
        super().__init_subclass__(**kwargs)
        if "schema" in cls.__dict__:
            Draft7Validator.check_schema(cls.schema)
            cls.request_model = type(
                f"{cls.__name__}Data",
                (ThesisRequestDataModel,),
                {"validator": Draft7Validator(cls.schema), "__module__": cls.__module__},
            )
