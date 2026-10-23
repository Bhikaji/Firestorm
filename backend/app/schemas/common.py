from __future__ import annotations

from datetime import UTC, datetime
from typing import Generic, TypeVar

from pydantic import BaseModel, ConfigDict, Field

T = TypeVar("T")


class ORMModel(BaseModel):
    model_config = ConfigDict(from_attributes=True)


class Page(BaseModel, Generic[T]):
    items: list[T]
    total: int
    page: int
    page_size: int

    @property
    def pages(self) -> int:
        return max(1, -(-self.total // self.page_size))


class Message(BaseModel):
    message: str
    detail: str | None = None


class TimeRange(BaseModel):
    start: datetime | None = None
    end: datetime | None = None

    def normalised(self) -> tuple[datetime | None, datetime | None]:
        def _aware(value: datetime | None) -> datetime | None:
            if value is None:
                return None
            return value if value.tzinfo else value.replace(tzinfo=UTC)

        return _aware(self.start), _aware(self.end)


class SortSpec(BaseModel):
    field: str = Field(default="created_at", max_length=40)
    direction: str = Field(default="desc", pattern="^(asc|desc)$")
