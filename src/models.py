from pydantic import BaseModel

class Finding(BaseModel):
    scanner: str
    finding_id: str
    title: str
    resource: str
    file: str

    line_start: int | None = None
    line_end: int | None = None

    severity: str | None = None
    description: str | None = None
    guideline: str | None = None

    component: str | None = None
    installed_version: str | None = None
    fixed_version: str | None = None
    reference: str | None = None