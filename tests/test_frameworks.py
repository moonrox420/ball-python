from __future__ import annotations

from pathlib import Path

import pytest

from pycleaner.dead_code_detector import DeadCodeDetector


def test_pydantic_model_fields_not_flagged_as_dead(tmp_path: Path) -> None:
    code = """
from pydantic import BaseModel, field_validator

class UserProfile(BaseModel):
    user_id: int
    username: str
    email: str = "default@domain.com"

    @field_validator("email")
    def validate_email(cls, v: str) -> str:
        return v.lower()
"""
    f = tmp_path / "models.py"
    f.write_text(code, encoding="utf-8")

    detector = DeadCodeDetector()
    report = detector.scan_project(tmp_path)

    # None of user_id, username, email, or validate_email should be flagged
    names_flagged = {item.name for item in report.items}
    assert "user_id" not in names_flagged
    assert "username" not in names_flagged
    assert "email" not in names_flagged
    assert "validate_email" not in names_flagged


def test_pytest_fixtures_and_marks_not_flagged(tmp_path: Path) -> None:
    code = """
import pytest

pytestmark = pytest.mark.unit

@pytest.fixture
def db_session():
    return {}

def test_something(db_session):
    assert True
"""
    f = tmp_path / "test_app.py"
    f.write_text(code, encoding="utf-8")

    detector = DeadCodeDetector()
    report = detector.scan_project(tmp_path)

    names_flagged = {item.name for item in report.items}
    assert "pytestmark" not in names_flagged
    assert "db_session" not in names_flagged
    assert "test_something" not in names_flagged


def test_fastapi_route_handlers_not_flagged(tmp_path: Path) -> None:
    code = """
from fastapi import FastAPI, APIRouter

app = FastAPI()
router = APIRouter()

@app.get("/health")
def health_check():
    return {"status": "ok"}

@router.post("/items")
async def create_item():
    return {"created": True}
"""
    f = tmp_path / "api.py"
    f.write_text(code, encoding="utf-8")

    detector = DeadCodeDetector()
    report = detector.scan_project(tmp_path)

    names_flagged = {item.name for item in report.items}
    assert "health_check" not in names_flagged
    assert "create_item" not in names_flagged


def test_sqlalchemy_models_not_flagged(tmp_path: Path) -> None:
    code = """
from sqlalchemy.orm import DeclarativeBase, Mapped

class Base(DeclarativeBase):
    pass

class Order(Base):
    __tablename__ = "orders"
    id: Mapped[int]
    total: Mapped[float]
"""
    f = tmp_path / "db.py"
    f.write_text(code, encoding="utf-8")

    detector = DeadCodeDetector()
    report = detector.scan_project(tmp_path)

    names_flagged = {item.name for item in report.items}
    assert "id" not in names_flagged
    assert "total" not in names_flagged
    assert "__tablename__" not in names_flagged


def test_dataclass_fields_not_flagged(tmp_path: Path) -> None:
    code = """
from dataclasses import dataclass

@dataclass
class Config:
    timeout: int = 30
    retries: int = 3

    def __post_init__(self):
        pass
"""
    f = tmp_path / "cfg.py"
    f.write_text(code, encoding="utf-8")

    detector = DeadCodeDetector()
    report = detector.scan_project(tmp_path)

    names_flagged = {item.name for item in report.items}
    assert "timeout" not in names_flagged
    assert "retries" not in names_flagged
    assert "__post_init__" not in names_flagged


def test_pytorch_model_methods_not_flagged(tmp_path: Path) -> None:
    code = """
import torch
import torch.nn as nn

class TransformerModel(nn.Module):
    def __init__(self):
        super().__init__()
        self.linear = nn.Linear(10, 10)

    def forward(self, x):
        return self.linear(x)

    def compute_loss(self, pred, target):
        return (pred - target).sum()
"""
    f = tmp_path / "model.py"
    f.write_text(code, encoding="utf-8")

    detector = DeadCodeDetector()
    report = detector.scan_project(tmp_path)

    names_flagged = {item.name for item in report.items}
    assert "forward" not in names_flagged
    assert "compute_loss" not in names_flagged


def test_pydantic_settings_and_model_post_init_not_flagged(tmp_path: Path) -> None:
    code = """
from pydantic_settings import BaseSettings, SettingsConfigDict

class AppConfig(BaseSettings):
    api_key: str = "secret"
    model_config = SettingsConfigDict(env_file=".env")

    def model_post_init(self, context) -> None:
        pass
"""
    f = tmp_path / "settings.py"
    f.write_text(code, encoding="utf-8")

    detector = DeadCodeDetector()
    report = detector.scan_project(tmp_path)

    names_flagged = {item.name for item in report.items}
    assert "api_key" not in names_flagged
    assert "model_config" not in names_flagged
    assert "model_post_init" not in names_flagged

