"""Tests for lab management, hints, scoreboard, and flag submission."""

from pathlib import Path
from app.config import settings


def test_lab_reset(client):
    """Verify POST /lab/reset restores database to default seed state."""
    response = client.post("/lab/reset")
    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "success"
    assert "restored" in data["message"]


def test_lab_hints_disabled_and_enabled(client, monkeypatch):
    """Verify GET /lab/hints/{cat} honors LAB_HINTS setting."""
    # When off (default)
    monkeypatch.setattr(settings, "LAB_HINTS", "off")
    res_off = client.get("/lab/hints/API1")
    assert res_off.status_code == 200
    assert res_off.json()["status"] == "hints_disabled"

    # When on
    monkeypatch.setattr(settings, "LAB_HINTS", "on")
    res_on = client.get("/lab/hints/API1")
    assert res_on.status_code == 200
    assert res_on.json()["status"] == "active"
    assert "BOLA" in res_on.json()["title"]


def test_lab_scoreboard_and_flag_submission(client):
    """Verify scoreboard returns all 10 flags and correct submission awards points."""
    # Scoreboard before submission
    res_sb = client.get("/lab/scoreboard")
    assert res_sb.status_code == 200
    sb_data = res_sb.json()
    assert sb_data["total_challenges"] == 10
    assert sb_data["max_score"] == 1000

    # Submit invalid flag
    res_bad = client.post("/lab/flags/submit", json={"flag_code": "FLAG{INVALID_WRONG_CODE}"})
    assert res_bad.status_code == 400

    # Submit valid API1 flag
    res_good = client.post(
        "/lab/flags/submit",
        json={"flag_code": "FLAG{API1_BOLA_ORDER_DATA_EXPOSED_9182}"},
    )
    assert res_good.status_code == 200
    assert res_good.json()["status"] == "correct"
    assert res_good.json()["category"] == "API1"
    assert res_good.json()["points_awarded"] == 100

    # Submit duplicate
    res_dup = client.post(
        "/lab/flags/submit",
        json={"flag_code": "FLAG{API1_BOLA_ORDER_DATA_EXPOSED_9182}"},
    )
    assert res_dup.status_code == 200
    assert res_dup.json()["status"] == "already_solved"

    # Scoreboard after submission
    res_sb_after = client.get("/lab/scoreboard")
    assert res_sb_after.json()["total_score"] >= 100
    assert res_sb_after.json()["solved_count"] >= 1


def test_json_access_logging_middleware(client):
    """Verify structured JSON access log file is populated."""
    client.get("/health")
    log_file = Path("./logs/access.log")
    assert log_file.exists()
    content = log_file.read_text(encoding="utf-8")
    assert "/health" in content
    assert '"status_code": 200' in content
