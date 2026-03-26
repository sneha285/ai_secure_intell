from fastapi.testclient import TestClient

from app.main import app


def test_endpoint_blocks_high_risk_password():
    client = TestClient(app)
    payload = {
        "input_type": "text",
        "content": "User submitted password=supersecret123",
        "options": {"mask": True, "block_high_risk": True, "log_analysis": True},
    }
    resp = client.post("/analyze", json=payload)
    assert resp.status_code == 200
    data = resp.json()
    assert data["action"] == "blocked"
    assert data["risk_level"] in ("critical", "high")


def test_validation_requires_filename_for_file_input():
    client = TestClient(app)
    payload = {"input_type": "file", "content": "abc", "options": {"mask": True}}
    resp = client.post("/analyze", json=payload)
    assert resp.status_code == 400

