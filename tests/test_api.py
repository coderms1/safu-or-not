# test_api.py
from fastapi.testclient import TestClient
from app.main import app

client = TestClient(app)

def test_root_check():
    res = client.post("/check", json={"url": "http://example.com"})
    assert res.status_code == 200
    assert "status" in res.json()
