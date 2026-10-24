from pathlib import Path

from fastapi.testclient import TestClient

from backend.main import app
from backend.services.threat_service import ThreatAnalysisRepository


client = TestClient(app)
FIXTURES_DIR = Path(__file__).resolve().parent.parent / "fixtures"


def _upload_fixture(name: str):
    with (FIXTURES_DIR / name).open("rb") as file_obj:
        return client.post(
            "/api/v1/analyze/file",
            files={"file": (name, file_obj, "application/octet-stream")},
        )


def test_file_prediction_is_returned_when_history_storage_fails(monkeypatch):
    def fail_history_write(self, record):
        raise RuntimeError("simulated read-only database")

    monkeypatch.setattr(ThreatAnalysisRepository, "create", fail_history_write)
    response = _upload_fixture("malicious_pe_benchmark.exe")

    assert response.status_code == 200
    result = response.json()
    assert result["input_type"] == "FILE"
    assert result["prediction"] == "Malicious"
    assert result["probability"] > 0.9
    assert result["history_saved"] is False


def test_file_analysis_reports_unavailable_model_instead_of_guessing(monkeypatch):
    import backend.services.threat_service as threat_service

    monkeypatch.setattr(threat_service, "MALWARE_MODEL", None)
    response = _upload_fixture("real_benign_sample.exe")

    assert response.status_code == 503
    assert "model is unavailable" in response.json()["detail"].lower()
