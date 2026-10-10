import pytest
from fastapi.testclient import TestClient

from app.main import app


@pytest.fixture()
def client(tmp_path, monkeypatch):
    monkeypatch.setenv("SCAMGUARD_DB", str(tmp_path / "test.db"))
    monkeypatch.delenv("VT_API_KEY", raising=False)
    return TestClient(app)


def scan(client, message, **extra):
    response = client.post("/scan", json={"message": message, **extra})
    assert response.status_code == 200
    return response.json()


SCAMS = [
    ("Dear customer your KYC will expire today. Click http://sbi-kyc-update.xyz to avoid account block", "Bank / KYC Fraud"),
    ("Sir please share your OTP to receive the refund in your account", "OTP / PIN Theft"),
    ("Congratulations! You have won Rs 25 lakh in KBC lucky draw. Claim your prize now", "Lottery / Prize Scam"),
    ("Part time job work from home, earn Rs 5000 daily. Join Telegram group to start tasks", "Fake Job / Task Scam"),
    ("This is CBI. Your Aadhaar is linked to money laundering. You are under digital arrest, join video call", "Impersonation / Digital Arrest"),
    ("Your electricity will be disconnected tonight 9:30 pm because bill is unpaid. Call 98XXXXXXXX", "Electricity / Utility Bill Scam"),
    ("Guaranteed returns! Double your money in 7 days, join our WhatsApp group for crypto tips", "Investment / Crypto Scam"),
    ("आपका खाता बंद हो जाएगा, केवाईसी अपडेट करें immediately http://bit.ly/abc123", "Bank / KYC Fraud"),
]

SAFE = [
    "Hi, are we still meeting at 5 pm today?",
    "123456 is your OTP for login. Do not share this OTP with anyone. Valid for 10 minutes.",
    "Rs 500 debited from A/c XX1234 on 10-10-26 via UPI. If not you, call 1930.",
    "Your Amazon order has shipped. Track at https://www.amazon.in/orders",
    "Happy birthday! Let's catch up this weekend.",
    "Your package will be delivered tomorrow between 2 and 6 pm.",
]


@pytest.mark.parametrize("message,category", SCAMS)
def test_scams_are_flagged(client, message, category):
    result = scan(client, message)
    assert result["is_scam"] is True, message
    assert result["match"]["category_name"] == category
    assert result["match"]["explanation"]


@pytest.mark.parametrize("message", SAFE)
def test_safe_messages_pass(client, message):
    result = scan(client, message)
    assert result["is_scam"] is False, message
    assert result["match"] is None


def test_link_only_scam(client):
    result = scan(client, "Check this out http://192.168.4.7/secure-login-verify")
    assert result["is_scam"] is True
    assert result["match"]["category_name"] == "Suspicious Link"


def test_lookalike_domain_flagged_but_official_domain_not(client):
    assert scan(client, "Update details: http://sbi-secure-login.top/kyc")["is_scam"] is True
    assert scan(client, "Visit https://www.onlinesbi.sbi for netbanking")["is_scam"] is False


@pytest.mark.parametrize("lang,fragment", [("hi", "सावधान"), ("bn", "সতর্ক"), ("en", "Warning"), ("xx", "Warning")])
def test_regional_warnings(client, lang, fragment):
    result = scan(client, "Share your OTP now to claim your prize", lang=lang)
    assert fragment in result["warning"]


def test_empty_message_rejected(client):
    assert client.post("/scan", json={"message": ""}).status_code == 422


def test_digest_counts_per_user(client):
    scan(client, "Share your OTP to receive refund", user_id="grandma")
    scan(client, "Hi, how are you?", user_id="grandma")
    scan(client, "Hi, how are you?", user_id="someone_else")
    data = client.get("/digest/grandma?days=7").json()
    assert data["total_scans"] == 2
    assert data["scams_flagged"] == 1
    assert data["categories"] == {"OTP / PIN Theft": 1}
    assert "OTP / PIN Theft" in data["digest_text"]


def test_digest_empty_user(client):
    data = client.get("/digest/nobody").json()
    assert data["total_scans"] == 0
    assert "No messages" in data["digest_text"]


def test_digest_days_validated(client):
    assert client.get("/digest/x?days=0").status_code == 422
    assert client.get("/digest/x?days=500").status_code == 422
