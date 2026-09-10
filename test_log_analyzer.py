from log_analyzer import get_risk_level, get_recommendation


def test_low_risk():
    assert get_risk_level(2) == "LOW"


def test_medium_risk():
    assert get_risk_level(3) == "MEDIUM"


def test_high_risk():
    assert get_risk_level(5) == "HIGH"


def test_high_risk_recommendation():
    result = get_recommendation("HIGH")
    assert "blocking" in result.lower()