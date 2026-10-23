from app.services.risk_service import DeterministicRiskEngine
from app.models.finding import FindingSeverity, RiskLevel
from app.models.asset import BusinessCriticality, AssetExposure


def test_deterministic_risk_critical_scenario():
    score, level, rationale, breakdown = DeterministicRiskEngine.calculate_risk(
        severity=FindingSeverity.CRITICAL,
        asset_criticality=BusinessCriticality.CRITICAL,
        asset_exposure=AssetExposure.INTERNET_FACING,
        exploitability_factor=1.2,
        confidence_factor=1.0
    )
    # 90 * 1.30 * 1.25 * 1.2 * 1.0 = 175.5 -> clamped to 100.0
    assert score == 100.0
    assert level == RiskLevel.CRITICAL
    assert "Risk score 100.0" in rationale
    assert breakdown["engine_version"] == "1.0.0"


def test_deterministic_risk_low_internal_scenario():
    score, level, rationale, breakdown = DeterministicRiskEngine.calculate_risk(
        severity=FindingSeverity.LOW,
        asset_criticality=BusinessCriticality.LOW,
        asset_exposure=AssetExposure.RESTRICTED,
        exploitability_factor=1.0,
        confidence_factor=1.0
    )
    # 20 * 0.85 * 0.80 * 1.0 * 1.0 = 13.6
    assert score == 13.6
    assert level == RiskLevel.INFO
    assert breakdown["base_score"] == 20.0


def test_deterministic_risk_reproducibility():
    res1 = DeterministicRiskEngine.calculate_risk(
        severity=FindingSeverity.HIGH,
        asset_criticality=BusinessCriticality.HIGH,
        asset_exposure=AssetExposure.INTERNAL,
        exploitability_factor=1.0,
        confidence_factor=1.1
    )
    res2 = DeterministicRiskEngine.calculate_risk(
        severity=FindingSeverity.HIGH,
        asset_criticality=BusinessCriticality.HIGH,
        asset_exposure=AssetExposure.INTERNAL,
        exploitability_factor=1.0,
        confidence_factor=1.1
    )
    assert res1 == res2
