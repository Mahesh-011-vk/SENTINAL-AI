from typing import Dict, Any, Tuple
from app.models.finding import FindingSeverity, RiskLevel
from app.models.asset import BusinessCriticality, AssetExposure
from app.config import settings


class DeterministicRiskEngine:
    """
    SentinelAI Deterministic Risk Engine v1.0.0
    
    Calculates internal platform risk score (0.0 to 100.0) and assigns an
    internal risk level (CRITICAL, HIGH, MEDIUM, LOW, INFO).
    
    Formula:
      Base Score (from Technical Severity):
        CRITICAL = 90.0, HIGH = 70.0, MEDIUM = 45.0, LOW = 20.0, INFO = 5.0
        
      Asset Criticality Multiplier:
        CRITICAL = 1.30, HIGH = 1.15, MEDIUM = 1.00, LOW = 0.85
        
      Asset Exposure Multiplier:
        INTERNET_FACING = 1.25, INTERNAL = 1.00, RESTRICTED = 0.80
        
      Exploitability Factor: default 1.0 (range 0.5 - 1.5)
      Confidence Factor: default 1.0 (range 0.8 - 1.2)
      
      Raw Score = Base Score * CriticalityMultiplier * ExposureMultiplier * ExploitabilityFactor * ConfidenceFactor
      Final Score = clamp(round(Raw Score, 1), 0.0, 100.0)
    """

    VERSION = "1.0.0"

    SEVERITY_BASE_SCORES: Dict[FindingSeverity, float] = {
        FindingSeverity.CRITICAL: 90.0,
        FindingSeverity.HIGH: 70.0,
        FindingSeverity.MEDIUM: 45.0,
        FindingSeverity.LOW: 20.0,
        FindingSeverity.INFO: 5.0,
    }

    CRITICALITY_MULTIPLIERS: Dict[BusinessCriticality, float] = {
        BusinessCriticality.CRITICAL: 1.30,
        BusinessCriticality.HIGH: 1.15,
        BusinessCriticality.MEDIUM: 1.00,
        BusinessCriticality.LOW: 0.85,
    }

    EXPOSURE_MULTIPLIERS: Dict[AssetExposure, float] = {
        AssetExposure.INTERNET_FACING: 1.25,
        AssetExposure.INTERNAL: 1.00,
        AssetExposure.RESTRICTED: 0.80,
    }

    @classmethod
    def calculate_risk(
        cls,
        severity: FindingSeverity,
        asset_criticality: BusinessCriticality,
        asset_exposure: AssetExposure,
        exploitability_factor: float = 1.0,
        confidence_factor: float = 1.0,
    ) -> Tuple[float, RiskLevel, str, Dict[str, Any]]:
        """
        Calculate deterministic risk score and return (score, risk_level, rationale, inputs_breakdown).
        """
        base = cls.SEVERITY_BASE_SCORES.get(severity, 45.0)
        crit_mult = cls.CRITICALITY_MULTIPLIERS.get(asset_criticality, 1.0)
        exp_mult = cls.EXPOSURE_MULTIPLIERS.get(asset_exposure, 1.0)
        
        # Bounded factors
        bounded_exploitability = max(0.5, min(1.5, exploitability_factor))
        bounded_confidence = max(0.8, min(1.2, confidence_factor))

        raw_score = base * crit_mult * exp_mult * bounded_exploitability * bounded_confidence
        final_score = round(max(0.0, min(100.0, raw_score)), 1)

        # Map to Risk Level
        if final_score >= 85.0:
            level = RiskLevel.CRITICAL
        elif final_score >= 65.0:
            level = RiskLevel.HIGH
        elif final_score >= 40.0:
            level = RiskLevel.MEDIUM
        elif final_score >= 15.0:
            level = RiskLevel.LOW
        else:
            level = RiskLevel.INFO

        rationale = (
            f"Risk score {final_score} ({level.value}) evaluated via SentinelAI Risk Engine v{cls.VERSION}. "
            f"Factors: Base Severity={severity.value} ({base}), "
            f"Asset Criticality={asset_criticality.value} (x{crit_mult}), "
            f"Asset Exposure={asset_exposure.value} (x{exp_mult}), "
            f"Exploitability Factor={bounded_exploitability}, "
            f"Confidence Factor={bounded_confidence}."
        )

        breakdown = {
            "engine_version": cls.VERSION,
            "base_score": base,
            "criticality_multiplier": crit_mult,
            "exposure_multiplier": exp_mult,
            "exploitability_factor": bounded_exploitability,
            "confidence_factor": bounded_confidence,
            "final_score": final_score,
            "risk_level": level.value
        }

        return final_score, level, rationale, breakdown
