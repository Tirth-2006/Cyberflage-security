from cyberflage.detector import ThreatDetector


def test_detector_levels() -> None:
    detector = ThreatDetector({"MEDIUM": 30, "HIGH": 60, "CRITICAL": 85})

    low = detector.evaluate([{"type": "normal", "weight": 5}])
    assert low.level == "LOW"

    medium = detector.evaluate([{"type": "burst", "weight": 35}])
    assert medium.level == "MEDIUM"

    critical = detector.evaluate([{"type": "mass_encrypt", "weight": 90}])
    assert critical.level == "CRITICAL"
    assert critical.action == "activate_decoy"
