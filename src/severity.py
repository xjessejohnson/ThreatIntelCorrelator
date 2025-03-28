# src/severity.py

def calculate_severity(scan_results):
    """Calculates severity score based on scan results and detection ratios."""
    severity = 0
    if not scan_results:
        return severity

    total_engines = len(scan_results)
    malicious_detections = 0

    for engine, result in scan_results.items():
        if result and "category" in result and result["category"] == "malicious":
            malicious_detections += 1

    if total_engines > 0:
        detection_ratio = malicious_detections / total_engines
        severity = int(detection_ratio * 10)  # Scale severity to 0-10

    return severity

# Add more sophisticated severity calculation logic as needed.
