# src/severity.py

def calculate_severity(scan_results):
    """Calculates severity score based on scan results."""
    severity = 0
    if not scan_results:
        return severity

    for engine, result in scan_results.items():
        if result and "category" in result and result["category"] == "malicious":
            severity += 1  # Increment severity for each malicious detection

    return severity

# Add more sophisticated severity calculation logic as needed.
