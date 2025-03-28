# src/response.py

def generate_response_recommendations(correlated_iocs, severity):
    """Generates response recommendations based on correlated IOCs and severity."""
    recommendations = []

    if not correlated_iocs:
        return recommendations

    if severity >= 7:
        recommendations.append("High Severity Threat Detected!")

    for ioc in correlated_iocs:
        if "http" in ioc:
            recommendations.append(f"Block URL: {ioc}")
        elif "." in ioc and ioc.replace(".", "").isdigit():
            recommendations.append(f"Block IP: {ioc}")
        else:
            recommendations.append(f"Investigate IOC: {ioc}")

    if severity >= 5:
        recommendations.append("Initiate Threat Hunting Protocol.")

    return recommendations

# Add more sophisticated recommendation logic as needed.
