# src/response_recommendation.py

def generate_response_recommendations(correlated_iocs):
    """Generates response recommendations based on correlated IOCs."""
    recommendations = []

    if not correlated_iocs:
        return recommendations

    for ioc in correlated_iocs:
        if "http" in ioc:
            recommendations.append(f"Block URL: {ioc}")
        elif "." in ioc and ioc.replace(".","").isdigit():
            recommendations.append(f"Block IP: {ioc}")
        else:
            recommendations.append(f"Investigate IOC: {ioc}")

    return recommendations

# Add more sophisticated recommendation logic as needed.
