# src/correlation.py

def correlate_iocs(ioc_lists):
    """Correlates IOCs from multiple lists."""
    if not ioc_lists:
        return []

    common_iocs = set(ioc_lists[0])
    for ioc_list in ioc_lists[1:]:
        common_iocs.intersection_update(ioc_list)

    return list(common_iocs)

# Add more correlation functions as needed.
