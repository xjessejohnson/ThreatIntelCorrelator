# src/correlation.py

def correlate_iocs(ioc_lists):
    """Correlates IOCs from multiple lists with improved logic."""
    if not ioc_lists:
        return []

    all_iocs = []
    for ioc_list in ioc_lists:
        all_iocs.extend(ioc_list)

    ioc_counts = {}
    for ioc in all_iocs:
        ioc_counts[ioc] = ioc_counts.get(ioc, 0) + 1

    correlated_iocs = [ioc for ioc, count in ioc_counts.items() if count > 1] #Iocs that appear more than once.

    return correlated_iocs
