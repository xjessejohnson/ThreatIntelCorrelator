# src/data_processing.py
import re

def extract_file_metadata(vt_data):
    """Extracts file metadata from VirusTotal data."""
    metadata = {}
    if vt_data and "data" in vt_data and "attributes" in vt_data["data"]:
        attributes = vt_data["data"]["attributes"]
        metadata["file_name"] = attributes.get("names", ["unknown"])[0]
        metadata["file_size"] = attributes.get("size", 0)
        # Add other metadata fields as needed
    return metadata

def extract_scan_results(vt_data):
    """Extracts scan results from VirusTotal data."""
    scan_results = {}
    if vt_data and "data" in vt_data and "attributes" in vt_data["data"] and "last_analysis_results" in vt_data["data"]["attributes"]:
        scan_results = vt_data["data"]["attributes"]["last_analysis_results"]
    return scan_results

def extract_iocs(vt_data):
    """Extracts IOCs from VirusTotal data."""
    iocs = []
    if vt_data and "data" in vt_data and "attributes" in vt_data["data"] and "last_analysis_results" in vt_data["data"]["attributes"]:
        results = vt_data["data"]["attributes"]["last_analysis_results"]
        for engine, result in results.items():
            if result and "category" in result and result["category"] == "malicious" and "result" in result:
                # Basic IOC extraction (URLs and IP addresses)
                urls = re.findall(r'http[s]?://(?:[a-zA-Z]|[0-9]|[$-_@.&+]|[!*\(\),]|(?:%[0-9a-fA-F][0-9a-fA-F]))+', str(result["result"]))
                ips = re.findall(r'\b(?:\d{1,3}\.){3}\d{1,3}\b', str(result["result"]))
                iocs.extend(urls)
                iocs.extend(ips)

    return iocs

# Add more data processing functions as needed.
