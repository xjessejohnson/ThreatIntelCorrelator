# src/data_acquisition.py
import requests
import json
import logging
from . import database
from . import data_processing
from . import correlation
from . import response

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

def get_virus_total_data(file_hash):
    """Retrieves analysis data from VirusTotal for a given file hash with error handling."""
    api_key = "2984b7ea69fef8b5c9770309dea86f804c66d2799d809d84e2ac3dad371e61a4"  # Replace with your API key.
    url = f"https://www.virustotal.com/api/v3/files/{file_hash}"
    headers = {"x-apikey": api_key}

    try:
        response = requests.get(url, headers=headers)
        response.raise_for_status()
        data = response.json()
        return data
    except requests.exceptions.RequestException as e:
        logging.error(f"Error fetching VirusTotal data for {file_hash}: {e}")
        return None
    except json.JSONDecodeError as e:
        logging.error(f"Error decoding JSON response for {file_hash}: {e}")
        return None

if __name__ == "__main__":
    file_hashes = [
        "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",  # example hash 1
        "9078623824b155840552718e2f6f2e46048997a5142a5481d6b059814234495c",  # example hash 2
    ]

    all_iocs = []
    for file_hash in file_hashes:
        virus_total_data = get_virus_total_data(file_hash)

        if virus_total_data:
            logging.info(f"Successfully retrieved VirusTotal data for {file_hash}")
            file_metadata = data_processing.extract_file_metadata(virus_total_data)
            scan_results = data_processing.extract_scan_results(virus_total_data)
            iocs = data_processing.extract_iocs(virus_total_data)
            severity = data_processing.extract_severity(virus_total_data)

            database.store_file_data(file_hash, file_metadata.get('file_name', "unknown"), file_metadata.get('file_size', 0))
            database.store_virus_total_results(file_hash, scan_results)
            database.store_iocs(file_hash, iocs)
            database.store_severity(file_hash, severity)

            all_iocs.append(iocs)

            logging.info(f"Severity Score for {file_hash}: {severity}")
        else:
            logging.warning(f"Failed to retrieve VirusTotal data for {file_hash}.")

    correlated_iocs = correlation.correlate_iocs(all_iocs)
    logging.info(f"Correlated IOCs: {correlated_iocs}")

    recommendations = response.generate_response_recommendations(correlated_iocs, severity)
    logging.info(f"Response Recommendations: {recommendations}")
