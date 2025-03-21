# src/data_acquisition.py
import requests
import json
from . import database
from . import data_processing
from . import correlation
from . import response_recommendation

def get_virus_total_data(file_hash):
    """
    Retrieves analysis data from VirusTotal for a given file hash.
    """
    api_key = "2984b7ea69fef8b5c9770309dea86f804c66d2799d809d84e2ac3dad371e61a4"  # Replace with your API key.
    url = f"https://www.virustotal.com/api/v3/files/{file_hash}"
    headers = {"x-apikey": api_key}

    try:
        response = requests.get(url, headers=headers)
        response.raise_for_status()  # Raise HTTPError for bad responses (4xx or 5xx)
        data = response.json()
        return data
    except requests.exceptions.RequestException as e:
        print(f"Error fetching VirusTotal data: {e}")
        return None
    except json.JSONDecodeError as e:
        print(f"Error decoding JSON response: {e}")
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
            print(json.dumps(virus_total_data, indent=4))
            file_metadata = data_processing.extract_file_metadata(virus_total_data)
            scan_results = data_processing.extract_scan_results(virus_total_data)
            iocs = data_processing.extract_iocs(virus_total_data)

            database.store_file_data(file_hash, file_metadata.get('file_name', "unknown"), file_metadata.get('file_size', 0))
            database.store_virus_total_results(file_hash, scan_results)
            all_iocs.append(iocs)
        else:
            print(f"Failed to retrieve VirusTotal data for {file_hash}.")

    correlated_iocs = correlation.correlate_iocs(all_iocs)
    print("Correlated IOCs:", correlated_iocs)

    recommendations = response_recommendation.generate_response_recommendations(correlated_iocs)
    print("Response Recommendations:", recommendations)
