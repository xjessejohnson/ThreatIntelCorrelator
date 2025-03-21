import requests
import json

def get_virus_total_data(file_hash):
    """
    Retrieves analysis data from VirusTotal for a given file hash.
    """
    api_key = "2984b7ea69fef8b5c9770309dea86f804c66d2799d809d84e2ac3dad371e61a4" #replace with your api key.
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
    file_hash = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"  # example hash
    virus_total_data = get_virus_total_data(file_hash)

    if virus_total_data:
        print(json.dumps(virus_total_data, indent=4))
        file_name = "example.exe"
        file_size = 1024
        database.store_file_data(file_hash, file_name, file_size)
        database.store_virus_total_results(file_hash, virus_total_data)
        file_metadata = data_processing.extract_file_metadata(virus_total_data)
        scan_results = data_processing.extract_scan_results(virus_total_data)
        iocs = data_processing.extract_iocs(virus_total_data)

        database.store_file_data(file_hash, file_metadata.get('file_name', "unknown"), file_metadata.get('file_size', 0))
        database.store_virus_total_results(file_hash, scan_results)
    else:
        print("Failed to retrieve VirusTotal data.")
