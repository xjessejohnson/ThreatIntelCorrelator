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
    file_hash = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855" #example hash
    virus_total_data = get_virus_total_data(file_hash)

    if virus_total_data:
        print(json.dumps(virus_total_data, indent=4)) #prints the json in an easy to read format.
    else:
        print("Failed to retrieve VirusTotal data.")
