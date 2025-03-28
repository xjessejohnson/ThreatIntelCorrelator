# src/cli.py
import argparse
from . import data_acquisition
from . import database
import json

def main():
    parser = argparse.ArgumentParser(description="Threat Intelligence Correlator CLI")
    parser.add_argument("file_hashes", nargs="+", help="File hashes to analyze")
    args = parser.parse_args()

    all_iocs = []
    for file_hash in args.file_hashes:
        virus_total_data = data_acquisition.get_virus_total_data(file_hash)
        if virus_total_data:
            print(json.dumps(virus_total_data, indent=4))
            file_metadata = data_acquisition.data_processing.extract_file_metadata(virus_total_data)
            scan_results = data_acquisition.data_processing.extract_scan_results(virus_total_data)
            iocs = data_acquisition.data_processing.extract_iocs(virus_total_data)
            severity = data_acquisition.data_processing.extract_severity(virus_total_data)
            database.store_file_data(file_hash, file_metadata.get('file_name', "unknown"), file_metadata.get('file_size', 0))
            database.store_virus_total_results(file_hash, scan_results)
            database.store_iocs(file_hash, iocs)
            database.store_severity(file_hash, severity)
            all_iocs.append(iocs)
            print(f"Severity Score: {severity}")
        else:
            print(f"Failed to retrieve VirusTotal data for {file_hash}.")
    correlated_iocs = data_acquisition.correlation.correlate_iocs(all_iocs)
    print("Correlated IOCs:", correlated_iocs)
    recommendations = data_acquisition.response.generate_response_recommendations(correlated_iocs, severity)
    print("Response Recommendations:", recommendations)

if __name__ == "__main__":
    main()
