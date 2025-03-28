# src/database.py

data_store = {}  # Simulate database with a dictionary

def store_file_data(file_hash, file_name, file_size):
    """Simulates storing file metadata in the database."""
    if file_hash not in data_store:
        data_store[file_hash] = {}
    data_store[file_hash]["file_metadata"] = {"name": file_name, "size": file_size}
    print(f"Simulated storage: file data for {file_hash}")

def store_virus_total_results(file_hash, vt_data):
    """Simulates storing VirusTotal results."""
    if file_hash not in data_store:
        data_store[file_hash] = {}
    data_store[file_hash]["vt_results"] = vt_data
    print(f"Simulated storage: VirusTotal results for {file_hash}")

def store_iocs(file_hash, iocs):
    """Simulates storing IOCs."""
    if file_hash not in data_store:
        data_store[file_hash] = {}
    data_store[file_hash]["iocs"] = iocs
    print(f"Simulated storage: IOCs for {file_hash}")

def store_severity(file_hash, severity):
    """Simulates storing severity."""
    if file_hash not in data_store:
        data_store[file_hash] = {}
    data_store[file_hash]["severity"] = severity
    print(f"Simulated storage: Severity for {file_hash}, Severity: {severity}")

def get_data(file_hash):
    """Simulates retrieving all data for a file hash."""
    return data_store.get(file_hash, {})
