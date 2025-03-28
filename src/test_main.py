# tests/test_main.py
import unittest
from src import correlation, severity, response

class TestFunctions(unittest.TestCase):

    def test_correlate_iocs(self):
        ioc_lists = [["ip1", "url1"], ["ip1", "hash1"]]
        self.assertEqual(correlation.correlate_iocs(ioc_lists), ["ip1"])

    def test_calculate_severity(self):
        scan_results = {"engine1": {"category": "malicious"}, "engine2": {"category": "harmless"}}
        self.assertEqual(severity.calculate_severity(scan_results), 5)

    def test_generate_response(self):
        iocs = ["1.1.1.1"]
        self.assertEqual(response.generate_response_recommendations(iocs, 7), ["High Severity Threat Detected!", "Block IP: 1.1.1.1", "Initiate Threat Hunting Protocol."])

if __name__ == '__main__':
    unittest.main()
