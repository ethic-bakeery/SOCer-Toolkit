# tests/test_ip_lookup.py
import unittest
from modules.ip_lookup import IPLookup
from modules.utils import load_config

class TestIPLookup(unittest.TestCase):
    def setUp(self):
        self.config = load_config()
        self.ip_lookup = IPLookup(self.config)
    
    def test_enrich_ip(self):
        result = self.ip_lookup.enrich("8.8.8.8")
        self.assertIn("IPLocation", result)

if __name__ == "__main__":
    unittest.main()