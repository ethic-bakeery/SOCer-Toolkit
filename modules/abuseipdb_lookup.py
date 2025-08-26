"""
AbuseIPDB lookup module for the IOC enrichment tool
"""

from typing import Dict, Any
from .utils import make_api_request

class AbuseIPDBLookup:
    """Handles AbuseIPDB API lookups"""
    
    def __init__(self, config: Dict[str, Any]):
        self.api_key = config['api_keys'].get('abuseipdb')
        self.base_url = "https://api.abuseipdb.com/api/v2"
        self.headers = {
            "Key": self.api_key,
            "Accept": "application/json"
        }
    
    def lookup_ip(self, ip: str) -> Dict[str, Any]:
        """
        Lookup an IP address on AbuseIPDB
        
        Args:
            ip: The IP address to lookup
            
        Returns:
            Dictionary with AbuseIPDB results
        """
        if not self.api_key:
            return {"error": "AbuseIPDB API key not configured"}
        
        url = f"{self.base_url}/check"
        params = {
            "ipAddress": ip,
            "maxAgeInDays": 90,
            "verbose": True
        }
        
        response = make_api_request(url, self.headers, params)
        
        if not response:
            return {"error": "AbuseIPDB API request failed"}
        
        # Extract relevant data
        result = {}
        data = response.get('data', {})
        
        result['abuse_confidence_score'] = data.get('abuseConfidenceScore', 0)
        result['total_reports'] = data.get('totalReports', 0)
        result['country_code'] = data.get('countryCode', '')
        result['isp'] = data.get('isp', '')
        result['domain'] = data.get('domain', '')
        result['usage_type'] = data.get('usageType', '')
        
        return result