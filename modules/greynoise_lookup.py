"""
GreyNoise lookup module for the IOC enrichment tool
"""

from typing import Dict, Any
from .utils import make_api_request

class GreyNoiseLookup:
    """Handles GreyNoise API lookups"""
    
    def __init__(self, config: Dict[str, Any]):
        self.api_key = config['api_keys'].get('greynoise')
        self.base_url = "https://api.greynoise.io/v3/community"
        self.headers = {
            "key": self.api_key,
            "Accept": "application/json"
        }
    
    def lookup_ip(self, ip: str) -> Dict[str, Any]:
        """
        Lookup an IP address on GreyNoise
        
        Args:
            ip: The IP address to lookup
            
        Returns:
            Dictionary with GreyNoise results
        """
        if not self.api_key:
            return {"error": "GreyNoise API key not configured"}
        
        url = f"{self.base_url}/{ip}"
        response = make_api_request(url, self.headers)
        
        if not response:
            return {"error": "GreyNoise API request failed"}
        
        # Extract relevant data
        result = {}
        
        result['noise'] = response.get('noise', False)
        result['riot'] = response.get('riot', False)
        result['classification'] = response.get('classification', 'unknown')
        result['name'] = response.get('name', '')
        result['link'] = response.get('link', '')
        result['last_seen'] = response.get('last_seen', '')
        
        return result