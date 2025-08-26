"""
VirusTotal lookup module for the IOC enrichment tool
"""

from typing import Dict, Any
from .utils import make_api_request

class VirusTotalLookup:
    """Handles VirusTotal API lookups"""
    
    def __init__(self, config: Dict[str, Any]):
        self.api_key = config['api_keys'].get('virustotal')
        self.base_url = "https://www.virustotal.com/api/v3"
        self.headers = {
            "x-apikey": self.api_key
        }
    
    def lookup_ip(self, ip: str) -> Dict[str, Any]:
        """
        Lookup an IP address on VirusTotal
        
        Args:
            ip: The IP address to lookup
            
        Returns:
            Dictionary with VirusTotal results
        """
        if not self.api_key:
            return {"error": "VirusTotal API key not configured"}
        
        url = f"{self.base_url}/ip_addresses/{ip}"
        response = make_api_request(url, self.headers)
        
        if not response:
            return {"error": "VirusTotal API request failed"}
        
        # Extract relevant data
        result = {}
        data = response.get('data', {})
        attributes = data.get('attributes', {})
        
        # Last analysis stats
        last_analysis_stats = attributes.get('last_analysis_stats', {})
        result['malicious'] = last_analysis_stats.get('malicious', 0)
        result['suspicious'] = last_analysis_stats.get('suspicious', 0)
        result['undetected'] = last_analysis_stats.get('undetected', 0)
        result['harmless'] = last_analysis_stats.get('harmless', 0)
        
        # Other relevant info
        result['reputation'] = attributes.get('reputation', 0)
        result['last_analysis_date'] = attributes.get('last_analysis_date', '')
        
        return result
    
    def lookup_domain(self, domain: str) -> Dict[str, Any]:
        """
        Lookup a domain on VirusTotal
        
        Args:
            domain: The domain to lookup
            
        Returns:
            Dictionary with VirusTotal results
        """
        if not self.api_key:
            return {"error": "VirusTotal API key not configured"}
        
        url = f"{self.base_url}/domains/{domain}"
        response = make_api_request(url, self.headers)
        
        if not response:
            return {"error": "VirusTotal API request failed"}
        
        # Extract relevant data
        result = {}
        data = response.get('data', {})
        attributes = data.get('attributes', {})
        
        # Last analysis stats
        last_analysis_stats = attributes.get('last_analysis_stats', {})
        result['malicious'] = last_analysis_stats.get('malicious', 0)
        result['suspicious'] = last_analysis_stats.get('suspicious', 0)
        result['undetected'] = last_analysis_stats.get('undetected', 0)
        result['harmless'] = last_analysis_stats.get('harmless', 0)
        
        # Other relevant info
        result['reputation'] = attributes.get('reputation', 0)
        result['last_analysis_date'] = attributes.get('last_analysis_date', '')
        
        return result
    
    def lookup_hash(self, file_hash: str) -> Dict[str, Any]:
        """
        Lookup a file hash on VirusTotal
        
        Args:
            file_hash: The hash to lookup
            
        Returns:
            Dictionary with VirusTotal results
        """
        if not self.api_key:
            return {"error": "VirusTotal API key not configured"}
        
        url = f"{self.base_url}/files/{file_hash}"
        response = make_api_request(url, self.headers)
        
        if not response:
            return {"error": "VirusTotal API request failed"}
        
        # Extract relevant data
        result = {}
        data = response.get('data', {})
        attributes = data.get('attributes', {})
        
        # Last analysis stats
        last_analysis_stats = attributes.get('last_analysis_stats', {})
        result['malicious'] = last_analysis_stats.get('malicious', 0)
        result['suspicious'] = last_analysis_stats.get('suspicious', 0)
        result['undetected'] = last_analysis_stats.get('undetected', 0)
        result['harmless'] = last_analysis_stats.get('harmless', 0)
        
        # Other relevant info
        result['type_description'] = attributes.get('type_description', '')
        result['size'] = attributes.get('size', 0)
        result['last_analysis_date'] = attributes.get('last_analysis_date', '')
        
        return result