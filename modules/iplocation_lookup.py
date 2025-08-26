"""
IP location lookup module for the IOC enrichment tool
"""

from typing import Dict, Any
from .utils import make_api_request

class IPLocationLookup:
    """Handles IP location lookups using free API"""
    
    def __init__(self, config: Dict[str, Any]):
        self.base_url = "http://ip-api.com/json"
        self.headers = {
            "Accept": "application/json"
        }
    
    def lookup_ip(self, ip: str) -> Dict[str, Any]:
        """
        Lookup an IP address location
        
        Args:
            ip: The IP address to lookup
            
        Returns:
            Dictionary with IP location results
        """
        url = f"{self.base_url}/{ip}"
        params = {
            "fields": "status,message,continent,continentCode,country,countryCode,region,regionName,city,district,zip,lat,lon,timezone,offset,currency,isp,org,as,asname,reverse,mobile,proxy,hosting,query"
        }
        
        response = make_api_request(url, self.headers, params)
        
        if not response or response.get('status') != 'success':
            return {"error": "IP location API request failed"}
        
        # Extract relevant data
        result = {}
        
        result['continent'] = response.get('continent', '')
        result['country'] = response.get('country', '')
        result['region'] = response.get('regionName', '')
        result['city'] = response.get('city', '')
        result['zip'] = response.get('zip', '')
        result['lat'] = response.get('lat', '')
        result['lon'] = response.get('lon', '')
        result['timezone'] = response.get('timezone', '')
        result['isp'] = response.get('isp', '')
        result['org'] = response.get('org', '')
        result['as'] = response.get('as', '')
        result['proxy'] = response.get('proxy', False)
        result['hosting'] = response.get('hosting', False)
        
        return result