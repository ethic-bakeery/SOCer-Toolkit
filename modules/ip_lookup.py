"""
IP lookup module for the IOC enrichment tool
"""

from typing import Dict, Any
from .virustotal_lookup import VirusTotalLookup
from .abuseipdb_lookup import AbuseIPDBLookup
from .greynoise_lookup import GreyNoiseLookup
from .shodan_lookup import ShodanLookup
from .iplocation_lookup import IPLocationLookup

class IPLookup:
    """Handles IP address enrichment from multiple sources"""
    
    def __init__(self, config: Dict[str, Any]):
        self.config = config
        self.vt_lookup = VirusTotalLookup(config)
        self.abuseipdb_lookup = AbuseIPDBLookup(config)
        self.greynoise_lookup = GreyNoiseLookup(config)
        self.shodan_lookup = ShodanLookup(config)
        self.iplocation_lookup = IPLocationLookup(config)
    
    def enrich(self, ip: str) -> Dict[str, Any]:
        """
        Enrich an IP address with data from various sources
        
        Args:
            ip: The IP address to enrich
            
        Returns:
            Dictionary with enrichment results from all sources
        """
        results = {}
        
        # VirusTotal
        vt_result = self.vt_lookup.lookup_ip(ip)
        if vt_result:
            results["VirusTotal"] = vt_result
        
        # AbuseIPDB
        abuseipdb_result = self.abuseipdb_lookup.lookup_ip(ip)
        if abuseipdb_result:
            results["AbuseIPDB"] = abuseipdb_result
        
        # GreyNoise
        greynoise_result = self.greynoise_lookup.lookup_ip(ip)
        if greynoise_result:
            results["GreyNoise"] = greynoise_result
        
        # Shodan
        shodan_result = self.shodan_lookup.lookup_ip(ip)
        if shodan_result:
            results["Shodan"] = shodan_result
        
        # IP Location
        iplocation_result = self.iplocation_lookup.lookup_ip(ip)
        if iplocation_result:
            results["IPLocation"] = iplocation_result
        
        return results