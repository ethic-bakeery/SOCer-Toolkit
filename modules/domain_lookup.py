"""
Domain lookup module for the IOC enrichment tool
"""

from typing import Dict, Any
from .virustotal_lookup import VirusTotalLookup
from .whois_lookup import WhoisLookup

class DomainLookup:
    """Handles domain enrichment from multiple sources"""
    
    def __init__(self, config: Dict[str, Any]):
        self.config = config
        self.vt_lookup = VirusTotalLookup(config)
        self.whois_lookup = WhoisLookup(config)
    
    def enrich(self, domain: str) -> Dict[str, Any]:
        """
        Enrich a domain with data from various sources
        
        Args:
            domain: The domain to enrich
            
        Returns:
            Dictionary with enrichment results from all sources
        """
        results = {}
        
        # VirusTotal
        vt_result = self.vt_lookup.lookup_domain(domain)
        if vt_result:
            results["VirusTotal"] = vt_result
        
        # WHOIS
        whois_result = self.whois_lookup.lookup_domain(domain)
        if whois_result:
            results["Whois"] = whois_result
        
        return results