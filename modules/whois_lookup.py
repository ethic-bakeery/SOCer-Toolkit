"""
WHOIS lookup module for the IOC enrichment tool
"""

import whois
from typing import Dict, Any

class WhoisLookup:
    """Handles WHOIS lookups for domains"""
    
    def __init__(self, config: Dict[str, Any]):
        pass  # No API key needed for WHOIS
    
    def lookup_domain(self, domain: str) -> Dict[str, Any]:
        """
        Lookup a domain using WHOIS
        
        Args:
            domain: The domain to lookup
            
        Returns:
            Dictionary with WHOIS results
        """
        try:
            w = whois.whois(domain)
            
            # Extract relevant data
            result = {}
            
            result['registrar'] = w.registrar
            result['creation_date'] = str(w.creation_date) if w.creation_date else ''
            result['expiration_date'] = str(w.expiration_date) if w.expiration_date else ''
            result['last_updated'] = str(w.updated_date) if w.updated_date else ''
            result['name_servers'] = list(w.name_servers) if w.name_servers else []
            result['status'] = list(w.status) if w.status else []
            result['emails'] = list(w.emails) if w.emails else []
            
            return result
        except Exception as e:
            return {"error": f"WHOIS lookup failed: {str(e)}"}