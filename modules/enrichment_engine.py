"""
Enrichment engine for the IOC enrichment tool
"""

from typing import Dict, Any
from .ip_lookup import IPLookup
from .domain_lookup import DomainLookup
from .hash_lookup import HashLookup
from .utils import detect_ioc_type

class EnrichmentEngine:
    """Orchestrates the enrichment process for IOCs"""
    
    def __init__(self, config: Dict[str, Any]):
        self.config = config
        self.ip_lookup = IPLookup(config)
        self.domain_lookup = DomainLookup(config)
        self.hash_lookup = HashLookup(config)
    
    def enrich(self, ioc: str) -> Dict[str, Any]:
        """
        Enrich an IOC with data from various sources
        
        Args:
            ioc: The IOC to enrich
            
        Returns:
            Dictionary with enrichment results
        """
        ioc_type = detect_ioc_type(ioc)
        
        if not ioc_type:
            return {"ioc": ioc, "error": "Unknown IOC type"}
        
        result = {
            "ioc": ioc,
            "type": ioc_type,
            "sources": {}
        }
        
        try:
            if ioc_type == "ip":
                result["sources"] = self.ip_lookup.enrich(ioc)
            elif ioc_type in ["domain"]:
                result["sources"] = self.domain_lookup.enrich(ioc)
            elif ioc_type in ["md5", "sha1", "sha256"]:
                result["sources"] = self.hash_lookup.enrich(ioc, ioc_type)
            else:
                result["error"] = f"Unsupported IOC type: {ioc_type}"
        except Exception as e:
            result["error"] = f"Enrichment failed: {str(e)}"
        
        return result