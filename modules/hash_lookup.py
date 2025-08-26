"""
Hash lookup module for the IOC enrichment tool
"""

from typing import Dict, Any
from .virustotal_lookup import VirusTotalLookup

class HashLookup:
    """Handles file hash enrichment from multiple sources"""
    
    def __init__(self, config: Dict[str, Any]):
        self.config = config
        self.vt_lookup = VirusTotalLookup(config)
    
    def enrich(self, file_hash: str, hash_type: str) -> Dict[str, Any]:
        """
        Enrich a file hash with data from various sources
        
        Args:
            file_hash: The hash to enrich
            hash_type: Type of hash (md5, sha1, sha256)
            
        Returns:
            Dictionary with enrichment results from all sources
        """
        results = {}
        
        # VirusTotal
        vt_result = self.vt_lookup.lookup_hash(file_hash)
        if vt_result:
            results["VirusTotal"] = vt_result
        
        return results