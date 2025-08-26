"""
Data normalizer for the IOC enrichment tool
"""

from typing import Dict, Any

class DataNormalizer:
    """Normalizes data from various sources into a standard format"""
    
    @staticmethod
    def normalize_virustotal_data(data: Dict[str, Any]) -> Dict[str, Any]:
        """Normalize VirusTotal data"""
        normalized = {}
        
        if 'malicious' in data:
            normalized['detections'] = data['malicious']
            normalized['scan_date'] = data.get('last_analysis_date', '')
        
        return normalized
    
    @staticmethod
    def normalize_abuseipdb_data(data: Dict[str, Any]) -> Dict[str, Any]:
        """Normalize AbuseIPDB data"""
        normalized = {}
        
        if 'abuse_confidence_score' in data:
            normalized['abuse_score'] = data['abuse_confidence_score']
            normalized['reports'] = data.get('total_reports', 0)
        
        return normalized
    
    @staticmethod
    def normalize_greynoise_data(data: Dict[str, Any]) -> Dict[str, Any]:
        """Normalize GreyNoise data"""
        normalized = {}
        
        if 'classification' in data:
            normalized['classification'] = data['classification']
            normalized['last_seen'] = data.get('last_seen', '')
        
        return normalized
    
    @staticmethod
    def normalize_shodan_data(data: Dict[str, Any]) -> Dict[str, Any]:
        """Normalize Shodan data"""
        normalized = {}
        
        if 'org' in data:
            normalized['org'] = data['org']
            normalized['ports'] = data.get('open_ports', [])
            normalized['vulnerabilities'] = data.get('vulnerabilities', [])
        
        return normalized
    
    @staticmethod
    def normalize_iplocation_data(data: Dict[str, Any]) -> Dict[str, Any]:
        """Normalize IP location data"""
        normalized = {}
        
        if 'country' in data:
            normalized['country'] = data['country']
            normalized['asn'] = data.get('as', '')
            normalized['isp'] = data.get('isp', '')
        
        return normalized
    
    @staticmethod
    def normalize_whois_data(data: Dict[str, Any]) -> Dict[str, Any]:
        """Normalize WHOIS data"""
        normalized = {}
        
        if 'registrar' in data:
            normalized['registrar'] = data['registrar']
            normalized['creation_date'] = data.get('creation_date', '')
            normalized['name_servers'] = data.get('name_servers', [])
        
        return normalized
    
    def normalize_all(self, enrichment_data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Normalize all enrichment data
        
        Args:
            enrichment_data: Raw enrichment data from various sources
            
        Returns:
            Normalized data in standard format
        """
        normalized = {}
        
        for source, data in enrichment_data.items():
            if source == "VirusTotal":
                normalized[source] = self.normalize_virustotal_data(data)
            elif source == "AbuseIPDB":
                normalized[source] = self.normalize_abuseipdb_data(data)
            elif source == "GreyNoise":
                normalized[source] = self.normalize_greynoise_data(data)
            elif source == "Shodan":
                normalized[source] = self.normalize_shodan_data(data)
            elif source == "IPLocation":
                normalized[source] = self.normalize_iplocation_data(data)
            elif source == "Whois":
                normalized[source] = self.normalize_whois_data(data)
            else:
                normalized[source] = data  # Keep as-is if no normalizer
        
        return normalized