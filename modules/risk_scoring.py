"""
Risk scoring engine for the IOC enrichment tool
"""

from typing import Dict, Any

class RiskScoringEngine:
    """Calculates risk scores based on enrichment data"""
    
    def __init__(self):
        self.weights = {
            'virustotal_detections': 0.3,
            'abuseipdb_score': 0.25,
            'greynoise_classification': 0.2,
            'shodan_vulnerabilities': 0.15,
            'suspicious_location': 0.1
        }
    
    def calculate_score(self, normalized_data: Dict[str, Any]) -> float:
        """
        Calculate a risk score based on normalized data
        
        Args:
            normalized_data: Normalized enrichment data
            
        Returns:
            Risk score between 0 and 100
        """
        score = 0
        
        # VirusTotal component
        vt_data = normalized_data.get('VirusTotal', {})
        vt_detections = vt_data.get('detections', 0)
        score += min(vt_detections * 10, 30) * self.weights['virustotal_detections']
        
        # AbuseIPDB component
        abuse_data = normalized_data.get('AbuseIPDB', {})
        abuse_score = abuse_data.get('abuse_score', 0)
        score += abuse_score * self.weights['abuseipdb_score']
        
        # GreyNoise component
        gn_data = normalized_data.get('GreyNoise', {})
        gn_classification = gn_data.get('classification', 'unknown')
        if gn_classification == 'malicious':
            score += 100 * self.weights['greynoise_classification']
        elif gn_classification == 'suspicious':
            score += 50 * self.weights['greynoise_classification']
        
        # Shodan component
        shodan_data = normalized_data.get('Shodan', {})
        shodan_vulns = len(shodan_data.get('vulnerabilities', []))
        score += min(shodan_vulns * 15, 100) * self.weights['shodan_vulnerabilities']
        
        # Location component (simplified)
        location_data = normalized_data.get('IPLocation', {})
        country = location_data.get('country', '').lower()
        suspicious_countries = ['ru', 'cn', 'kp', 'ir', 'sy']  # Simplified list
        if country in suspicious_countries:
            score += 100 * self.weights['suspicious_location']
        
        return min(score, 100)
    
    def get_risk_level(self, score: float) -> str:
        """
        Convert score to risk level
        
        Args:
            score: Risk score between 0 and 100
            
        Returns:
            Risk level (Low, Medium, High)
        """
        if score < 30:
            return "Low"
        elif score < 70:
            return "Medium"
        else:
            return "High"
    
    def assess_risk(self, normalized_data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Assess risk based on normalized data
        
        Args:
            normalized_data: Normalized enrichment data
            
        Returns:
            Dictionary with score and risk level
        """
        score = self.calculate_score(normalized_data)
        risk_level = self.get_risk_level(score)
        
        return {
            "score": round(score, 2),
            "level": risk_level
        }