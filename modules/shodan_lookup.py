"""
Shodan lookup module for the IOC enrichment tool
"""

from typing import Dict, Any
import requests


class ShodanLookup:
    """Handles Shodan API lookups"""

    def __init__(self, config: Dict[str, Any]):
        self.api_key = config['api_keys'].get('shodan')
        self.base_url = "https://api.shodan.io"
        self.headers = {
            "Accept": "application/json"
        }

    def lookup_ip(self, ip: str) -> Dict[str, Any]:
        """
        Lookup an IP address on Shodan

        Args:
            ip: The IP address to lookup

        Returns:
            Dictionary with Shodan results
        """
        if not self.api_key:
            return {"error": "Shodan API key not configured"}

        url = f"{self.base_url}/shodan/host/{ip}"
        params = {"key": self.api_key}

        try:
            response = requests.get(url, headers=self.headers, params=params, timeout=10)
            if response.status_code != 200:
                return {"error": f"Shodan API request failed: {response.status_code} {response.text}"}

            data = response.json()

            # Extract relevant data
            result = {
                "org": data.get("org", ""),
                "isp": data.get("isp", ""),
                "country_code": data.get("country_code", ""),
                "last_update": data.get("last_update", ""),
                "open_ports": data.get("ports", []),
                "vulnerabilities": list(data.get("vulns", {}).keys()) if data.get("vulns") else []
            }

            return result

        except requests.RequestException as e:
            return {"error": f"Request failed: {str(e)}"}
