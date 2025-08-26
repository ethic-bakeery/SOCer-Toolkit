"""
Utility functions for the IOC enrichment tool
"""

import logging
import yaml
import re
from typing import Dict, Any, Optional

def load_config(config_path: str = "config.yaml") -> Dict[str, Any]:
    """
    Load configuration from YAML file
    
    Args:
        config_path: Path to the config file
        
    Returns:
        Dictionary with configuration
    """
    try:
        with open(config_path, 'r') as file:
            return yaml.safe_load(file)
    except FileNotFoundError:
        logging.error(f"Config file {config_path} not found")
        raise
    except yaml.YAMLError as e:
        logging.error(f"Error parsing config file: {e}")
        raise

def setup_logging(verbose: bool = False) -> logging.Logger:
    """
    Setup logging configuration
    
    Args:
        verbose: Enable verbose logging
        
    Returns:
        Logger instance
    """
    level = logging.DEBUG if verbose else logging.INFO
    logging.basicConfig(
        level=level,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
    )
    return logging.getLogger(__name__)

def detect_ioc_type(ioc: str) -> Optional[str]:
    """
    Detect the type of IOC (IP, domain, hash)
    
    Args:
        ioc: The IOC string
        
    Returns:
        Type of IOC or None if unknown
    """
    # IP address patterns (IPv4 and IPv6)
    ipv4_pattern = r'^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$'
    ipv6_pattern = r'^(([0-9a-fA-F]{1,4}:){7,7}[0-9a-fA-F]{1,4}|([0-9a-fA-F]{1,4}:){1,7}:|([0-9a-fA-F]{1,4}:){1,6}:[0-9a-fA-F]{1,4}|([0-9a-fA-F]{1,4}:){1,5}(:[0-9a-fA-F]{1,4}){1,2}|([0-9a-fA-F]{1,4}:){1,4}(:[0-9a-fA-F]{1,4}){1,3}|([0-9a-fA-F]{1,4}:){1,3}(:[0-9a-fA-F]{1,4}){1,4}|([0-9a-fA-F]{1,4}:){1,2}(:[0-9a-fA-F]{1,4}){1,5}|[0-9a-fA-F]{1,4}:((:[0-9a-fA-F]{1,4}){1,6})|:((:[0-9a-fA-F]{1,4}){1,7}|:)|fe80:(:[0-9a-fA-F]{0,4}){0,4}%[0-9a-zA-Z]{1,}|::(ffff(:0{1,4}){0,1}:){0,1}((25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])\.){3,3}(25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])|([0-9a-fA-F]{1,4}:){1,4}:((25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])\.){3,3}(25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9]))$'
    
    # Hash patterns
    md5_pattern = r'^[a-fA-F0-9]{32}$'
    sha1_pattern = r'^[a-fA-F0-9]{40}$'
    sha256_pattern = r'^[a-fA-F0-9]{64}$'
    
    # Domain pattern (simplified)
    domain_pattern = r'^([a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$'
    
    if re.match(ipv4_pattern, ioc) or re.match(ipv6_pattern, ioc):
        return "ip"
    elif re.match(md5_pattern, ioc):
        return "md5"
    elif re.match(sha1_pattern, ioc):
        return "sha1"
    elif re.match(sha256_pattern, ioc):
        return "sha256"
    elif re.match(domain_pattern, ioc):
        return "domain"
    
    return None

def make_api_request(url: str, headers: Dict[str, str], params: Dict[str, Any] = None, 
                    timeout: int = 30) -> Dict[str, Any]:
    """
    Make an API request with error handling
    
    Args:
        url: API endpoint URL
        headers: Request headers
        params: Query parameters
        timeout: Request timeout
        
    Returns:
        API response as dictionary
    """
    import requests
    
    try:
        response = requests.get(url, headers=headers, params=params, timeout=timeout)
        response.raise_for_status()
        return response.json()
    except requests.exceptions.RequestException as e:
        logging.error(f"API request failed: {e}")
        return {}