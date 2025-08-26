# SOCer Documentation

## **Table of Contents**
- [Overview](#overview)
- [Architecture](#architecture)
- [Installation & Setup](#installation--setup)
- [Configuration](#configuration)
- [Usage](#usage)
- [API Integration](#api-integration)
- [Extending the Tool](#extending-the-tool)
- [Development Guidelines](#development-guidelines)
- [Troubleshooting](#troubleshooting)
- [Contributing](#contributing)
- [Support](#support)
- [License](#license)
- [Acknowledgments](#acknowledgments)
- [Sample Output](#sample-output)

## **Overview**

The SOCer is a Python-based SOAR-like automation solution designed for Security Operations Centers (SOC). It automates the enrichment of Indicators of Compromise (IOCs) by querying multiple Threat Intelligence (TI) sources, consolidating results, and applying risk scoring to accelerate investigations and reduce alert fatigue.

### **Key Features**

- **Multi-source Enrichment**: Query VirusTotal, AbuseIPDB, GreyNoise, Shodan, and more
- **Flexible Input Methods**: CLI, file input, and clipboard support
- **Risk Scoring Engine**: Automated risk assessment with color-coded output
- **Multiple Output Formats**: JSON, CSV, HTML reports
- **Extensible Architecture**: Easy to add new TI sources and functionality
- **Professional Terminal Display**: Colorful, human-readable output

## **Architecture**

### **System Design**

```
┌─────────────────┐    ┌─────────────────┐    ┌─────────────────┐
│   Input Handler │ → │ Enrichment Engine│ →  │  Risk Scoring   │
└─────────────────┘    └─────────────────┘    └─────────────────┘
        ↓                      ↓                      ↓
┌─────────────────┐    ┌─────────────────┘    ┌─────────────────┐
│  File/Clipboard │    │TI Source Module │    │ Report Generator│
└─────────────────┘    └─────────────────┘    └─────────────────┘
```

### **Module Structure**

```
soar-mini-automation/
├── socer.py                 # Entry point
├── config.yaml            # Configuration file
├── requirements.txt       # Dependencies
├── modules/              # Core functionality
│   ├── __init__.py
│   ├── input_handler.py      # Input processing
│   ├── enrichment_engine.py  # Orchestration
│   ├── data_normalizer.py    # Data standardization
│   ├── risk_scoring.py       # Risk assessment
│   ├── report_generator.py   # Output generation
│   ├── terminal_display.py   # Colorful terminal output
│   ├── utils.py              # Common utilities
│   └── *_lookup.py          # TI source modules
├── inputs/               # Sample IOC files
├── outputs/              # Generated reports
└── tests/               # Unit tests
```

## **Installation & Setup**

### **Prerequisites**

- Python 3.8+
- pip (Python package manager)
- API keys for desired threat intelligence services

### **Installation Steps**

1. **Clone or create the project structure:**

```bash
mkdir soar-mini-automation && cd soar-mini-automation
# Create the directory structure as shown above
```

1. **Create a virtual environment:**

```bash
python3 -m venv venv
source venv/bin/activate# On Windows: venv\Scripts\activate
```

1. **Install dependencies:**

```bash
pip install -r requirements.txt
```

1. **Configure API keys:**

```bash
cp config.yaml.example config.yaml
# Edit config.yaml with your API keys
```

### **Adding to System PATH**

To make the tool accessible from anywhere in your system:

### **Linux/macOS**

```bash
# Add to your shell profile (~/.bashrc, ~/.zshrc, etc.)echo 'export PATH="$PATH:/path/to/soar-mini-automation"' >> ~/.bashrc
source ~/.bashrc

# Make the script executablechmod +x /path/to/soar-mini-automation/socer.py

# Optional: Create a symlinksudo ln -s /path/to/soar-mini-automation/main.py /usr/local/bin/ioc-enricher
```

### **Windows**

```powershell
# Add to system PATH
setx PATH "%PATH%;C:\path\to\soar-mini-automation"

# Or create a batch file in a directory already in PATH
@echo off
python C:\path\to\soar-mini-automation\socer.py %*
```

## **Configuration**

### **config.yaml Structure**

```yaml
api_keys:
  virustotal: "your_virustotal_api_key_here"
  abuseipdb: "your_abuseipdb_api_key_here"
  greynoise: "your_greynoise_api_key_here"
  shodan: "your_shodan_api_key_here"

settings:
  timeout: 30# API timeout in secondsmax_retries: 3# Retry attempts for API callsoutput_format: "json"# Default output formatoutput_directory: "outputs/"# Report storage location
```

### **Environment Variables (Alternative)**

You can also set API keys as environment variables:

```bash
export VIRUSTOTAL_API_KEY="your_key"
export ABUSEIPDB_API_KEY="your_key"
# etc.
```

## **Usage**

### **Basic Commands**

**Single IOC analysis:**

```bash
python3 socer.py --ioc 8.8.8.8
```

**Batch file processing:**

```bash
python3 socer.py --file inputs/sample_iocs.txt
```

**Clipboard input:**

```bash
# Copy IOCs to clipboard first
# if you are on linux make sure you have xclip installed
# sudo apt-get install xclip
python3 socer.py --clipboard
```

**Terminal display with colors:**

```bash
python3 socer.py --ioc malicious-domain.com --display
```

**Custom output format:**

```bash
python3 socer.py --ioc 8.8.8.8 --output html
```

### **Advanced Options**

```bash
# Verbose logging
python3 socer.py --ioc 8.8.8.8 --verbose

# Custom config file
python3 socer.py --ioc 8.8.8.8 --config custom_config.yaml

# Custom output directory
python3 socer.py --ioc 8.8.8.8 --output-dir ./reports/

# No timestamp in filename
python3 socer.py --ioc 8.8.8.8 --no-timestamp
```

### **Input File Format**

Create a text file with one IOC per line:

```
8.8.8.8
google.com
44d88612fea8a8f36de82e1278abb02f
malicious-domain.com
```

## **Sample Output**
```bash
python3 socer.py --ioc 60.17.67.45 --display
```

```
  .--.--.                                               
 /  /    '.                                             
|  :  /`. /     ,---.                           __  ,-. 
;  |  |--`     '   ,'\                        ,' ,'/ /| 
|  :  ;_      /   /   |    ,---.      ,---.   '  | |' | 
 \  \    `.  .   ; ,. :   /     \    /     \  |  |   ,' 
  `----.   \ '   | |: :  /    / '   /    /  | '  :  /   
  __ \  \  | '   | .; : .    ' /   .    ' / | |  | '    
 /  /`--'  / |   :    | '   ; :__  '   ;   /| ;  : |    
'--'.     /   \   \  /  '   | '.'| '   |  / | |  , ;    
  `--'---'     `----'   |   :    : |   :    |  ---'     
                         \   \  /   \   \  /            
                          `----'     `----'             


   ooo   ccc   eee   rrr
  o   o c     e     r  r
  o   o c     eee   rrr 
  o   o c     e     r r 
   ooo   ccc   eee   r  r

2025-08-25 20:50:53,044 - modules.utils - INFO - Processing 1 IOCs
Processing 1 IOC(s)...
2025-08-25 20:50:53,045 - modules.utils - INFO - Processing IOC 1/1: 60.17.67.45
Enriching IOC 1/1: 60.17.67.45

IOC ENRICHMENT RESULTS
============================================================

================================================================================
IOC: 60.17.67.45 (ip)
Risk Level: Medium (38.75)
================================================================================

VirusTotal:
  Malicious: 3
  Suspicious: 0
  Undetected: 30
  Harmless: 61
  Reputation: 0
  Last Analysis Date: 1756182609

AbuseIPDB:
  Abuse Confidence Score: 39
  Total Reports: 5
  Country Code: CN
  Isp: China Unicom Liaoning province network
  Domain: chinaunicom.cn
  Usage Type: Fixed Line ISP

GreyNoise:
  Noise: True
  Riot: False
  Classification: malicious
  Name: unknown
  Link: https://viz.greynoise.io/ip/60.17.67.45
  Last Seen: 2025-08-26

Shodan:
  Error: Shodan API request failed: 404 {"error": "No information available for that IP."}

IPLocation:
  Continent: Asia
  Country: China
  Region: Liaoning
  City: Sujiatun
  Lat: 41.6592
  Lon: 123.339
  Timezone: Asia/Shanghai
  Isp: CHINA UNICOM China169 Backbone
  Org: Unicom LN
  As: AS4837 CHINA UNICOM China169 Backbone
  Proxy: False
  Hosting: False

Summary:
  VirusTotal:
    Detections: 3
    Scan Date: 1756182609
  AbuseIPDB:
    Abuse Score: 39
    Reports: 5
  GreyNoise:
    Classification: malicious
    Last Seen: 2025-08-26
  IPLocation:
    Country: China
    Asn: AS4837 CHINA UNICOM China169 Backbone
    Isp: CHINA UNICOM China169 Backbone

================================================================================

Analysis complete!
Processing complete!
Results saved to: outputs/ioc_report_20250825_205056.json
```

## **API Integration**

### **Supported Threat Intelligence Sources**

1. **VirusTotal** - Multi-engine malware detection
    - Required: API key from https://www.virustotal.com/
    - Endpoints: IPs, domains, file hashes
2. **AbuseIPDB** - IP reputation and abuse reports
    - Required: API key from https://www.abuseipdb.com/
    - Endpoints: IP addresses only
3. **GreyNoise** - Internet background noise analysis
    - Required: API key from https://www.greynoise.io/
    - Endpoints: IP addresses only
4. **Shodan** - Open port and service discovery
    - Required: API key from https://www.shodan.io/
    - Endpoints: IP addresses only
5. **IP Location** - Free geolocation service (no API key needed)
    - Endpoints: IP addresses only
6. **WHOIS** - Domain registration information (no API key needed)
    - Endpoints: Domains only

### **Adding New API Sources**

To add a new threat intelligence source:

1. Create a new lookup module in **`modules/:`**

```python
# modules/new_source_lookup.pyfrom .utils import make_api_request

class NewSourceLookup:
    def __init__(self, config):
        self.api_key = config['api_keys'].get('new_source')
        self.base_url = "https://api.new-source.com/v1"
        self.headers = {"Authorization": f"Bearer {self.api_key}"}

    def lookup_ioc(self, ioc, ioc_type):
# Implement API call and data parsing
        url = f"{self.base_url}/check/{ioc}"
        response = make_api_request(url, self.headers)
        return self._parse_response(response)

    def _parse_response(self, response):
# Extract and format relevant datareturn {
            'score': response.get('threat_score', 0),
            'classification': response.get('verdict', 'unknown')
        }
```

1. Update the appropriate lookup class:

```python
# In ip_lookup.py, domain_lookup.py, or hash_lookup.pyfrom .new_source_lookup import NewSourceLookup

class IPLookup:
    def __init__(self, config):
# ... existing code ...
        self.new_source = NewSourceLookup(config)

    def enrich(self, ip):
        results = {}
# ... existing code ...
        new_source_result = self.new_source.lookup_ip(ip)
        if new_source_result:
            results["NewSource"] = new_source_result
        return results
```

1. Update the data normalizer:

```python
# In data_normalizer.pyclass DataNormalizer:
# ... existing code ...

    @staticmethod
    def normalize_new_source_data(data):
        normalized = {}
        if 'score' in data:
            normalized['threat_score'] = data['score']
            normalized['verdict'] = data.get('classification', 'unknown')
        return normalized

    def normalize_all(self, enrichment_data):
        normalized = {}
# ... existing code ...elif source == "NewSource":
            normalized[source] = self.normalize_new_source_data(data)
# ... existing code ...return normalized
```

1. Update the risk scoring engine if needed:

```python
# In risk_scoring.pyclass RiskScoringEngine:
    def calculate_score(self, normalized_data):
        score = 0
# ... existing code ...

# Add new source scoring
        new_source_data = normalized_data.get('NewSource', {})
        threat_score = new_source_data.get('threat_score', 0)
        score += threat_score * 0.15# Adjust weight as needed

        return min(score, 100)
```

## **Extending the Tool**

### **Adding New IOC Types**

1. Update IOC detection in **`utils.py`**:

```python
def detect_ioc_type(ioc):
# ... existing patterns ...

# Add new IOC type pattern
    new_type_pattern = r'^new_ioc_pattern$'
    if re.match(new_type_pattern, ioc):
        return "new_type"

    return None
```

1. Create a new lookup class in **`modules/`**:

```python
# modules/new_type_lookup.pyfrom typing import Dict, Any

class NewTypeLookup:
    def __init__(self, config: Dict[str, Any]):
        self.config = config
# Initialize any required API clients

    def enrich(self, new_type_ioc: str) -> Dict[str, Any]:
        results = {}
# Implement enrichment logicreturn results
```

1. Update the enrichment engine:

```python
# In enrichment_engine.pyfrom .new_type_lookup import NewTypeLookup

class EnrichmentEngine:
    def __init__(self, config):
# ... existing code ...
        self.new_type_lookup = NewTypeLookup(config)

    def enrich(self, ioc):
        ioc_type = detect_ioc_type(ioc)
# ... existing code ...elif ioc_type == "new_type":
            result["sources"] = self.new_type_lookup.enrich(ioc)
# ... existing code ...return result
```

### **Custom Risk Scoring**

To modify the risk scoring algorithm:

```python
# Create a custom risk scoring classclass CustomRiskScoringEngine(RiskScoringEngine):
    def __init__(self, custom_weights=None):
        super().__init__()
        if custom_weights:
            self.weights = custom_weights

    def calculate_score(self, normalized_data):
# Implement custom scoring logic
        score = 0

# Example: Different weighting for specific sources
        vt_data = normalized_data.get('VirusTotal', {})
        vt_detections = vt_data.get('detections', 0)
        score += min(vt_detections * 15, 40)# Increased weight

# Add custom factorsif self._is_suspicious_country(normalized_data):
            score += 20

        return min(score, 100)

    def _is_suspicious_country(self, normalized_data):
        location_data = normalized_data.get('IPLocation', {})
        country = location_data.get('country', '').lower()
        suspicious = ['cn', 'ru', 'ir', 'kp', 'sy']
        return country in suspicious

# Usage in socer.py
custom_scorer = CustomRiskScoringEngine({
    'virustotal_detections': 0.4,
    'abuseipdb_score': 0.2,
# ... custom weights})
```

### **Custom Output Formats**

To add a new output format:

1. Extend the report generator:

```python
# In report_generator.pyclass ReportGenerator:
# ... existing code ...

    def generate_custom_report(self, results, no_timestamp=False):
        filename = self._generate_filename("custom", no_timestamp)

# Implement custom formatting logicwith open(filename, 'w') as f:
            for result in results:
# Custom formatting
                f.write(f"IOC: {result['ioc']}\n")
                f.write(f"Risk: {result['risk_assessment']['level']}\n")
# ... more fields ...

        return filename
```

1. Update the main application to support the new format:

```python
# In socer.pyif output_format == "custom":
    filename = report_generator.generate_custom_report(results, args.no_timestamp)
```

## **Development Guidelines**

### **Code Style**

- Follow PEP 8 guidelines
- Use type hints for function signatures
- Write docstrings for all public methods
- Use descriptive variable names

### **Testing**

- Write unit tests for new functionality
- Place tests in the **`tests/`** directory
- Use pytest framework for testing
- Maintain test coverage > 80%

Example test structure:

```python
# tests/test_new_feature.pyimport unittest
from modules.new_feature import NewFeature

class TestNewFeature(unittest.TestCase):
    def setUp(self):
        self.feature = NewFeature()

    def test_feature_behavior(self):
        result = self.feature.process("input")
        self.assertEqual(result, "expected_output")

    def test_error_handling(self):
        with self.assertRaises(ValueError):
            self.feature.process(None)

if __name__ == "__main__":
    unittest.main()
```

### **Error Handling**

- Use try-except blocks for API calls
- Provide meaningful error messages
- Implement retry logic for transient failures
- Validate inputs before processing

### **Logging**

- Use the built-in logging module
- Different log levels for different environments
- Configurable verbosity

## **Troubleshooting**

### **Common Issues**

1. **API Key Errors**
    - Symptom: "API key not configured" errors
    - Solution: Check config.yaml or environment variables
2. **Rate Limiting**
    - Symptom: API requests failing with 429 errors
    - Solution: Implement retry logic or upgrade API plan
3. **Network Issues**
    - Symptom: Timeout errors
    - Solution: Increase timeout setting in config
4. **Memory Issues with Large Files**
    - Symptom: Slow performance with large input files
    - Solution: Process IOCs in batches

### **Debug Mode**

Enable verbose logging for debugging:

```bash
python socer.py --ioc 8.8.8.8 --verbose
```

### **Getting Help**

1. Check the log files in the output directory
2. Verify API keys are correct and have sufficient privileges
3. Ensure all dependencies are installed correctly
4. Check network connectivity to API endpoints

## **Contributing**

### **Development Process**

1. Fork the repository
2. Create a feature branch
3. Implement changes with tests
4. Submit a pull request

### **Contribution Guidelines**

- Maintain backward compatibility
- Update documentation for new features
- Add tests for new functionality
- Follow the existing code style

### **Roadmap**

- Web dashboard interface
- Real-time monitoring capabilities
- Additional TI source integrations
- Advanced correlation engine
- Machine learning-based risk assessment
- Plugin system for extensibility

---

## **Support**

For questions, issues, or contributions:

- Create an issue on the GitHub repository
- Check the documentation for common solutions
- Review existing issues for similar problems

## **License**

This project is licensed under the MIT License - see the LICENSE file for details.

## **Acknowledgments**

- VirusTotal, AbuseIPDB, GreyNoise, and Shodan for their threat intelligence APIs
- The open-source community for various Python libraries used in this project
- Security researchers and SOC analysts who provided feedback and testing

---

