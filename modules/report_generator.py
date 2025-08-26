"""
Report generator for the IOC enrichment tool
"""

import json
import csv
import os
from datetime import datetime
from typing import List, Dict, Any
from jinja2 import Template
from .data_normalizer import DataNormalizer
from .risk_scoring import RiskScoringEngine

class ReportGenerator:
    """Generates reports in various formats"""
    
    def __init__(self, config: Dict[str, Any]):
        self.config = config
        self.output_dir = config['settings']['output_directory']
        self.normalizer = DataNormalizer()
        self.risk_scorer = RiskScoringEngine()
        
        # Create output directory if it doesn't exist
        os.makedirs(self.output_dir, exist_ok=True)
    
    def _generate_filename(self, format: str, no_timestamp: bool = False) -> str:
        """
        Generate a filename with optional timestamp
        
        Args:
            format: File format extension
            no_timestamp: If True, don't include timestamp in filename
            
        Returns:
            Generated filename
        """
        if no_timestamp:
            filename = f"ioc_report.{format}"
        else:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            filename = f"ioc_report_{timestamp}.{format}"
        
        return os.path.join(self.output_dir, filename)
    
    def _add_risk_assessment(self, results: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """
        Add risk assessment to all results
        
        Args:
            results: List of enrichment results
            
        Returns:
            Results with risk assessment added
        """
        for result in results:
            if 'sources' in result and 'error' not in result:
                normalized_data = self.normalizer.normalize_all(result['sources'])
                risk_assessment = self.risk_scorer.assess_risk(normalized_data)
                
                result['normalized_sources'] = normalized_data
                result['risk_assessment'] = risk_assessment
            else:
                # Add empty risk assessment for errored results
                result['risk_assessment'] = {"score": 0, "level": "Unknown"}
        
        return results
    
    def generate_json_report(self, results: List[Dict[str, Any]], no_timestamp: bool = False) -> str:
        """
        Generate a JSON report
        
        Args:
            results: List of enrichment results
            no_timestamp: If True, don't include timestamp in filename
            
        Returns:
            Path to the generated report
        """
        # Add risk assessment to all results
        results_with_risk = self._add_risk_assessment(results)
        
        filename = self._generate_filename("json", no_timestamp)
        
        with open(filename, 'w') as f:
            json.dump(results_with_risk, f, indent=2)
        
        return filename
    
    def generate_csv_report(self, results: List[Dict[str, Any]], no_timestamp: bool = False) -> str:
        """
        Generate a CSV report
        
        Args:
            results: List of enrichment results
            no_timestamp: If True, don't include timestamp in filename
            
        Returns:
            Path to the generated report
        """
        # Add risk assessment to all results
        results_with_risk = self._add_risk_assessment(results)
        
        filename = self._generate_filename("csv", no_timestamp)
        
        # Flatten the data for CSV
        csv_data = []
        for result in results_with_risk:
            if 'error' in result:
                csv_data.append({
                    'ioc': result['ioc'],
                    'type': result.get('type', 'unknown'),
                    'error': result['error']
                })
                continue
            
            # Add data from each source
            row = {
                'ioc': result['ioc'],
                'type': result['type'],
                'risk_score': result['risk_assessment']['score'],
                'risk_level': result['risk_assessment']['level']
            }
            
            # Add normalized data
            normalized_data = result.get('normalized_sources', {})
            for source, data in normalized_data.items():
                for key, value in data.items():
                    if isinstance(value, list):
                        value = ';'.join(map(str, value))
                    row[f"{source}_{key}"] = value
            
            csv_data.append(row)
        
        # Write to CSV
        if csv_data:
            fieldnames = csv_data[0].keys()
            with open(filename, 'w', newline='') as f:
                writer = csv.DictWriter(f, fieldnames=fieldnames)
                writer.writeheader()
                writer.writerows(csv_data)
        
        return filename
    
    def generate_html_report(self, results: List[Dict[str, Any]], no_timestamp: bool = False) -> str:
        """
        Generate an HTML report
        
        Args:
            results: List of enrichment results
            no_timestamp: If True, don't include timestamp in filename
            
        Returns:
            Path to the generated report
        """
        # Add risk assessment to all results
        results_with_risk = self._add_risk_assessment(results)
        
        filename = self._generate_filename("html", no_timestamp)
        
        # Prepare data for HTML template
        report_data = []
        for result in results_with_risk:
            if 'error' in result:
                report_data.append({
                    'ioc': result['ioc'],
                    'type': result.get('type', 'unknown'),
                    'error': result['error'],
                    'risk_level': 'Unknown'
                })
                continue
            
            report_data.append({
                'ioc': result['ioc'],
                'type': result['type'],
                'sources': result.get('normalized_sources', {}),
                'risk_score': result['risk_assessment']['score'],
                'risk_level': result['risk_assessment']['level']
            })
        
        # HTML template
        html_template = """
        <!DOCTYPE html>
        <html>
        <head>
            <title>IOC Enrichment Report</title>
            <style>
                body { font-family: Arial, sans-serif; margin: 20px; }
                h1 { color: #333; }
                .ioc-card { border: 1px solid #ddd; padding: 15px; margin-bottom: 20px; border-radius: 5px; }
                .low-risk { border-left: 5px solid #4CAF50; }
                .medium-risk { border-left: 5px solid #FFC107; }
                .high-risk { border-left: 5px solid #F44336; }
                .unknown-risk { border-left: 5px solid #9E9E9E; }
                .source-section { margin-top: 10px; }
                .source-name { font-weight: bold; margin-top: 10px; }
                .risk-badge { 
                    display: inline-block; 
                    padding: 3px 8px; 
                    border-radius: 3px; 
                    color: white; 
                    font-weight: bold; 
                }
                .risk-low { background-color: #4CAF50; }
                .risk-medium { background-color: #FFC107; }
                .risk-high { background-color: #F44336; }
                .risk-unknown { background-color: #9E9E9E; }
                table { border-collapse: collapse; width: 100%; }
                th, td { border: 1px solid #ddd; padding: 8px; text-align: left; }
                th { background-color: #f2f2f2; }
            </style>
        </head>
        <body>
            <h1>IOC Enrichment Report</h1>
            <p>Generated on: {{ timestamp }}</p>
            <p>Total IOCs: {{ ioc_count }}</p>
            
            {% for item in report_data %}
            <div class="ioc-card {{ item.risk_level|lower }}-risk">
                <h2>IOC: {{ item.ioc }} ({{ item.type }})</h2>
                <p>
                    Risk Level: 
                    <span class="risk-badge risk-{{ item.risk_level|lower }}">
                        {{ item.risk_level }} ({{ item.risk_score }})
                    </span>
                </p>
                
                {% if item.error %}
                    <p class="error">Error: {{ item.error }}</p>
                {% else %}
                    {% for source_name, source_data in item.sources.items() %}
                    <div class="source-section">
                        <div class="source-name">{{ source_name }}</div>
                        <table>
                            {% for key, value in source_data.items() %}
                            <tr>
                                <th>{{ key }}</th>
                                <td>
                                    {% if value is iterable and value is not string %}
                                        {{ value|join(', ') }}
                                    {% else %}
                                        {{ value }}
                                    {% endif %}
                                </td>
                            </tr>
                            {% endfor %}
                        </table>
                    </div>
                    {% endfor %}
                {% endif %}
            </div>
            {% endfor %}
        </body>
        </html>
        """
        
        # Render template
        template = Template(html_template)
        html_content = template.render(
            timestamp=datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            ioc_count=len(report_data),
            report_data=report_data
        )
        
        # Write to file
        with open(filename, 'w') as f:
            f.write(html_content)
        
        return filename