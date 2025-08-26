"""
Terminal display module for colorful output of IOC enrichment results
"""

class TerminalDisplay:
    """Displays IOC enrichment results in a colorful terminal format"""
    
    # ANSI color codes
    COLORS = {
        'RED': '\033[91m',
        'GREEN': '\033[92m',
        'YELLOW': '\033[93m',
        'BLUE': '\033[94m',
        'MAGENTA': '\033[95m',
        'CYAN': '\033[96m',
        'WHITE': '\033[97m',
        'RESET': '\033[0m',
        'BOLD': '\033[1m',
        'UNDERLINE': '\033[4m'
    }
    
    def _colorize(self, text, color):
        """Apply color to text"""
        return f"{self.COLORS[color]}{text}{self.COLORS['RESET']}"
    
    def _get_risk_color(self, risk_level):
        """Get color based on risk level"""
        if risk_level == "High":
            return "RED"
        elif risk_level == "Medium":
            return "YELLOW"
        elif risk_level == "Low":
            return "GREEN"
        else:
            return "WHITE"
    
    def _display_ioc_header(self, ioc, ioc_type, risk_score, risk_level):
        """Display IOC header with risk information"""
        risk_color = self._get_risk_color(risk_level)
        
        print("\n" + "="*80)
        print(f"{self._colorize('IOC:', 'BOLD')} {self._colorize(ioc, 'CYAN')} ({ioc_type})")
        print(f"{self._colorize('Risk Level:', 'BOLD')} {self._colorize(risk_level, risk_color)} "
              f"{self._colorize(f'({risk_score})', risk_color)}")
        print("="*80)
    
    def _display_source_results(self, source_name, source_data):
        """Display results from a single source"""
        print(f"\n{self._colorize(source_name + ':', 'BOLD')}")
        
        if 'error' in source_data:
            print(f"  {self._colorize('Error:', 'RED')} {source_data['error']}")
            return
        
        for key, value in source_data.items():
            # Skip empty values
            if value is None or value == "":
                continue
                
            # Format list values
            if isinstance(value, list):
                if value:
                    value_str = ", ".join(str(v) for v in value)
                else:
                    continue
            else:
                value_str = str(value)
            
            # Apply color based on content
            display_key = f"  {key.replace('_', ' ').title()}:"
            
            if key in ['malicious', 'detections', 'abuse_score', 'abuse_confidence_score']:
                if value > 0:
                    display_value = self._colorize(value_str, 'RED')
                else:
                    display_value = self._colorize(value_str, 'GREEN')
            elif key in ['classification']:
                if 'malicious' in value_str.lower():
                    display_value = self._colorize(value_str, 'RED')
                elif 'benign' in value_str.lower():
                    display_value = self._colorize(value_str, 'GREEN')
                else:
                    display_value = self._colorize(value_str, 'YELLOW')
            elif key in ['country']:
                # Highlight suspicious countries
                suspicious_countries = ['china', 'russia', 'iran', 'north korea', 'syria']
                if any(country in value_str.lower() for country in suspicious_countries):
                    display_value = self._colorize(value_str, 'YELLOW')
                else:
                    display_value = value_str
            else:
                display_value = value_str
            
            print(f"{display_key} {display_value}")
    
    def _display_normalized_summary(self, normalized_data):
        """Display normalized summary information"""
        print(f"\n{self._colorize('Summary:', 'BOLD')}")
        
        for source, data in normalized_data.items():
            if not data:  # Skip empty sources
                continue
                
            print(f"  {self._colorize(source + ':', 'UNDERLINE')}")
            for key, value in data.items():
                if value is None or value == "":
                    continue
                    
                if isinstance(value, list):
                    if value:
                        value_str = ", ".join(str(v) for v in value)
                    else:
                        continue
                else:
                    value_str = str(value)
                
                display_key = f"    {key.replace('_', ' ').title()}:"
                
                # Apply color based on content
                if key in ['detections', 'abuse_score', 'reports']:
                    if value > 0:
                        display_value = self._colorize(value_str, 'RED')
                    else:
                        display_value = self._colorize(value_str, 'GREEN')
                elif key in ['classification']:
                    if 'malicious' in value_str.lower():
                        display_value = self._colorize(value_str, 'RED')
                    elif 'benign' in value_str.lower():
                        display_value = self._colorize(value_str, 'GREEN')
                    else:
                        display_value = self._colorize(value_str, 'YELLOW')
                else:
                    display_value = value_str
                
                print(f"{display_key} {display_value}")
    
    def display_results(self, results):
        """
        Display enrichment results in the terminal with colors
        
        Args:
            results: List of enrichment results
        """
        print(f"\n{self._colorize('IOC ENRICHMENT RESULTS', 'BOLD')}")
        print(f"{self._colorize('=' * 60, 'BOLD')}")
        
        for result in results:
            # Extract basic information
            ioc = result.get('ioc', 'Unknown')
            ioc_type = result.get('type', 'Unknown')
            
            # Get risk assessment
            risk_assessment = result.get('risk_assessment', {})
            risk_score = risk_assessment.get('score', 0)
            risk_level = risk_assessment.get('level', 'Unknown')
            
            # Get sources data
            sources = result.get('sources', {})
            normalized_sources = result.get('normalized_sources', {})
            
            # Display header
            self._display_ioc_header(ioc, ioc_type, risk_score, risk_level)
            
            # Display detailed source results
            for source_name, source_data in sources.items():
                self._display_source_results(source_name, source_data)
            
            # Display normalized summary
            if normalized_sources:
                self._display_normalized_summary(normalized_sources)
            
            print("\n" + "="*80)
        
        print(f"\n{self._colorize('Analysis complete!', 'GREEN')}")