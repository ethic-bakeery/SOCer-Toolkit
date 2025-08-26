#!/usr/bin/env python3
"""
Main entry point for the IOC Enrichment & Reputation Tool
"""

import argparse
import sys
import textwrap
from modules.input_handler import InputHandler
from modules.enrichment_engine import EnrichmentEngine
from modules.report_generator import ReportGenerator
from modules.terminal_display import TerminalDisplay
from modules.utils import load_config, setup_logging

# Import the banner
try:
    from banner import print_banner
except ImportError:
    # Fallback if banner.py doesn't exist
    def print_banner():
        print("=" * 60)
        print("IOC Enrichment & Reputation Tool")
        print("=" * 60)

def main():
    """Main function to run the IOC enrichment tool"""
    # Display banner
    
    # Parse command line arguments with detailed help
    parser = argparse.ArgumentParser(
        description="IOC Enrichment & Reputation Tool",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=textwrap.dedent('''
        EXAMPLES:
          # Single IOC lookup with terminal display
          python socer.py --ioc 8.8.8.8 --display
          
          # Batch file processing with HTML output
          python socer.py --file inputs/sample_iocs.txt --output html
          
          # Clipboard input with verbose logging and terminal display
          python socer.py --clipboard --verbose --display

        SUPPORTED IOC TYPES:
          • IP Addresses: 8.8.8.8, 2001:db8::1
          • Domains: example.com, sub.domain.org
          • File Hashes: 
            - MD5: 44d88612fea8a8f36de82e1278abb02f
            - SHA1: 7c4a8d09ca3762af61e59520943dc26494f8941b
            - SHA256: 5e884898da28047151d0e56f8dc6292773603d0d6aabbdd62a11ef721d1542d8
        ''')
    )
    
    # Input arguments
    input_group = parser.add_argument_group('Input Options')
    input_group.add_argument("--ioc", type=str, 
                           help="Single IOC to analyze (IP, domain, or hash)")
    input_group.add_argument("--file", type=str, 
                           help="File containing IOCs to analyze (one per line)")
    input_group.add_argument("--clipboard", action="store_true", 
                           help="Use IOCs from clipboard (supports multiple IOCs separated by newlines, commas, or spaces)")
    
    # Output arguments
    output_group = parser.add_argument_group('Output Options')
    output_group.add_argument("--output", type=str, choices=["json", "csv", "html"], 
                            default="json", help="Output format (default: json)")
    output_group.add_argument("--output-dir", type=str, 
                            help="Custom output directory (default: ./outputs/)")
    output_group.add_argument("--no-timestamp", action="store_true",
                            help="Don't include timestamp in output filename")
    output_group.add_argument("--display", "-d", action="store_true",
                            help="Display colorful results in terminal")
    output_group.add_argument("--no-banner", action="store_true",
                            help="Don't display the banner")
    
    # Configuration arguments
    config_group = parser.add_argument_group('Configuration Options')
    config_group.add_argument("--config", type=str, default="config.yaml",
                            help="Path to config file (default: config.yaml)")
    config_group.add_argument("--timeout", type=int, 
                            help="API timeout in seconds (overrides config)")
    
    # Miscellaneous arguments
    misc_group = parser.add_argument_group('Miscellaneous Options')
    misc_group.add_argument("--verbose", "-v", action="store_true", 
                          help="Enable verbose output")
    misc_group.add_argument("--version", action="version", 
                          version="IOC Enrichment Tool v1.0.0",
                          help="Show program version and exit")
    
    args = parser.parse_args()
    
    # Display banner unless disabled
    if not args.no_banner:
        print_banner()
        print()  # Add some space after banner
    
    # Validate arguments
    if not any([args.ioc, args.file, args.clipboard]):
        parser.error("No input specified. Use --ioc, --file, or --clipboard")
    
    # Load configuration
    try:
        config = load_config(args.config)
    except FileNotFoundError:
        print(f"Error: Config file '{args.config}' not found.")
        print("Please create a config.yaml file with your API keys.")
        print("See the README for configuration instructions.")
        sys.exit(1)
    
    # Override config values with command line arguments
    if args.timeout:
        config['settings']['timeout'] = args.timeout
    if args.output_dir:
        config['settings']['output_directory'] = args.output_dir
    if args.output:
        config['settings']['output_format'] = args.output
    
    # Setup logging
    logger = setup_logging(args.verbose)
    
    # Handle input
    input_handler = InputHandler()
    iocs = input_handler.get_iocs(args.ioc, args.file, args.clipboard)
    
    if not iocs:
        logger.error("No valid IOCs found to process")
        print("Error: No valid IOCs detected. Please check your input.")
        print("Supported IOC types: IP addresses, domains, MD5/SHA1/SHA256 hashes")
        sys.exit(1)
    
    logger.info(f"Processing {len(iocs)} IOCs")
    print(f"Processing {len(iocs)} IOC(s)...")
    
    # Enrich IOCs
    enrichment_engine = EnrichmentEngine(config)
    results = []
    
    for i, ioc in enumerate(iocs, 1):
        logger.info(f"Processing IOC {i}/{len(iocs)}: {ioc}")
        print(f"Enriching IOC {i}/{len(iocs)}: {ioc}")
        result = enrichment_engine.enrich(ioc)
        results.append(result)
    
    # Generate reports
    report_generator = ReportGenerator(config)
    output_format = config['settings']['output_format']
    
    try:
        if output_format == "json":
            filename = report_generator.generate_json_report(results, args.no_timestamp)
        elif output_format == "csv":
            filename = report_generator.generate_csv_report(results, args.no_timestamp)
        elif output_format == "html":
            filename = report_generator.generate_html_report(results, args.no_timestamp)
    except Exception as e:
        logger.error(f"Report generation failed: {e}")
        print(f"Error generating report: {e}")
        sys.exit(1)
    
    # Display results in terminal if requested
    if args.display:
        terminal_display = TerminalDisplay()
        terminal_display.display_results(results)
    
    print("Processing complete!")
    print(f"Results saved to: {filename}")

if __name__ == "__main__":
    main()