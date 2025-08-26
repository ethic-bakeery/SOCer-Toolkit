"""
Input handler for the IOC enrichment tool
"""

import os
import pyperclip
from typing import List
from .utils import detect_ioc_type

class InputHandler:
    """Handles input from various sources and validates IOCs"""
    
    def __init__(self):
        self.valid_iocs = []
    
    def get_iocs(self, cli_ioc: str = None, file_path: str = None, 
                from_clipboard: bool = False) -> List[str]:
        """
        Get IOCs from various input sources
        
        Args:
            cli_ioc: IOC from command line
            file_path: Path to file containing IOCs
            from_clipboard: Whether to read from clipboard
            
        Returns:
            List of valid IOCs
        """
        iocs = []
        
        # Get IOC from command line
        if cli_ioc:
            ioc_type = detect_ioc_type(cli_ioc)
            if ioc_type:
                iocs.append(cli_ioc)
            else:
                print(f"Warning: {cli_ioc} is not a recognized IOC type")
        
        # Get IOCs from file
        if file_path:
            file_iocs = self._read_iocs_from_file(file_path)
            iocs.extend(file_iocs)
        
        # Get IOCs from clipboard
        if from_clipboard:
            clipboard_iocs = self._read_iocs_from_clipboard()
            iocs.extend(clipboard_iocs)
        
        # Remove duplicates and validate
        unique_iocs = list(set(iocs))
        self.valid_iocs = [ioc for ioc in unique_iocs if detect_ioc_type(ioc)]
        
        return self.valid_iocs
    
    def _read_iocs_from_file(self, file_path: str) -> List[str]:
        """
        Read IOCs from a file
        
        Args:
            file_path: Path to the file
            
        Returns:
            List of IOCs from the file
        """
        if not os.path.exists(file_path):
            print(f"Warning: File {file_path} does not exist")
            return []
        
        iocs = []
        try:
            with open(file_path, 'r') as file:
                for line in file:
                    line = line.strip()
                    if line and not line.startswith('#'):  # Skip empty lines and comments
                        iocs.append(line)
        except IOError as e:
            print(f"Error reading file {file_path}: {e}")
        
        return iocs
    
    def _read_iocs_from_clipboard(self) -> List[str]:
        """
        Read IOCs from clipboard
        
        Returns:
            List of IOCs from clipboard
        """
        try:
            clipboard_content = pyperclip.paste()
            if not clipboard_content:
                return []
            
            # Split by common delimiters
            delimiters = ['\n', '\t', ',', ';', ' ']
            iocs = []
            
            for delimiter in delimiters:
                if delimiter in clipboard_content:
                    iocs = [ioc.strip() for ioc in clipboard_content.split(delimiter) if ioc.strip()]
                    break
            
            # If no delimiters found, treat the whole content as one IOC
            if not iocs:
                iocs = [clipboard_content.strip()]
            
            return iocs
        except pyperclip.PyperclipException as e:
            print(f"Error accessing clipboard: {e}")
            return []