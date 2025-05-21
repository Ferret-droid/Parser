import logging
import os
import subprocess
import tempfile
from typing import Dict, List, Any, Tuple

class YaraXEngine:
    """
    Wrapper for YARA-X rule execution engine.
    Handles rule compilation, scanning, and result parsing.
    """
    
    def __init__(self, rules_directory: str = None):
        """
        Initialize YARA-X engine with a rules directory.
        
        Args:
            rules_directory: Directory containing YARA-X rule files (.yar, .yara)
        """
        self.rules_directory = rules_directory or os.path.join(
            os.path.dirname(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))),
            "data", "yara_rules"
        )
        self.logger = logging.getLogger(__name__)
        self.logger.info(f"Initializing YARA-X engine with rules from: {self.rules_directory}")
        
        # Check if yara-x is installed
        try:
            version = subprocess.check_output(["yax", "--version"], stderr=subprocess.STDOUT).decode().strip()
            self.logger.info(f"YARA-X version: {version}")
        except (subprocess.SubprocessError, FileNotFoundError):
            self.logger.error("YARA-X (yax) not found. Please install YARA-X.")
            raise RuntimeError("YARA-X not installed or not in PATH")
    
    def compile_rules(self, rules_content: str = None, rule_file: str = None) -> str:
        """
        Compile YARA-X rules from a string or a file.
        Returns path to compiled rules file.
        
        Args:
            rules_content: String containing YARA rules
            rule_file: Path to a YARA rule file
            
        Returns:
            Path to the compiled rules file
        """
        if not rules_content and not rule_file:
            raise ValueError("Either rules_content or rule_file must be provided")
        
        # Create a temporary file for the rules
        temp_rule_file = None
        if rules_content:
            fd, temp_rule_file = tempfile.mkstemp(suffix='.yar')
            with os.fdopen(fd, 'w') as f:
                f.write(rules_content)
            rule_file = temp_rule_file
        
        # Compile the rules
        fd, compiled_rules = tempfile.mkstemp(suffix='.yarc')
        os.close(fd)
        
        try:
            subprocess.check_call([
                "yax", "compile", 
                "-o", compiled_rules,
                rule_file
            ])
            self.logger.info(f"Successfully compiled rules to {compiled_rules}")
            return compiled_rules
        except subprocess.SubprocessError as e:
            self.logger.error(f"Failed to compile YARA rules: {e}")
            raise
        finally:
            # Clean up temporary rule file if created
            if temp_rule_file and os.path.exists(temp_rule_file):
                os.unlink(temp_rule_file)
    
    def scan_content(self, content: str, compiled_rules: str = None, rules_content: str = None) -> List[Dict[str, Any]]:
        """
        Scan content with YARA-X rules.
        
        Args:
            content: The content to scan
            compiled_rules: Path to compiled rules file (priority)
            rules_content: Raw rules content to compile if compiled_rules not provided
            
        Returns:
            List of match results
        """
        # Create temporary file for content
        fd, content_file = tempfile.mkstemp()
        with os.fdopen(fd, 'w') as f:
            f.write(content)
        
        # Handle rules
        if not compiled_rules and rules_content:
            compiled_rules = self.compile_rules(rules_content=rules_content)
        elif not compiled_rules:
            raise ValueError("Either compiled_rules or rules_content must be provided")
        
        # Perform the scan
        try:
            output = subprocess.check_output([
                "yax", "scan",
                "--compiled-rules", compiled_rules,
                content_file
            ], stderr=subprocess.PIPE).decode()
            
            return self._parse_scan_output(output)
        except subprocess.SubprocessError as e:
            self.logger.error(f"Failed to scan content with YARA-X: {e}")
            return []
        finally:
            # Clean up temporary files
            if os.path.exists(content_file):
                os.unlink(content_file)
    
    def scan_file(self, file_path: str, compiled_rules: str = None, rules_content: str = None) -> List[Dict[str, Any]]:
        """
        Scan a file with YARA-X rules.
        
        Args:
            file_path: Path to the file to scan
            compiled_rules: Path to compiled rules file (priority)
            rules_content: Raw rules content to compile if compiled_rules not provided
            
        Returns:
            List of match results
        """
        # Handle rules
        if not compiled_rules and rules_content:
            compiled_rules = self.compile_rules(rules_content=rules_content)
        elif not compiled_rules:
            raise ValueError("Either compiled_rules or rules_content must be provided")
        
        # Perform the scan
        try:
            output = subprocess.check_output([
                "yax", "scan",
                "--compiled-rules", compiled_rules,
                file_path
            ], stderr=subprocess.PIPE).decode()
            
            return self._parse_scan_output(output)
        except subprocess.SubprocessError as e:
            self.logger.error(f"Failed to scan file with YARA-X: {e}")
            return []
    
    def _parse_scan_output(self, output: str) -> List[Dict[str, Any]]:
        """
        Parse the output from YARA-X scan command.
        
        Args:
            output: Output string from yax scan command
            
        Returns:
            List of parsed match results
        """
        results = []
        
        # Simple parsing of YARA output
        # This will need to be adapted based on actual output format
        lines = output.strip().split('\n')
        for line in lines:
            if line.startswith("Rule "):
                parts = line.split(" matches in ")
                rule_name = parts[0].replace("Rule ", "").strip()
                file_info = parts[1] if len(parts) > 1 else "Unknown file"
                
                results.append({
                    "rule": rule_name,
                    "file": file_info,
                    "strings": []  # Would need more parsing to extract matched strings
                })
        
        return results
    
    def create_rule_from_keywords(self, 
                                 rule_name: str, 
                                 identifier_keywords: List[str] = None, 
                                 global_keywords: List[str] = None,
                                 high_confidence_keywords: List[str] = None,
                                 general_keywords: List[str] = None,
                                 required_counts: Dict[str, int] = None) -> str:
        """
        Create a YARA rule from keyword lists with custom matching logic.
        
        Args:
            rule_name: Name for the rule
            identifier_keywords: List of identifying keywords
            global_keywords: List of global keywords
            high_confidence_keywords: List of high confidence keywords
            general_keywords: List of general keywords
            required_counts: Dict specifying required matches from each category
                             e.g. {"identifier": 1, "global": 1, "general": 2}
        
        Returns:
            YARA rule as a string
        """
        # Initialize empty lists if not provided
        identifier_keywords = identifier_keywords or []
        global_keywords = global_keywords or []
        high_confidence_keywords = high_confidence_keywords or []
        general_keywords = general_keywords or []
        
        # Default required counts if not specified
        if not required_counts:
            required_counts = {
                "identifier": 1 if identifier_keywords else 0,
                "global": 1 if global_keywords else 0,
                "high_confidence": 1 if high_confidence_keywords else 0,
                "general": 2 if general_keywords else 0
            }
        
        # Start building the rule
        rule = f'rule {rule_name} {{\n'
        rule += '    meta:\n'
        rule += f'        description = "CIPHER autogenerated rule for {rule_name}"\n'
        rule += f'        author = "CIPHER CRYPT System"\n'
        rule += '        generated = "auto"\n\n'
        
        # Build strings section
        rule += '    strings:\n'
        
        # Add strings for each category
        str_id = 0
        for keyword in identifier_keywords:
            rule += f'        $id{str_id} = "{keyword}" nocase ascii wide\n'
            str_id += 1
        
        str_gl = 0
        for keyword in global_keywords:
            rule += f'        $gl{str_gl} = "{keyword}" nocase ascii wide\n'
            str_gl += 1
        
        str_hc = 0
        for keyword in high_confidence_keywords:
            rule += f'        $hc{str_hc} = "{keyword}" nocase ascii wide\n'
            str_hc += 1
        
        str_gn = 0
        for keyword in general_keywords:
            rule += f'        $gn{str_gn} = "{keyword}" nocase ascii wide\n'
            str_gn += 1
        
        # Build condition section based on required_counts
        rule += '\n    condition:\n'
        conditions = []
        
        if identifier_keywords and required_counts.get("identifier", 0) > 0:
            count = required_counts.get("identifier")
            if count >= len(identifier_keywords):
                conditions.append(f'all of ($id*)')
            else:
                conditions.append(f'{count} of ($id*)')
        
        if global_keywords and required_counts.get("global", 0) > 0:
            count = required_counts.get("global")
            if count >= len(global_keywords):
                conditions.append(f'all of ($gl*)')
            else:
                conditions.append(f'{count} of ($gl*)')
        
        if high_confidence_keywords and required_counts.get("high_confidence", 0) > 0:
            count = required_counts.get("high_confidence")
            if count >= len(high_confidence_keywords):
                conditions.append(f'all of ($hc*)')
            else:
                conditions.append(f'{count} of ($hc*)')
        
        if general_keywords and required_counts.get("general", 0) > 0:
            count = required_counts.get("general")
            if count >= len(general_keywords):
                conditions.append(f'all of ($gn*)')
            else:
                conditions.append(f'{count} of ($gn*)')
        
        # Combine conditions
        if not conditions:
            conditions = ["false"]  # No valid condition
        
        rule += '        ' + ' and '.join(conditions) + '\n'
        rule += '}\n'
        
        return rule