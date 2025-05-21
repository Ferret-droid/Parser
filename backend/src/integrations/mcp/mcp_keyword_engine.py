import json
import logging
import os
import re
import subprocess
import tempfile
from datetime import datetime
from typing import Dict, List, Any, Optional, Tuple
from enum import Enum

class KeywordCategory(str, Enum):
    IDENTIFIER = "identifier"
    HIGH_CONFIDENCE = "high_confidence"
    GENERAL = "general"

class SensitivityLevel(str, Enum):
    GENERAL = "general"
    INTERNAL = "internal"
    CONFIDENTIAL = "confidential"
    SENSITIVE = "sensitive"

class KeywordMCPEngine:
    """
    Wrapper for MCP integration with keyword guardrails system.
    This service enables testing of CIPHER keyword detection rules.
    """
    
    def __init__(self, mcp_server_script: str = None):
        """
        Initialize keyword MCP engine.
        
        Args:
            mcp_server_script: Path to MCP server script
        """
        self.logger = logging.getLogger(__name__)
        
        # Get path to MCP server script
        if not mcp_server_script:
            base_dir = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
            self.mcp_server_script = os.path.join(base_dir, "integrations", "mcp", "keyword_guardrail_server.py")
        else:
            self.mcp_server_script = mcp_server_script
        
        # Check if script exists
        if not os.path.exists(self.mcp_server_script):
            self.logger.warning(f"MCP server script not found at {self.mcp_server_script}")
            
        # MCP server process
        self.mcp_process = None
    
    def start_server(self) -> bool:
        """
        Start the MCP server process.
        
        Returns:
            True if server started successfully
        """
        if self.mcp_process and self.mcp_process.poll() is None:
            # Server already running
            return True
        
        try:
            # Start MCP server as subprocess
            self.mcp_process = subprocess.Popen(
                ["python", self.mcp_server_script],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE
            )
            
            # Wait a bit for server to start
            import time
            time.sleep(1)
            
            # Check if process is still running
            if self.mcp_process.poll() is None:
                self.logger.info("MCP server started successfully")
                return True
            else:
                stdout, stderr = self.mcp_process.communicate()
                self.logger.error(f"Failed to start MCP server: {stderr.decode()}")
                return False
        
        except Exception as e:
            self.logger.error(f"Error starting MCP server: {str(e)}")
            return False
    
    def stop_server(self):
        """Stop the MCP server process."""
        if self.mcp_process and self.mcp_process.poll() is None:
            self.mcp_process.terminate()
            try:
                self.mcp_process.wait(timeout=5)
                self.logger.info("MCP server stopped")
            except subprocess.TimeoutExpired:
                self.mcp_process.kill()
                self.logger.warning("MCP server killed forcefully")
    
    def analyze_text(self, 
                   text: str, 
                   user_id: str, 
                   user_roles: List[str] = None,
                   context: str = None) -> Dict[str, Any]:
        """
        Analyze text using the keyword MCP engine.
        
        Args:
            text: Text content to analyze
            user_id: User ID
            user_roles: List of user roles
            context: Context for analysis
            
        Returns:
            Analysis results
        """
        # Ensure server is running
        if not self.start_server():
            raise RuntimeError("MCP server not running")
        
        # Create temporary file for input
        fd, input_path = tempfile.mkstemp(suffix='.json')
        try:
            # Prepare input data
            input_data = {
                "text": text,
                "user_id": user_id,
                "user_roles": user_roles or ["employee"],
                "context": context or "keyword_analysis"
            }
            
            # Write input to file
            with os.fdopen(fd, 'w') as f:
                json.dump(input_data, f)
            
            # Call MCP server
            result = subprocess.check_output([
                "python", "-c", 
                f"from mcp.service.client import Client; "
                f"client = Client('http://localhost:8000'); "
                f"result = client.tool('analyze_keyword_sensitivity', open('{input_path}').read()); "
                f"print(result)"
            ]).decode()
            
            # Parse result
            result_dict = json.loads(result)
            
            return result_dict
            
        except Exception as e:
            self.logger.error(f"Error analyzing text with MCP: {str(e)}")
            raise
        finally:
            # Clean up temporary file
            if os.path.exists(input_path):
                os.unlink(input_path)
    
    def check_permissions(self, 
                        user_id: str, 
                        sensitivity_level: SensitivityLevel,
                        user_roles: List[str] = None) -> Dict[str, Any]:
        """
        Check user permissions for accessing content.
        
        Args:
            user_id: User ID
            sensitivity_level: Content sensitivity level
            user_roles: List of user roles
            
        Returns:
            Permission check results
        """
        # Ensure server is running
        if not self.start_server():
            raise RuntimeError("MCP server not running")
        
        # Create temporary file for input
        fd, input_path = tempfile.mkstemp(suffix='.json')
        try:
            # Prepare input data
            input_data = {
                "user_id": user_id,
                "sensitivity_level": sensitivity_level,
                "user_roles": user_roles or ["employee"]
            }
            
            # Write input to file
            with os.fdopen(fd, 'w') as f:
                json.dump(input_data, f)
            
            # Call MCP server
            result = subprocess.check_output([
                "python", "-c", 
                f"from mcp.service.client import Client; "
                f"client = Client('http://localhost:8000'); "
                f"result = client.tool('check_keyword_permissions', open('{input_path}').read()); "
                f"print(result)"
            ]).decode()
            
            # Parse result
            result_dict = json.loads(result)
            
            return result_dict
            
        except Exception as e:
            self.logger.error(f"Error checking permissions with MCP: {str(e)}")
            raise
        finally:
            # Clean up temporary file
            if os.path.exists(input_path):
                os.unlink(input_path)
    
    def simulate_scenario(self, scenario_name: str) -> Dict[str, Any]:
        """
        Simulate a keyword analysis scenario.
        
        Args:
            scenario_name: Name of the scenario to simulate
            
        Returns:
            Simulation results
        """
        # Ensure server is running
        if not self.start_server():
            raise RuntimeError("MCP server not running")
        
        try:
            # Call MCP server
            result = subprocess.check_output([
                "python", "-c", 
                f"from mcp.service.client import Client; "
                f"client = Client('http://localhost:8000'); "
                f"result = client.tool('simulate_keyword_scenario', '{scenario_name}'); "
                f"print(result)"
            ]).decode()
            
            # Parse result
            result_dict = json.loads(result)
            
            return result_dict
            
        except Exception as e:
            self.logger.error(f"Error simulating scenario with MCP: {str(e)}")
            raise
    
    def get_keyword_categories(self) -> Dict[str, Any]:
        """
        Get keyword categories configuration.
        
        Returns:
            Keyword categories configuration
        """
        # Ensure server is running
        if not self.start_server():
            raise RuntimeError("MCP server not running")
        
        try:
            # Call MCP server
            result = subprocess.check_output([
                "python", "-c", 
                f"from mcp.service.client import Client; "
                f"client = Client('http://localhost:8000'); "
                f"result = client.resource('keywords://categories'); "
                f"print(result)"
            ]).decode()
            
            # Parse result
            result_dict = json.loads(result)
            
            return result_dict
            
        except Exception as e:
            self.logger.error(f"Error getting keyword categories from MCP: {str(e)}")
            raise
    
    def get_permission_matrix(self) -> Dict[str, Any]:
        """
        Get permission matrix configuration.
        
        Returns:
            Permission matrix configuration
        """
        # Ensure server is running
        if not self.start_server():
            raise RuntimeError("MCP server not running")
        
        try:
            # Call MCP server
            result = subprocess.check_output([
                "python", "-c", 
                f"from mcp.service.client import Client; "
                f"client = Client('http://localhost:8000'); "
                f"result = client.resource('keywords://permissions'); "
                f"print(result)"
            ]).decode()
            
            # Parse result
            result_dict = json.loads(result)
            
            return result_dict
            
        except Exception as e:
            self.logger.error(f"Error getting permission matrix from MCP: {str(e)}")
            raise
    
    def get_keyword_audit_logs(self) -> List[Dict[str, Any]]:
        """
        Get keyword analysis audit logs.
        
        Returns:
            Recent audit logs
        """
        # Ensure server is running
        if not self.start_server():
            raise RuntimeError("MCP server not running")
        
        try:
            # Call MCP server
            result = subprocess.check_output([
                "python", "-c", 
                f"from mcp.service.client import Client; "
                f"client = Client('http://localhost:8000'); "
                f"result = client.resource('audit://keyword-logs'); "
                f"print(result)"
            ]).decode()
            
            # Parse result
            result_dict = json.loads(result)
            
            return result_dict
            
        except Exception as e:
            self.logger.error(f"Error getting audit logs from MCP: {str(e)}")
            raise
    
    def get_blocked_attempts(self) -> List[Dict[str, Any]]:
        """
        Get blocked access attempts.
        
        Returns:
            Blocked access attempt logs
        """
        # Ensure server is running
        if not self.start_server():
            raise RuntimeError("MCP server not running")
        
        try:
            # Call MCP server
            result = subprocess.check_output([
                "python", "-c", 
                f"from mcp.service.client import Client; "
                f"client = Client('http://localhost:8000'); "
                f"result = client.resource('audit://blocked-attempts'); "
                f"print(result)"
            ]).decode()
            
            # Parse result
            result_dict = json.loads(result)
            
            return result_dict
            
        except Exception as e:
            self.logger.error(f"Error getting blocked attempts from MCP: {str(e)}")
            raise
    
    def get_sensitive_access_logs(self) -> List[Dict[str, Any]]:
        """
        Get sensitive access logs.
        
        Returns:
            Sensitive access logs
        """
        # Ensure server is running
        if not self.start_server():
            raise RuntimeError("MCP server not running")
        
        try:
            # Call MCP server
            result = subprocess.check_output([
                "python", "-c", 
                f"from mcp.service.client import Client; "
                f"client = Client('http://localhost:8000'); "
                f"result = client.resource('audit://sensitive-access'); "
                f"print(result)"
            ]).decode()
            
            # Parse result
            result_dict = json.loads(result)
            
            return result_dict
            
        except Exception as e:
            self.logger.error(f"Error getting sensitive access logs from MCP: {str(e)}")
            raise
    
    def get_keyword_statistics(self) -> Dict[str, Any]:
        """
        Get keyword analysis statistics.
        
        Returns:
            Keyword analysis statistics
        """
        # Ensure server is running
        if not self.start_server():
            raise RuntimeError("MCP server not running")
        
        try:
            # Call MCP server
            result = subprocess.check_output([
                "python", "-c", 
                f"from mcp.service.client import Client; "
                f"client = Client('http://localhost:8000'); "
                f"result = client.tool('keyword_statistics'); "
                f"print(result)"
            ]).decode()
            
            # Parse result
            result_dict = json.loads(result)
            
            return result_dict
            
        except Exception as e:
            self.logger.error(f"Error getting keyword statistics from MCP: {str(e)}")
            raise