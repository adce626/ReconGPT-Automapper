import subprocess
import json
import logging
import tempfile
import os
from parsers import ReconParser
from models import Finding
from app import db

class ReconEngine:
    """Engine for running reconnaissance tools and collecting results"""
    
    def __init__(self):
        self.parser = ReconParser()
        self.supported_tools = {
            'amass': self._run_amass,
            'subfinder': self._run_subfinder,
            'httpx': self._run_httpx,
            'nuclei': self._run_nuclei
        }
    
    def run_scan(self, target, tools, scan_id):
        """Run reconnaissance scan with specified tools"""
        all_findings = []
        
        logging.info(f"Starting recon scan for target: {target}")
        
        for tool in tools:
            if tool in self.supported_tools:
                try:
                    logging.info(f"Running {tool} for target: {target}")
                    findings = self.supported_tools[tool](target, scan_id)
                    all_findings.extend(findings)
                    logging.info(f"{tool} completed with {len(findings)} findings")
                except Exception as e:
                    logging.error(f"Error running {tool}: {str(e)}")
                    continue
            else:
                logging.warning(f"Unsupported tool: {tool}")
        
        return all_findings
    
    def _run_amass(self, target, scan_id):
        """Run Amass subdomain enumeration"""
        findings = []
        
        try:
            # Create temporary output file
            with tempfile.NamedTemporaryFile(mode='w+', suffix='.json', delete=False) as temp_file:
                temp_filename = temp_file.name
            
            # Run amass command
            cmd = [
                'amass', 'enum', 
                '-d', target,
                '-json',
                '-o', temp_filename
            ]
            
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=300)
            
            if result.returncode == 0:
                # Parse results
                findings = self.parser.parse_amass_output(temp_filename, scan_id)
            else:
                logging.error(f"Amass failed: {result.stderr}")
                # Create mock finding to show tool was attempted
                findings = [self._create_error_finding('amass', target, scan_id, result.stderr)]
            
            # Clean up temp file
            if os.path.exists(temp_filename):
                os.unlink(temp_filename)
                
        except subprocess.TimeoutExpired:
            logging.error("Amass timed out")
            findings = [self._create_error_finding('amass', target, scan_id, "Tool timed out")]
        except FileNotFoundError:
            logging.error("Amass not found in PATH")
            findings = [self._create_mock_finding('amass', 'subdomain', target, scan_id)]
        except Exception as e:
            logging.error(f"Amass execution failed: {str(e)}")
            findings = [self._create_mock_finding('amass', 'subdomain', target, scan_id)]
        
        return findings
    
    def _run_subfinder(self, target, scan_id):
        """Run Subfinder subdomain enumeration"""
        findings = []
        
        try:
            # Run subfinder command
            cmd = ['subfinder', '-d', target, '-json']
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=300)
            
            if result.returncode == 0:
                findings = self.parser.parse_subfinder_output(result.stdout, scan_id)
            else:
                logging.error(f"Subfinder failed: {result.stderr}")
                findings = [self._create_error_finding('subfinder', target, scan_id, result.stderr)]
                
        except subprocess.TimeoutExpired:
            logging.error("Subfinder timed out")
            findings = [self._create_error_finding('subfinder', target, scan_id, "Tool timed out")]
        except FileNotFoundError:
            logging.error("Subfinder not found in PATH")
            findings = [self._create_mock_finding('subfinder', 'subdomain', target, scan_id)]
        except Exception as e:
            logging.error(f"Subfinder execution failed: {str(e)}")
            findings = [self._create_mock_finding('subfinder', 'subdomain', target, scan_id)]
        
        return findings
    
    def _run_httpx(self, target, scan_id):
        """Run httpx for HTTP probing"""
        findings = []
        
        try:
            # Run httpx command
            cmd = [
                'httpx', 
                '-u', target,
                '-json',
                '-status-code',
                '-tech-detect',
                '-title'
            ]
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=300)
            
            if result.returncode == 0:
                findings = self.parser.parse_httpx_output(result.stdout, scan_id)
            else:
                logging.error(f"httpx failed: {result.stderr}")
                findings = [self._create_error_finding('httpx', target, scan_id, result.stderr)]
                
        except subprocess.TimeoutExpired:
            logging.error("httpx timed out")
            findings = [self._create_error_finding('httpx', target, scan_id, "Tool timed out")]
        except FileNotFoundError:
            logging.error("httpx not found in PATH")
            findings = [self._create_mock_finding('httpx', 'http_service', target, scan_id)]
        except Exception as e:
            logging.error(f"httpx execution failed: {str(e)}")
            findings = [self._create_mock_finding('httpx', 'http_service', target, scan_id)]
        
        return findings
    
    def _run_nuclei(self, target, scan_id):
        """Run Nuclei vulnerability scanner"""
        findings = []
        
        try:
            # Run nuclei command
            cmd = [
                'nuclei',
                '-u', target,
                '-json',
                '-severity', 'low,medium,high,critical'
            ]
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=600)
            
            if result.returncode == 0:
                findings = self.parser.parse_nuclei_output(result.stdout, scan_id)
            else:
                logging.error(f"Nuclei failed: {result.stderr}")
                findings = [self._create_error_finding('nuclei', target, scan_id, result.stderr)]
                
        except subprocess.TimeoutExpired:
            logging.error("Nuclei timed out")
            findings = [self._create_error_finding('nuclei', target, scan_id, "Tool timed out")]
        except FileNotFoundError:
            logging.error("Nuclei not found in PATH")
            findings = [self._create_mock_finding('nuclei', 'vulnerability', target, scan_id)]
        except Exception as e:
            logging.error(f"Nuclei execution failed: {str(e)}")
            findings = [self._create_mock_finding('nuclei', 'vulnerability', target, scan_id)]
        
        return findings
    
    def _create_error_finding(self, tool, target, scan_id, error_msg):
        """Create an error finding when tool execution fails"""
        finding = Finding(
            scan_id=scan_id,
            tool=tool,
            finding_type='error',
            target=target,
            data={'error': error_msg, 'status': 'failed'},
            severity='low'
        )
        db.session.add(finding)
        db.session.commit()
        return finding
    
    def _create_mock_finding(self, tool, finding_type, target, scan_id):
        """Create a mock finding when tool is not available"""
        mock_data = {
            'status': 'tool_not_available',
            'message': f'{tool} is not installed or not in PATH',
            'target': target,
            'simulated': True
        }
        
        finding = Finding(
            scan_id=scan_id,
            tool=tool,
            finding_type=finding_type,
            target=target,
            data=mock_data,
            severity='info'
        )
        db.session.add(finding)
        db.session.commit()
        return finding
    
    def get_available_tools(self):
        """Check which tools are available in the system"""
        available = {}
        for tool in self.supported_tools.keys():
            try:
                result = subprocess.run([tool, '--help'], 
                                      capture_output=True, 
                                      timeout=10)
                available[tool] = result.returncode == 0
            except (FileNotFoundError, subprocess.TimeoutExpired):
                available[tool] = False
        
        return available
