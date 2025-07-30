import json
import logging
from models import Finding
from app import db
from urllib.parse import urlparse

class ReconParser:
    """Parser for various recon tool outputs"""
    
    def parse_amass_output(self, filename, scan_id):
        """Parse Amass JSON output"""
        findings = []
        
        try:
            with open(filename, 'r') as f:
                for line in f:
                    line = line.strip()
                    if not line:
                        continue
                    
                    try:
                        data = json.loads(line)
                        finding = Finding(
                            scan_id=scan_id,
                            tool='amass',
                            finding_type='subdomain',
                            target=data.get('name', ''),
                            data=data,
                            severity='info'
                        )
                        db.session.add(finding)
                        findings.append(finding)
                    except json.JSONDecodeError:
                        continue
            
            db.session.commit()
            
        except Exception as e:
            logging.error(f"Error parsing Amass output: {str(e)}")
        
        return findings
    
    def parse_subfinder_output(self, output, scan_id):
        """Parse Subfinder JSON output"""
        findings = []
        
        try:
            for line in output.strip().split('\n'):
                if not line.strip():
                    continue
                
                try:
                    data = json.loads(line)
                    finding = Finding(
                        scan_id=scan_id,
                        tool='subfinder',
                        finding_type='subdomain',
                        target=data.get('host', ''),
                        data=data,
                        severity='info'
                    )
                    db.session.add(finding)
                    findings.append(finding)
                except json.JSONDecodeError:
                    # Handle plain text output
                    subdomain = line.strip()
                    if subdomain:
                        finding = Finding(
                            scan_id=scan_id,
                            tool='subfinder',
                            finding_type='subdomain',
                            target=subdomain,
                            data={'host': subdomain, 'source': 'subfinder'},
                            severity='info'
                        )
                        db.session.add(finding)
                        findings.append(finding)
            
            db.session.commit()
            
        except Exception as e:
            logging.error(f"Error parsing Subfinder output: {str(e)}")
        
        return findings
    
    def parse_httpx_output(self, output, scan_id):
        """Parse httpx JSON output"""
        findings = []
        
        try:
            for line in output.strip().split('\n'):
                if not line.strip():
                    continue
                
                try:
                    data = json.loads(line)
                    
                    # Determine severity based on status code and findings
                    severity = self._determine_http_severity(data)
                    
                    finding = Finding(
                        scan_id=scan_id,
                        tool='httpx',
                        finding_type='http_service',
                        target=data.get('url', ''),
                        data=data,
                        severity=severity
                    )
                    db.session.add(finding)
                    findings.append(finding)
                    
                except json.JSONDecodeError:
                    continue
            
            db.session.commit()
            
        except Exception as e:
            logging.error(f"Error parsing httpx output: {str(e)}")
        
        return findings
    
    def parse_nuclei_output(self, output, scan_id):
        """Parse Nuclei JSON output"""
        findings = []
        
        try:
            for line in output.strip().split('\n'):
                if not line.strip():
                    continue
                
                try:
                    data = json.loads(line)
                    
                    # Extract severity from nuclei output
                    severity = data.get('info', {}).get('severity', 'info')
                    
                    finding = Finding(
                        scan_id=scan_id,
                        tool='nuclei',
                        finding_type='vulnerability',
                        target=data.get('host', ''),
                        data=data,
                        severity=severity
                    )
                    db.session.add(finding)
                    findings.append(finding)
                    
                except json.JSONDecodeError:
                    continue
            
            db.session.commit()
            
        except Exception as e:
            logging.error(f"Error parsing Nuclei output: {str(e)}")
        
        return findings
    
    def _determine_http_severity(self, data):
        """Determine severity level for HTTP findings"""
        status_code = data.get('status_code', 0)
        title = data.get('title', '').lower()
        tech = data.get('tech', [])
        
        # High severity indicators
        if status_code in [401, 403]:
            return 'medium'  # Authentication/authorization issues
        
        if any(keyword in title for keyword in ['admin', 'login', 'dashboard', 'panel']):
            return 'medium'  # Potential admin interfaces
        
        # Check for interesting technologies
        interesting_tech = ['apache', 'nginx', 'iis', 'tomcat', 'jenkins', 'grafana']
        if any(t.lower() in str(tech).lower() for t in interesting_tech):
            return 'medium'
        
        # Default severity
        if status_code == 200:
            return 'low'
        elif status_code in [500, 502, 503]:
            return 'low'  # Server errors
        
        return 'info'
    
    def parse_custom_json(self, json_data, tool_name, scan_id):
        """Parse custom JSON input"""
        findings = []
        
        try:
            if isinstance(json_data, str):
                data = json.loads(json_data)
            else:
                data = json_data
            
            # Handle different JSON structures
            if isinstance(data, list):
                for item in data:
                    finding = self._create_finding_from_dict(item, tool_name, scan_id)
                    if finding:
                        findings.append(finding)
            elif isinstance(data, dict):
                finding = self._create_finding_from_dict(data, tool_name, scan_id)
                if finding:
                    findings.append(finding)
            
            db.session.commit()
            
        except Exception as e:
            logging.error(f"Error parsing custom JSON: {str(e)}")
        
        return findings
    
    def _create_finding_from_dict(self, data, tool_name, scan_id):
        """Create a finding from a dictionary"""
        try:
            # Extract target from various possible fields
            target = data.get('target') or data.get('host') or data.get('url') or data.get('domain') or ''
            
            # Extract finding type
            finding_type = data.get('type', 'unknown')
            
            # Extract severity
            severity = data.get('severity', 'info')
            
            finding = Finding(
                scan_id=scan_id,
                tool=tool_name,
                finding_type=finding_type,
                target=target,
                data=data,
                severity=severity
            )
            
            db.session.add(finding)
            return finding
            
        except Exception as e:
            logging.error(f"Error creating finding from dict: {str(e)}")
            return None
    
    def parse_dnsx_output(self, output, scan_id):
        """Parse dnsx JSON output"""
        findings = []
        
        try:
            for line in output.strip().split('\n'):
                if not line.strip():
                    continue
                
                try:
                    data = json.loads(line)
                    finding = Finding(
                        scan_id=scan_id,
                        tool='dnsx',
                        finding_type='dns_record',
                        target=data.get('host', ''),
                        data=data,
                        severity='info'
                    )
                    db.session.add(finding)
                    findings.append(finding)
                except json.JSONDecodeError:
                    continue
            
            db.session.commit()
            
        except Exception as e:
            logging.error(f"Error parsing dnsx output: {str(e)}")
        
        return findings
    
    def parse_waybackurls_output(self, output, scan_id):
        """Parse waybackurls text output"""
        findings = []
        
        try:
            urls = output.strip().split('\n')
            for url in urls:
                if not url.strip():
                    continue
                
                finding = Finding(
                    scan_id=scan_id,
                    tool='waybackurls',
                    finding_type='archived_url',
                    target=url.strip(),
                    data={'url': url.strip(), 'source': 'wayback_machine'},
                    severity='info'
                )
                db.session.add(finding)
                findings.append(finding)
            
            db.session.commit()
            
        except Exception as e:
            logging.error(f"Error parsing waybackurls output: {str(e)}")
        
        return findings
