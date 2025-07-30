import re
import json
import logging
from typing import Dict, List, Any

class DataSanitizer:
    """Sanitize sensitive data from reconnaissance outputs for safe sharing"""
    
    def __init__(self):
        # Patterns for sensitive data detection
        self.sensitive_patterns = {
            'api_keys': [
                r'[aA][pP][iI][_-]?[kK][eE][yY]\s*[:=]\s*["\']?([a-zA-Z0-9_-]{20,})["\']?',
                r'[sS][eE][cC][rR][eE][tT]\s*[:=]\s*["\']?([a-zA-Z0-9_-]{20,})["\']?',
                r'[tT][oO][kK][eE][nN]\s*[:=]\s*["\']?([a-zA-Z0-9_.-]{20,})["\']?'
            ],
            'credentials': [
                r'[pP][aA][sS][sS][wW][oO][rR][dD]\s*[:=]\s*["\']?([^"\'\s]{4,})["\']?',
                r'[uU][sS][eE][rR]\s*[:=]\s*["\']?([^"\'\s]{3,})["\']?',
                r'[lL][oO][gG][iI][nN]\s*[:=]\s*["\']?([^"\'\s]{3,})["\']?'
            ],
            'internal_ips': [
                r'\b10\.(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b',
                r'\b172\.(?:1[6-9]|2[0-9]|3[01])\.(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b',
                r'\b192\.168\.(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b'
            ],
            'session_tokens': [
                r'[sS][eE][sS][sS][iI][oO][nN]\s*[:=]\s*["\']?([a-zA-Z0-9+/=]{32,})["\']?',
                r'[jJ][sS][eE][sS][sS][iI][oO][nN][iI][dD]\s*[:=]\s*["\']?([a-zA-Z0-9]{20,})["\']?'
            ],
            'emails': [
                r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b'
            ]
        }
        
        # Replacement patterns for sanitization
        self.replacements = {
            'api_keys': '[API_KEY_REDACTED]',
            'credentials': '[CREDENTIAL_REDACTED]',
            'internal_ips': '[INTERNAL_IP_REDACTED]',
            'session_tokens': '[SESSION_TOKEN_REDACTED]',
            'emails': '[EMAIL_REDACTED]'
        }
    
    def sanitize_findings(self, findings: List[Any], sanitize_enabled: bool = True) -> tuple[List[Any], List[str]]:
        """Sanitize findings and return warnings about sensitive data found"""
        if not sanitize_enabled:
            return findings, []
        
        warnings = []
        sanitized_findings = []
        
        for finding in findings:
            sanitized_finding, finding_warnings = self._sanitize_finding(finding)
            sanitized_findings.append(sanitized_finding)
            warnings.extend(finding_warnings)
        
        return sanitized_findings, list(set(warnings))  # Remove duplicates
    
    def sanitize_json_output(self, data: Dict[str, Any], sanitize_enabled: bool = True) -> tuple[Dict[str, Any], List[str]]:
        """Sanitize JSON output for safe sharing"""
        if not sanitize_enabled:
            return data, []
        
        warnings = []
        sanitized_data = self._deep_sanitize_dict(data.copy(), warnings)
        
        return sanitized_data, list(set(warnings))
    
    def _sanitize_finding(self, finding: Any) -> tuple[Any, List[str]]:
        """Sanitize a single finding object"""
        warnings = []
        
        # Sanitize target
        original_target = finding.target
        sanitized_target, target_warnings = self._sanitize_text(original_target)
        finding.target = sanitized_target
        warnings.extend(target_warnings)
        
        # Sanitize data dictionary
        if hasattr(finding, 'data') and finding.data:
            original_data = finding.data.copy() if isinstance(finding.data, dict) else finding.data
            sanitized_data, data_warnings = self._sanitize_text(json.dumps(original_data))
            try:
                finding.data = json.loads(sanitized_data)
            except json.JSONDecodeError:
                finding.data = {'sanitized': True, 'original_type': type(original_data).__name__}
                warnings.append("Complex data structure sanitized")
            warnings.extend(data_warnings)
        
        return finding, warnings
    
    def _deep_sanitize_dict(self, data: Dict[str, Any], warnings: List[str]) -> Dict[str, Any]:
        """Recursively sanitize dictionary data"""
        if isinstance(data, dict):
            for key, value in data.items():
                if isinstance(value, (dict, list)):
                    data[key] = self._deep_sanitize_dict(value, warnings)
                elif isinstance(value, str):
                    sanitized_value, value_warnings = self._sanitize_text(value)
                    data[key] = sanitized_value
                    warnings.extend(value_warnings)
        elif isinstance(data, list):
            for i, item in enumerate(data):
                if isinstance(item, (dict, list)):
                    data[i] = self._deep_sanitize_dict(item, warnings)
                elif isinstance(item, str):
                    sanitized_item, item_warnings = self._sanitize_text(item)
                    data[i] = sanitized_item
                    warnings.extend(item_warnings)
        
        return data
    
    def _sanitize_text(self, text: str) -> tuple[str, List[str]]:
        """Sanitize text content and return warnings"""
        if not isinstance(text, str):
            return str(text), []
        
        sanitized_text = text
        warnings = []
        
        for category, patterns in self.sensitive_patterns.items():
            for pattern in patterns:
                if re.search(pattern, sanitized_text, re.IGNORECASE):
                    sanitized_text = re.sub(pattern, self.replacements[category], sanitized_text, flags=re.IGNORECASE)
                    warnings.append(f"Sensitive {category.replace('_', ' ')} detected and redacted")
        
        return sanitized_text, warnings
    
    def create_sanitization_report(self, warnings: List[str]) -> Dict[str, Any]:
        """Create a report of sanitization actions performed"""
        if not warnings:
            return {'sanitization_performed': False, 'warnings': []}
        
        warning_counts = {}
        for warning in warnings:
            warning_counts[warning] = warning_counts.get(warning, 0) + 1
        
        return {
            'sanitization_performed': True,
            'total_redactions': len(warnings),
            'redaction_types': warning_counts,
            'security_notice': 'Sensitive data has been automatically redacted for security. Original data remains in local scan files.',
            'recommendations': [
                'Review original scan files locally for complete data',
                'Ensure secure handling of original reconnaissance data',
                'Consider additional data classification before sharing results'
            ]
        }

# Global sanitizer instance
sanitizer = DataSanitizer()