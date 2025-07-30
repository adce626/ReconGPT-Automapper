import json
import os
import logging
from openai import OpenAI

class AIPrioritizer:
    """AI-powered analysis and prioritization of reconnaissance findings"""
    
    def __init__(self):
        self.openai_api_key = os.environ.get("OPENAI_API_KEY")
        if not self.openai_api_key:
            logging.warning("OpenAI API key not found in environment variables")
            self.client = None
        else:
            self.client = OpenAI(api_key=self.openai_api_key)
    
    def analyze_findings(self, findings):
        """Analyze findings and return prioritized results"""
        if not self.client:
            return self._mock_analysis(findings)
        
        try:
            # Prepare findings data for AI analysis
            findings_data = self._prepare_findings_data(findings)
            
            # Create AI analysis prompt
            analysis_prompt = self._create_analysis_prompt(findings_data)
            
            # Get AI analysis
            # the newest OpenAI model is "gpt-4o" which was released May 13, 2024.
            # do not change this unless explicitly requested by the user
            response = self.client.chat.completions.create(
                model="gpt-4o",
                messages=[
                    {
                        "role": "system",
                        "content": "You are a cybersecurity expert specializing in reconnaissance analysis and attack surface assessment. Analyze the provided reconnaissance findings and provide a comprehensive security assessment with prioritized targets."
                    },
                    {
                        "role": "user",
                        "content": analysis_prompt
                    }
                ],
                response_format={"type": "json_object"}
            )
            
            content = response.choices[0].message.content
            if content:
                result = json.loads(content)
            else:
                logging.warning("Empty response from AI")
                return self._mock_analysis(findings)
            return self._process_ai_response(result, findings)
            
        except Exception as e:
            logging.error(f"AI analysis failed: {str(e)}")
            return self._mock_analysis(findings)
    
    def _prepare_findings_data(self, findings):
        """Prepare findings data for AI analysis"""
        findings_summary = {
            'total_findings': len(findings),
            'findings_by_tool': {},
            'findings_by_severity': {},
            'findings_by_type': {},
            'sample_findings': []
        }
        
        for finding in findings:
            # Group by tool
            tool = finding.tool
            if tool not in findings_summary['findings_by_tool']:
                findings_summary['findings_by_tool'][tool] = 0
            findings_summary['findings_by_tool'][tool] += 1
            
            # Group by severity
            severity = finding.severity or 'unknown'
            if severity not in findings_summary['findings_by_severity']:
                findings_summary['findings_by_severity'][severity] = 0
            findings_summary['findings_by_severity'][severity] += 1
            
            # Group by type
            finding_type = finding.finding_type
            if finding_type not in findings_summary['findings_by_type']:
                findings_summary['findings_by_type'][finding_type] = 0
            findings_summary['findings_by_type'][finding_type] += 1
            
            # Add sample findings for AI analysis
            if len(findings_summary['sample_findings']) < 20:
                findings_summary['sample_findings'].append({
                    'tool': finding.tool,
                    'type': finding.finding_type,
                    'target': finding.target,
                    'severity': finding.severity,
                    'data': finding.get_data_dict()
                })
        
        return findings_summary
    
    def _create_analysis_prompt(self, findings_data):
        """Create AI analysis prompt"""
        prompt = f"""
        Analyze the following cybersecurity reconnaissance findings and provide a comprehensive assessment:

        FINDINGS SUMMARY:
        - Total findings: {findings_data['total_findings']}
        - Tools used: {list(findings_data['findings_by_tool'].keys())}
        - Severity distribution: {findings_data['findings_by_severity']}
        - Finding types: {findings_data['findings_by_type']}

        SAMPLE FINDINGS:
        {json.dumps(findings_data['sample_findings'], indent=2)}

        CRITICAL REQUIREMENT: Provide SPECIFIC evidence and reasoning for every assessment.
        
        Please provide your analysis in the following JSON format with detailed evidence:
        {{
            "overall_priority": 0.8,
            "confidence": 0.9,
            "evidence_summary": "3 critical vulnerabilities found: admin panel on port 8080, missing security headers, exposed API endpoints",
            "reasoning": "Detailed explanation with specific evidence from findings",
            "high_priority_targets": [
                {{
                    "target": "admin.example.com",
                    "priority_score": 0.9,
                    "evidence": "Admin panel accessible on port 8080 without authentication",
                    "specific_ports": [8080],
                    "security_headers": {{"missing": ["X-Frame-Options", "X-Content-Type-Options"]}},
                    "risk_factors": ["open admin panel", "missing security headers"],
                    "recommended_actions": ["Test default credentials on admin.example.com:8080", "Check for directory traversal"]
                }}
            ],
            "recommendations": [
                "Focus on admin interfaces found",
                "Test authentication mechanisms",
                "Scan for known vulnerabilities"
            ],
            "attack_vectors": [
                {{
                    "vector": "Admin Panel Access",
                    "likelihood": "high",
                    "impact": "high",
                    "targets": ["admin.example.com"]
                }}
            ],
            "summary": "Brief summary of key findings and recommendations"
        }}

        Consider the following factors in your analysis:
        1. Severity of vulnerabilities found
        2. Exposure of administrative interfaces
        3. Authentication and authorization weaknesses
        4. Technology stack vulnerabilities
        5. Information disclosure risks
        6. Potential for lateral movement
        """
        
        return prompt
    
    def _process_ai_response(self, ai_result, findings):
        """Process and validate AI response"""
        try:
            # Ensure required fields exist
            processed_result = {
                'overall_priority': ai_result.get('overall_priority', 0.5),
                'confidence': ai_result.get('confidence', 0.5),
                'reasoning': ai_result.get('reasoning', 'AI analysis completed'),
                'recommendations': ai_result.get('recommendations', []),
                'high_priority_targets': ai_result.get('high_priority_targets', []),
                'attack_vectors': ai_result.get('attack_vectors', []),
                'summary': ai_result.get('summary', 'Analysis completed')
            }
            
            # Validate and clamp numeric values
            processed_result['overall_priority'] = max(0.0, min(1.0, processed_result['overall_priority']))
            processed_result['confidence'] = max(0.0, min(1.0, processed_result['confidence']))
            
            return processed_result
            
        except Exception as e:
            logging.error(f"Error processing AI response: {str(e)}")
            return self._mock_analysis(findings)
    
    def _mock_analysis(self, findings):
        """Enhanced heuristic analysis when AI is not available with detailed evidence"""
        logging.info("Using enhanced heuristic analysis (OpenAI API not available)")
        
        # Detailed analysis counters
        high_severity_count = sum(1 for f in findings if f.severity in ['high', 'critical'])
        medium_severity_count = sum(1 for f in findings if f.severity == 'medium')
        unusual_ports = []
        admin_interfaces = []
        api_endpoints = []
        
        # Analyze findings for specific patterns
        for finding in findings:
            # Check for unusual ports
            if hasattr(finding, 'data') and finding.data:
                if isinstance(finding.data, dict) and 'port' in finding.data:
                    port = finding.data['port']
                    if port not in [80, 443, 22, 21, 25, 53, 110, 143, 993, 995]:
                        unusual_ports.append((finding.target, port))
            
            # Check for admin interfaces
            if any(keyword in finding.target.lower() for keyword in ['admin', 'dev', 'test', 'staging', 'internal']):
                admin_interfaces.append(finding.target)
            
            # Check for API endpoints
            if 'api' in finding.target.lower() or finding.finding_type == 'api_endpoint':
                api_endpoints.append(finding.target)
        
        # Calculate enhanced priority score
        total_findings = len(findings)
        if total_findings == 0:
            priority_score = 0.0
        else:
            base_score = (high_severity_count * 0.8 + medium_severity_count * 0.4) / total_findings
            bonus_score = 0.0
            if unusual_ports:
                bonus_score += 0.2
            if admin_interfaces:
                bonus_score += 0.3
            if api_endpoints:
                bonus_score += 0.1
            priority_score = min(1.0, base_score + bonus_score)
        
        # Identify potential high-priority targets
        high_priority_targets = []
        for finding in findings:
            if finding.severity in ['high', 'critical']:
                high_priority_targets.append({
                    'target': finding.target,
                    'priority_score': 0.8 if finding.severity == 'high' else 0.9,
                    'risk_factors': [f"{finding.tool} identified {finding.finding_type}"],
                    'recommended_actions': [f"Investigate {finding.finding_type} on {finding.target}"]
                })
        
        # Generate evidence-based recommendations
        evidence_summary = []
        if unusual_ports:
            evidence_summary.append(f"{len(unusual_ports)} unusual ports detected: {', '.join([str(p[1]) for p in unusual_ports[:5]])}")
        if admin_interfaces:
            evidence_summary.append(f"{len(admin_interfaces)} admin/dev interfaces found")
        if api_endpoints:
            evidence_summary.append(f"{len(api_endpoints)} API endpoints discovered")
        
        # Create detailed high-priority targets with evidence
        enhanced_high_priority_targets = []
        for finding in findings:
            if finding.severity in ['high', 'critical'] or finding.target in admin_interfaces:
                evidence = []
                if finding.target in admin_interfaces:
                    evidence.append("Contains admin/dev/test keywords")
                if hasattr(finding, 'data') and finding.data and isinstance(finding.data, dict):
                    if 'port' in finding.data and finding.data['port'] not in [80, 443]:
                        evidence.append(f"Unusual port: {finding.data['port']}")
                
                enhanced_high_priority_targets.append({
                    'target': finding.target,
                    'priority_score': 0.9 if finding.severity == 'critical' else 0.8,
                    'evidence': '; '.join(evidence) if evidence else f"{finding.tool} identified {finding.finding_type}",
                    'risk_factors': [finding.finding_type, finding.severity or 'unknown'],
                    'recommended_actions': [f"Manual verification of {finding.finding_type}", f"Security testing on {finding.target}"]
                })
        
        recommendations = [
            f"Review {high_severity_count} high-severity findings",
            f"Investigate {medium_severity_count} medium-severity findings",
            "Prioritize targets with multiple vulnerabilities",
            "Validate findings with manual testing"
        ]
        
        return {
            'overall_priority': min(priority_score, 1.0),
            'confidence': 0.6,  # Lower confidence for heuristic analysis
            'reasoning': f"Heuristic analysis based on {total_findings} findings. "
                        f"{high_severity_count} high-severity and {medium_severity_count} medium-severity issues identified.",
            'recommendations': recommendations,
            'high_priority_targets': high_priority_targets[:10],  # Limit to top 10
            'attack_vectors': [
                {
                    'vector': 'High-Severity Vulnerabilities',
                    'likelihood': 'medium',
                    'impact': 'high',
                    'targets': [t['target'] for t in high_priority_targets[:5]]
                }
            ],
            'summary': f"Analysis of {total_findings} reconnaissance findings completed. "
                      f"Focus on {high_severity_count} high-severity issues for immediate attention."
        }
    
    def generate_recommendations(self, findings, target_domain):
        """Generate specific recommendations for a target"""
        if not self.client:
            return self._mock_recommendations(findings, target_domain)
        
        try:
            prompt = f"""
            Based on the reconnaissance findings for {target_domain}, provide specific 
            actionable recommendations for security testing and vulnerability assessment.
            
            Findings: {json.dumps([{
                'tool': f.tool,
                'type': f.finding_type,
                'target': f.target,
                'severity': f.severity
            } for f in findings[:10]], indent=2)}
            
            Provide recommendations in JSON format:
            {{
                "immediate_actions": ["action1", "action2"],
                "tools_to_use": ["tool1", "tool2"],
                "attack_scenarios": ["scenario1", "scenario2"],
                "risk_assessment": "high/medium/low"
            }}
            """
            
            # the newest OpenAI model is "gpt-4o" which was released May 13, 2024.
            # do not change this unless explicitly requested by the user
            response = self.client.chat.completions.create(
                model="gpt-4o",
                messages=[
                    {"role": "system", "content": "You are a penetration testing expert providing actionable security recommendations."},
                    {"role": "user", "content": prompt}
                ],
                response_format={"type": "json_object"}
            )
            
            content = response.choices[0].message.content
            if content:
                return json.loads(content)
            else:
                logging.warning("Empty response from AI for recommendations")
                return self._mock_recommendations(findings, target_domain)
            
        except Exception as e:
            logging.error(f"Failed to generate recommendations: {str(e)}")
            return self._mock_recommendations(findings, target_domain)
    
    def _mock_recommendations(self, findings, target_domain):
        """Generate mock recommendations"""
        return {
            "immediate_actions": [
                f"Manually verify findings for {target_domain}",
                "Test for default credentials on discovered services",
                "Check for information disclosure vulnerabilities"
            ],
            "tools_to_use": [
                "Nmap for port scanning",
                "Burp Suite for web application testing",
                "Custom scripts for specific vulnerabilities"
            ],
            "attack_scenarios": [
                "Subdomain takeover attempts",
                "Authentication bypass testing",
                "Information gathering from exposed services"
            ],
            "risk_assessment": "medium"
        }
