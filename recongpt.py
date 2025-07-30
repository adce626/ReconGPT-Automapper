#!/usr/bin/env python3
"""
ReconGPT Automapper - AI-Powered Cybersecurity Reconnaissance Tool
Professional CLI tool for reconnaissance and attack surface analysis
"""

import click
import json
import os
import sys
import sqlite3
import re
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.progress import Progress, SpinnerColumn, TextColumn
from rich.syntax import Syntax
from rich.tree import Tree
from rich.columns import Columns
from datetime import datetime
import logging

# Setup logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

# Add the current directory to Python path for imports
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

try:
    from app import app, db
    from models import ReconScan, Finding, AIAnalysis
    from recon_engine import ReconEngine
    from ai_prioritizer import AIPrioritizer
    from graph_builder import GraphBuilder
except ImportError as e:
    logger.error(f"Import error: {e}")
    logger.error("Make sure you're running from the correct directory with dependencies installed")
    sys.exit(1)

console = Console()

def init_database():
    """Initialize database for CLI operations"""
    try:
        with app.app_context():
            db.create_all()
        return True
    except Exception as e:
        logger.error(f"Database initialization failed: {e}")
        return False

@click.group()
@click.version_option(version='1.0.0')
def main():
    """
    ReconGPT Automapper - The Smart Tool for Reconnaissance and Attack Surface Analysis
    
    Professional CLI tool that combines traditional reconnaissance with AI analysis
    to identify high-priority attack vectors and create intelligent attack surface maps.
    """
    if not init_database():
        console.print("[red]Failed to initialize database. Exiting.[/red]")
        sys.exit(1)
    
    # Initialize Flask app context for CLI operations
    app.app_context().push()

@main.command()
@click.argument('domain')
@click.option('--tools', '-t', multiple=True, 
              default=['amass', 'subfinder', 'httpx', 'nuclei', 'dnsx', 'waybackurls'],
              help='Recon tools to use (amass, subfinder, httpx, nuclei, dnsx, waybackurls)')
@click.option('--output', '-o', help='Output directory for results')
@click.option('--format', '-f', 
              type=click.Choice(['json', 'html']), 
              default='json',
              help='Output format (json for integration, html for reports)')
@click.option('--analyze/--no-analyze', default=True,
              help='Run AI analysis (default: enabled)')
@click.option('--ai-review-only', is_flag=True,
              help='Run AI analysis for review only, don\'t apply results automatically')
@click.option('--filter', 'filter_expr', 
              help='Filter results (e.g., "port!=443 && domain~=\'dev|admin\'")')
@click.option('--show-graphs/--no-graphs', default=False,
              help='Generate optional graphs (disabled by default)')
@click.option('--verbose', '-v', is_flag=True, help='Verbose output')
def scan(domain, tools, output, format, analyze, ai_review_only, filter_expr, show_graphs, verbose):
    """
    Run comprehensive reconnaissance scan on target domain
    
    Example: python recongpt.py scan target.com
    """
    
    if verbose:
        logging.getLogger().setLevel(logging.DEBUG)
    
    # Display tool banner
    ai_mode = "Review Only" if ai_review_only else ("Enabled" if analyze else "Disabled")
    console.print(Panel.fit(
        f"[bold blue]ReconGPT Automapper[/bold blue]\n"
        f"[white]Target: {domain}[/white]\n"
        f"[white]Tools: {', '.join(tools)}[/white]\n"
        f"[white]AI Analysis: {ai_mode}[/white]\n"
        f"[white]Filter: {filter_expr or 'None'}[/white]\n"
        f"[white]Graphs: {'Enabled' if show_graphs else 'Disabled'}[/white]",
        border_style="blue"
    ))
    
    # Create output directory if specified
    if output:
        os.makedirs(output, exist_ok=True)
        console.print(f"[green]Output directory: {output}[/green]")
    
    # Create scan record
    scan_name = f"ReconGPT Scan - {domain} - {datetime.now().strftime('%Y%m%d_%H%M%S')}"
    scan_record = ReconScan(name=scan_name, target=domain, status='running')
    db.session.add(scan_record)
    db.session.commit()
    
    findings = []
    
    # Initialize recon engine
    recon_engine = ReconEngine()
    
    # Check available tools
    available_tools = recon_engine.get_available_tools()
    unavailable_tools = [tool for tool in tools if not available_tools.get(tool, False)]
    
    if unavailable_tools:
        console.print(f"[yellow]Warning: {', '.join(unavailable_tools)} not available - will simulate results[/yellow]")
    
    # Run reconnaissance scan
    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        console=console
    ) as progress:
        
        scan_task = progress.add_task("Running reconnaissance scan...", total=None)
        
        try:
            scan_findings = recon_engine.run_scan(domain, tools, scan_record.id)
            findings.extend(scan_findings)
            
            scan_record.status = 'completed'
            scan_record.findings_count = len(findings)
            db.session.commit()
            
            progress.update(scan_task, description=f"Scan completed - {len(findings)} findings discovered")
            
        except Exception as e:
            logger.error(f"Scan failed: {e}")
            scan_record.status = 'failed'
            db.session.commit()
            console.print(f"[red]Scan failed: {e}[/red]")
            return
    
    # Apply filtering if specified
    if filter_expr:
        console.print(f"\n[yellow]Applying filter: {filter_expr}[/yellow]")
        filtered_findings = apply_filter(findings, filter_expr)
        console.print(f"[green]Filtered from {len(findings)} to {len(filtered_findings)} findings[/green]")
        findings = filtered_findings
    
    # Display initial results
    display_scan_summary(findings, domain)
    
    # Run AI analysis if enabled
    analysis_result = None
    if analyze and findings:
        console.print("\n[bold yellow]Running AI analysis...[/bold yellow]")
        
        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            console=console
        ) as progress:
            
            ai_task = progress.add_task("Analyzing findings with AI...", total=None)
            
            try:
                ai_prioritizer = AIPrioritizer()
                analysis_result = ai_prioritizer.analyze_findings(findings)
                
                # Enhanced AI analysis with SSRF/auth linking
                analysis_result = enhance_analysis_with_linking(analysis_result, findings)
                
                # Store analysis results only if not review-only mode
                if not ai_review_only:
                    analysis = AIAnalysis(
                        scan_id=scan_record.id,
                        analysis_type='prioritization',
                        priority_score=analysis_result.get('overall_priority', 0.5),
                        confidence=analysis_result.get('confidence', 0.5),
                        reasoning=analysis_result.get('reasoning', ''),
                        recommendations=analysis_result.get('recommendations', []),
                        targets=analysis_result.get('high_priority_targets', [])
                    )
                    db.session.add(analysis)
                    db.session.commit()
                
                progress.update(ai_task, description="AI analysis completed")
                
            except Exception as e:
                logger.error(f"AI analysis failed: {e}")
                console.print(f"[red]AI analysis failed: {e}[/red]")
    
    # Display AI analysis results
    if analysis_result:
        display_ai_analysis(analysis_result, domain, ai_review_only)
    
    # Generate attack surface map if enabled (optional)
    if show_graphs and findings:
        console.print("\n[bold yellow]Generating attack surface map...[/bold yellow]")
        try:
            graph_builder = GraphBuilder()
            nodes, edges = graph_builder.build_graph(findings)
            display_attack_surface_map(nodes, edges, domain)
        except Exception as e:
            logger.error(f"Map generation failed: {e}")
            console.print(f"[red]Map generation failed: {e}[/red]")
    
    # Generate outputs
    if output:
        generate_outputs(findings, analysis_result, domain, output, format, scan_record.id)
    
    # Display final summary
    display_final_summary(findings, analysis_result, domain)
    
    # Display integration examples for piping to other tools
    if format == 'json' and output:
        display_integration_examples(domain, output)

def display_scan_summary(findings, domain):
    """Display summary of scan results"""
    console.print(f"\n[bold green]Reconnaissance Results for {domain}[/bold green]")
    
    # Group findings by tool and type
    findings_by_tool = {}
    findings_by_type = {}
    severity_counts = {'critical': 0, 'high': 0, 'medium': 0, 'low': 0, 'info': 0}
    
    for finding in findings:
        # By tool
        if finding.tool not in findings_by_tool:
            findings_by_tool[finding.tool] = 0
        findings_by_tool[finding.tool] += 1
        
        # By type
        if finding.finding_type not in findings_by_type:
            findings_by_type[finding.finding_type] = 0
        findings_by_type[finding.finding_type] += 1
        
        # By severity
        severity = finding.severity or 'info'
        if severity in severity_counts:
            severity_counts[severity] += 1
    
    # Create summary table
    table = Table(title="Scan Summary")
    table.add_column("Tool", style="cyan")
    table.add_column("Findings", style="green")
    
    for tool, count in findings_by_tool.items():
        table.add_row(tool, str(count))
    
    console.print(table)
    
    # Display severity breakdown
    severity_table = Table(title="Severity Breakdown")
    severity_table.add_column("Severity", style="cyan")
    severity_table.add_column("Count", style="green")
    
    for severity, count in severity_counts.items():
        if count > 0:
            color = {
                'critical': 'red',
                'high': 'orange3', 
                'medium': 'yellow',
                'low': 'blue',
                'info': 'green'
            }.get(severity, 'white')
            severity_table.add_row(f"[{color}]{severity.upper()}[/{color}]", str(count))
    
    console.print(severity_table)

def apply_filter(findings, filter_expr):
    """Apply smart filtering to findings"""
    filtered = []
    
    # Parse filter expression
    # Support syntax like: port!=443 && domain~='dev|admin'
    for finding in findings:
        if evaluate_filter(finding, filter_expr):
            filtered.append(finding)
    
    return filtered

def evaluate_filter(finding, filter_expr):
    """Evaluate filter expression against a finding"""
    try:
        # Extract data from finding
        data = finding.get_data_dict()
        domain = finding.target.lower()
        port = None
        has_https = False
        
        # Extract port if available
        if 'port' in data:
            port = data['port']
        elif 'url' in data:
            url = data['url']
            if ':443' in url or url.startswith('https://'):
                port = 443
                has_https = True
            elif ':80' in url or url.startswith('http://'):
                port = 80
            elif ':' in url:
                try:
                    port = int(url.split(':')[-1].split('/')[0])
                except:
                    pass
        
        # Simple filter evaluation
        filter_expr = filter_expr.lower()
        
        # Check for unusual ports
        if 'port!=' in filter_expr:
            port_val = filter_expr.split('port!=')[1].split('&&')[0].split('||')[0].strip()
            try:
                port_val = int(port_val)
                if port == port_val:
                    return False
            except:
                pass
        
        # Check for no HTTPS
        if 'https' in filter_expr and 'no' in filter_expr:
            if has_https:
                return False
        
        # Check for domain patterns
        if 'domain~=' in filter_expr:
            pattern_part = filter_expr.split('domain~=')[1].split('&&')[0].split('||')[0].strip().strip("'\"")
            patterns = pattern_part.split('|')
            
            found_pattern = False
            for pattern in patterns:
                if pattern.strip() in domain:
                    found_pattern = True
                    break
            
            if not found_pattern:
                return False
        
        # Check for keywords
        keywords = ['admin', 'dev', 'test', 'internal', 'staging', 'api']
        if any(keyword in filter_expr for keyword in keywords):
            for keyword in keywords:
                if keyword in filter_expr and keyword in domain:
                    return True
        
        return True
        
    except Exception as e:
        logger.debug(f"Filter evaluation failed: {e}")
        return True  # Include by default if filter fails

def enhance_analysis_with_linking(analysis_result, findings):
    """Enhance AI analysis with SSRF and auth linking intelligence"""
    if not analysis_result:
        return analysis_result
    
    # Analyze domain relationships for SSRF/auth linking
    domain_map = {}
    auth_domains = []
    api_domains = []
    
    for finding in findings:
        domain = finding.target.lower()
        data = finding.get_data_dict()
        
        # Group domains by base domain
        base_domain = '.'.join(domain.split('.')[-2:]) if '.' in domain else domain
        if base_domain not in domain_map:
            domain_map[base_domain] = []
        domain_map[base_domain].append(domain)
        
        # Identify auth and API domains
        if any(keyword in domain for keyword in ['auth', 'login', 'sso', 'oauth']):
            auth_domains.append(domain)
        if any(keyword in domain for keyword in ['api', 'rest', 'graphql']):
            api_domains.append(domain)
    
    # Generate linking insights
    linking_insights = []
    
    for auth_domain in auth_domains:
        for api_domain in api_domains:
            if auth_domain != api_domain:
                auth_base = '.'.join(auth_domain.split('.')[-2:])
                api_base = '.'.join(api_domain.split('.')[-2:])
                
                if auth_base == api_base:
                    linking_insights.append({
                        'type': 'SSRF_Risk',
                        'description': f'{api_domain} may access {auth_domain} - potential SSRF vector',
                        'risk_level': 'high',
                        'recommendation': f'Test SSRF on {api_domain} targeting {auth_domain}'
                    })
    
    # Add linking insights to analysis
    if linking_insights:
        analysis_result['linking_insights'] = linking_insights
        
        # Update recommendations
        recommendations = analysis_result.get('recommendations', [])
        for insight in linking_insights:
            recommendations.append(insight['recommendation'])
        analysis_result['recommendations'] = recommendations
    
    return analysis_result

def display_ai_analysis(analysis_result, domain, review_only=False):
    """Display AI analysis results"""
    review_mode_text = " (Review Mode - Not Applied)" if review_only else ""
    console.print(f"\n[bold blue]AI Intelligence Report for {domain}{review_mode_text}[/bold blue]")
    
    if review_only:
        console.print("[yellow]⚠️  Review Mode: AI suggestions below are for review only and have not been applied[/yellow]")
    
    # Priority score
    priority = analysis_result.get('overall_priority', 0)
    priority_color = 'red' if priority > 0.7 else 'yellow' if priority > 0.4 else 'green'
    
    console.print(f"[bold]Overall Priority Score:[/bold] [{priority_color}]{priority:.2f}[/{priority_color}]")
    console.print(f"[bold]Confidence:[/bold] {analysis_result.get('confidence', 0):.2f}")
    
    # Reasoning
    if analysis_result.get('reasoning'):
        console.print(f"\n[bold]Analysis Reasoning:[/bold]")
        console.print(Panel(analysis_result['reasoning'], border_style="blue"))
    
    # Linking insights (new intelligence feature)
    linking_insights = analysis_result.get('linking_insights', [])
    if linking_insights:
        console.print(f"\n[bold magenta]🔗 Domain Linking Intelligence:[/bold magenta]")
        for insight in linking_insights:
            risk_color = {'high': 'red', 'medium': 'yellow', 'low': 'green'}.get(insight['risk_level'], 'white')
            console.print(f"[{risk_color}]● {insight['type']}:[/{risk_color}] {insight['description']}")
    
    # High priority targets
    high_priority = analysis_result.get('high_priority_targets', [])
    if high_priority:
        console.print(f"\n[bold red]High Priority Targets:[/bold red]")
        target_table = Table()
        target_table.add_column("Target", style="cyan")
        target_table.add_column("Risk Level", style="red")
        target_table.add_column("Reason", style="white")
        
        for target in high_priority[:10]:  # Show top 10
            if isinstance(target, dict):
                target_table.add_row(
                    target.get('target', 'Unknown'),
                    target.get('risk_level', 'Medium'),
                    target.get('reason', 'No reason provided')
                )
        
        console.print(target_table)
    
    # Recommendations
    recommendations = analysis_result.get('recommendations', [])
    if recommendations:
        console.print(f"\n[bold green]AI Recommendations:[/bold green]")
        for i, rec in enumerate(recommendations[:8], 1):  # Show top 8
            if isinstance(rec, dict):
                console.print(f"{i}. [yellow]{rec.get('action', rec)}[/yellow]")
            else:
                console.print(f"{i}. [yellow]{rec}[/yellow]")
    
    if review_only:
        console.print(f"\n[bold cyan]💡 To apply AI analysis automatically, run without --ai-review-only flag[/bold cyan]")

def display_attack_surface_map(nodes, edges, domain):
    """Display text-based attack surface map"""
    console.print(f"\n[bold magenta]Attack Surface Map for {domain}[/bold magenta]")
    
    # Group nodes by type
    nodes_by_type = {}
    for node in nodes:
        node_type = node.get('type', 'unknown')
        if node_type not in nodes_by_type:
            nodes_by_type[node_type] = []
        nodes_by_type[node_type].append(node)
    
    # Create tree structure
    tree = Tree(f"[bold]{domain}[/bold] - Attack Surface")
    
    for node_type, type_nodes in nodes_by_type.items():
        type_branch = tree.add(f"[cyan]{node_type.title()}s ({len(type_nodes)})[/cyan]")
        
        for node in type_nodes[:10]:  # Limit display
            node_label = node.get('label', node.get('id', 'Unknown'))
            risk_level = node.get('risk_level', 'medium')
            color = {'high': 'red', 'medium': 'yellow', 'low': 'green'}.get(risk_level, 'white')
            type_branch.add(f"[{color}]{node_label}[/{color}]")
        
        if len(type_nodes) > 10:
            type_branch.add(f"[dim]... and {len(type_nodes) - 10} more[/dim]")
    
    console.print(tree)
    
    # Display key relationships
    if edges:
        console.print(f"\n[bold]Key Relationships:[/bold]")
        relationship_table = Table()
        relationship_table.add_column("Source", style="cyan")
        relationship_table.add_column("Target", style="green")
        relationship_table.add_column("Relationship", style="yellow")
        
        for edge in edges[:10]:  # Show top 10 relationships
            relationship_table.add_row(
                edge.get('source', 'Unknown'),
                edge.get('target', 'Unknown'),
                edge.get('type', 'connected')
            )
        
        console.print(relationship_table)

def generate_outputs(findings, analysis_result, domain, output_dir, format, scan_id):
    """Generate output files"""
    console.print(f"\n[bold yellow]Generating output files...[/bold yellow]")
    
    timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
    base_filename = f"recongpt_{domain}_{timestamp}"
    
    if format == 'json':
        # JSON output
        json_file = os.path.join(output_dir, f"{base_filename}.json")
        output_data = {
            'scan_info': {
                'domain': domain,
                'scan_id': scan_id,
                'timestamp': timestamp,
                'total_findings': len(findings)
            },
            'findings': [
                {
                    'tool': f.tool,
                    'type': f.finding_type,
                    'target': f.target,
                    'severity': f.severity,
                    'data': f.get_data_dict()
                } for f in findings
            ],
            'ai_analysis': analysis_result
        }
        
        with open(json_file, 'w') as f:
            json.dump(output_data, f, indent=2)
        
        console.print(f"[green]JSON report saved to: {json_file}[/green]")
    
    elif format == 'html':
        # HTML output
        html_file = os.path.join(output_dir, f"{base_filename}.html")
        generate_html_report(findings, analysis_result, domain, html_file, timestamp)
        console.print(f"[green]HTML report saved to: {html_file}[/green]")
    
def display_integration_examples(domain, output_dir):
    """Display examples for integrating with other tools"""
    console.print(f"\n[bold cyan]🔧 Integration Examples:[/bold cyan]")
    
    latest_json = f"{output_dir}/recongpt_{domain}*.json"
    
    examples = [
        f"# Extract high-priority targets for httpx scanning:",
        f"cat {latest_json} | jq -r '.ai_analysis.high_priority_targets[]? | .target?' | httpx -silent",
        f"",
        f"# Extract all subdomains for nuclei scanning:",
        f"cat {latest_json} | jq -r '.findings[] | select(.type==\"subdomain\") | .target' | nuclei -silent",
        f"",
        f"# Extract URLs with unusual ports:",
        f"cat {latest_json} | jq -r '.findings[] | select(.data.port? and (.data.port != 80 and .data.port != 443)) | .target'",
        f"",
        f"# Extract domains containing dev/admin/test keywords:",
        f"cat {latest_json} | jq -r '.findings[] | select(.target | test(\"dev|admin|test|staging\")) | .target'",
        f"",
        f"# Generate custom wordlist from discovered patterns:",
        f"cat {latest_json} | jq -r '.findings[].target' | cut -d'.' -f1 | sort -u > custom_wordlist.txt"
    ]
    
    for example in examples:
        if example.startswith('#'):
            console.print(f"[bold yellow]{example}[/bold yellow]")
        elif example == "":
            console.print("")
        else:
            console.print(f"[green]{example}[/green]")

def generate_html_report(findings, analysis_result, domain, filename, timestamp):
    """Generate clean, lightweight HTML report"""
    
    # Group findings by risk level
    high_risk = [f for f in findings if f.severity in ['critical', 'high']]
    medium_risk = [f for f in findings if f.severity == 'medium']
    low_risk = [f for f in findings if f.severity in ['low', 'info']]
    
    html_content = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>ReconGPT Report - {domain}</title>
    <style>
        * {{ margin: 0; padding: 0; box-sizing: border-box; }}
        body {{ font-family: 'Segoe UI', system-ui, sans-serif; line-height: 1.6; color: #333; background: #f8f9fa; }}
        .container {{ max-width: 1200px; margin: 0 auto; padding: 20px; }}
        .header {{ background: #2c3e50; color: white; padding: 30px; border-radius: 8px; margin-bottom: 30px; }}
        .header h1 {{ font-size: 2.5em; margin-bottom: 10px; }}
        .header p {{ font-size: 1.2em; opacity: 0.9; }}
        .section {{ background: white; margin: 20px 0; padding: 25px; border-radius: 8px; box-shadow: 0 2px 10px rgba(0,0,0,0.1); }}
        .risk-high {{ border-left: 5px solid #e74c3c; }}
        .risk-medium {{ border-left: 5px solid #f39c12; }}
        .risk-low {{ border-left: 5px solid #27ae60; }}
        .target-list {{ list-style: none; }}
        .target-list li {{ padding: 10px; margin: 5px 0; background: #f8f9fa; border-radius: 4px; display: flex; justify-content: space-between; }}
        .target {{ font-family: 'Courier New', monospace; }}
        .badge {{ padding: 4px 12px; border-radius: 20px; font-size: 0.8em; font-weight: bold; }}
        .badge-high {{ background: #e74c3c; color: white; }}
        .badge-medium {{ background: #f39c12; color: white; }}
        .badge-low {{ background: #27ae60; color: white; }}
        .commands {{ background: #2c3e50; color: #ecf0f1; padding: 15px; border-radius: 4px; font-family: monospace; }}
        .commands h4 {{ color: #3498db; margin-bottom: 10px; }}
        .note {{ background: #3498db; color: white; padding: 15px; border-radius: 4px; margin: 10px 0; }}
        @media (max-width: 768px) {{ .container {{ padding: 10px; }} }}
    </style>
</head>
<body>
    <div class="container">
        <header class="header">
            <h1>ReconGPT Automapper Report</h1>
            <p>Target: {domain} | Generated: {timestamp} | Total Findings: {len(findings)}</p>
        </header>

        <section class="section risk-high">
            <h2>🔴 High Risk Targets ({len(high_risk)})</h2>
            <ul class="target-list">"""
    
    for finding in high_risk[:20]:  # Limit display
        html_content += f"""
                <li>
                    <span class="target">{finding.target}</span>
                    <span class="badge badge-high">{finding.tool} - {finding.finding_type}</span>
                </li>"""
    
    html_content += f"""
            </ul>
            {f'<p>... and {len(high_risk) - 20} more</p>' if len(high_risk) > 20 else ''}
        </section>

        <section class="section risk-medium">
            <h2>🟡 Medium Risk Targets ({len(medium_risk)})</h2>
            <ul class="target-list">"""
    
    for finding in medium_risk[:15]:
        html_content += f"""
                <li>
                    <span class="target">{finding.target}</span>
                    <span class="badge badge-medium">{finding.tool} - {finding.finding_type}</span>
                </li>"""
    
    html_content += f"""
            </ul>
            {f'<p>... and {len(medium_risk) - 15} more</p>' if len(medium_risk) > 15 else ''}
        </section>"""
    
    if analysis_result:
        linking_insights = analysis_result.get('linking_insights', [])
        recommendations = analysis_result.get('recommendations', [])
        
        html_content += f"""
        <section class="section">
            <h2>🤖 AI Analysis Summary</h2>
            <p><strong>Priority Score:</strong> {analysis_result.get('overall_priority', 0):.2f}/1.0</p>
            <p><strong>Confidence:</strong> {analysis_result.get('confidence', 0):.2f}/1.0</p>
            <p><strong>Reasoning:</strong> {analysis_result.get('reasoning', 'No reasoning provided')}</p>
            
            {f'''<h3>🔗 Domain Linking Intelligence</h3>
            <ul>''' + ''.join([f'<li><strong>{insight["type"]}:</strong> {insight["description"]}</li>' for insight in linking_insights]) + '</ul>' if linking_insights else ''}
            
            <h3>📋 AI Recommendations</h3>
            <ul>"""
        
        for rec in recommendations[:8]:
            html_content += f"<li>{rec}</li>"
        
        html_content += """
            </ul>
        </section>"""
    
    html_content += f"""
        <section class="section">
            <h2>🔧 Next Steps & Integration</h2>
            <div class="note">
                <strong>For Red Team / Bug Bounty:</strong> Focus on high-risk targets first. Use the commands below to integrate with your existing tools.
            </div>
            
            <h3>Command Examples:</h3>
            <div class="commands">
                <h4>Scan high-priority targets with httpx:</h4>
                <code>cat recongpt_{domain}_*.json | jq -r '.ai_analysis.high_priority_targets[]? | .target?' | httpx -silent</code>
                
                <h4>Run nuclei on all discovered subdomains:</h4>
                <code>cat recongpt_{domain}_*.json | jq -r '.findings[] | select(.type=="subdomain") | .target' | nuclei -silent</code>
                
                <h4>Extract unusual ports for manual testing:</h4>
                <code>cat recongpt_{domain}_*.json | jq -r '.findings[] | select(.data.port? and (.data.port != 80 and .data.port != 443)) | .target'</code>
            </div>
        </section>

        <section class="section risk-low">
            <h2>ℹ️ All Other Findings ({len(low_risk)})</h2>
            <ul class="target-list">"""
    
    for finding in low_risk[:10]:
        html_content += f"""
                <li>
                    <span class="target">{finding.target}</span>
                    <span class="badge badge-low">{finding.tool} - {finding.finding_type}</span>
                </li>"""
    
    html_content += f"""
            </ul>
            {f'<p>... and {len(low_risk) - 10} more (see JSON output for complete list)</p>' if len(low_risk) > 10 else ''}
        </section>
    </div>
</body>
</html>"""
    
    with open(filename, 'w') as f:
        f.write(html_content)

def generate_text_report(findings, analysis_result, domain, filename, timestamp):
    """Generate text report"""
    with open(filename, 'w') as f:
        f.write(f"ReconGPT Automapper Report\n")
        f.write(f"Target: {domain}\n")
        f.write(f"Generated: {timestamp}\n")
        f.write(f"Total Findings: {len(findings)}\n\n")
        
        f.write("FINDINGS:\n")
        f.write("-" * 50 + "\n")
        
        for finding in findings:
            f.write(f"Tool: {finding.tool}\n")
            f.write(f"Type: {finding.finding_type}\n")
            f.write(f"Target: {finding.target}\n")
            f.write(f"Severity: {finding.severity or 'info'}\n")
            f.write("-" * 30 + "\n")
        
        if analysis_result:
            f.write(f"\nAI ANALYSIS:\n")
            f.write("-" * 50 + "\n")
            f.write(f"Priority Score: {analysis_result.get('overall_priority', 0):.2f}\n")
            f.write(f"Confidence: {analysis_result.get('confidence', 0):.2f}\n")
            f.write(f"Reasoning: {analysis_result.get('reasoning', 'No reasoning provided')}\n")

def display_final_summary(findings, analysis_result, domain):
    """Display final summary and next steps"""
    console.print(f"\n[bold green]Scan Complete for {domain}[/bold green]")
    
    summary_panel = Panel.fit(
        f"[green]✓[/green] {len(findings)} findings discovered\n"
        f"[green]✓[/green] AI analysis {'completed' if analysis_result else 'skipped'}\n"
        f"[green]✓[/green] Attack surface mapped\n"
        f"\n[bold yellow]Next Steps:[/bold yellow]\n"
        f"• Review high-priority targets\n"
        f"• Test identified vulnerabilities\n"
        f"• Run additional tools on key findings\n"
        f"• Investigate suspicious patterns",
        title="Summary",
        border_style="green"
    )
    
    console.print(summary_panel)

@main.command()
@click.option('--scan-id', help='Show specific scan by ID')
def list(scan_id):
    """List previous scans and results"""
    
    if scan_id:
        # Show specific scan
        scan = ReconScan.query.get(scan_id)
        if not scan:
            console.print(f"[red]Scan {scan_id} not found[/red]")
            return
        
        findings = Finding.query.filter_by(scan_id=scan_id).all()
        analyses = AIAnalysis.query.filter_by(scan_id=scan_id).all()
        
        console.print(f"\n[bold blue]Scan Details - {scan.name}[/bold blue]")
        console.print(f"Target: {scan.target}")
        console.print(f"Status: {scan.status}")
        console.print(f"Created: {scan.created_at}")
        console.print(f"Findings: {len(findings)}")
        console.print(f"Analyses: {len(analyses)}")
        
        if findings:
            display_scan_summary(findings, scan.target)
        
        return
    
    # List all scans
    scans = ReconScan.query.order_by(ReconScan.created_at.desc()).limit(20).all()
    
    if not scans:
        console.print("[yellow]No scans found[/yellow]")
        return
    
    table = Table(title="Recent Scans")
    table.add_column("ID", style="cyan")
    table.add_column("Name", style="green")
    table.add_column("Target", style="yellow")
    table.add_column("Status", style="blue")
    table.add_column("Findings", style="magenta")
    table.add_column("Created", style="white")
    
    for scan in scans:
        status_color = {
            'completed': 'green',
            'running': 'yellow', 
            'failed': 'red'
        }.get(scan.status, 'white')
        
        table.add_row(
            str(scan.id),
            scan.name,
            scan.target,
            f"[{status_color}]{scan.status}[/{status_color}]",
            str(scan.findings_count),
            scan.created_at.strftime('%Y-%m-%d %H:%M')
        )
    
    console.print(table)

if __name__ == '__main__':
    try:
        main()
    except KeyboardInterrupt:
        console.print("\n[yellow]Scan interrupted by user[/yellow]")
        sys.exit(0)
    except Exception as e:
        logger.error(f"Unexpected error: {e}")
        console.print(f"[red]Error: {e}[/red]")
        sys.exit(1)