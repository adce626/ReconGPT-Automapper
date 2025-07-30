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
              default=['amass', 'subfinder', 'httpx', 'nuclei'],
              help='Recon tools to use (amass, subfinder, httpx, nuclei)')
@click.option('--output', '-o', help='Output directory for results')
@click.option('--format', '-f', 
              type=click.Choice(['json', 'html', 'txt']), 
              default='json',
              help='Output format')
@click.option('--analyze/--no-analyze', default=True,
              help='Run AI analysis (default: enabled)')
@click.option('--interactive-map/--no-interactive-map', default=True,
              help='Generate interactive attack surface map')
@click.option('--verbose', '-v', is_flag=True, help='Verbose output')
def scan(domain, tools, output, format, analyze, interactive_map, verbose):
    """
    Run comprehensive reconnaissance scan on target domain
    
    Example: python recongpt.py scan target.com
    """
    
    if verbose:
        logging.getLogger().setLevel(logging.DEBUG)
    
    # Display tool banner
    console.print(Panel.fit(
        f"[bold blue]ReconGPT Automapper[/bold blue]\n"
        f"[white]Target: {domain}[/white]\n"
        f"[white]Tools: {', '.join(tools)}[/white]\n"
        f"[white]AI Analysis: {'Enabled' if analyze else 'Disabled'}[/white]",
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
                
                # Store analysis results
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
        display_ai_analysis(analysis_result, domain)
    
    # Generate attack surface map if enabled
    if interactive_map and findings:
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

def display_ai_analysis(analysis_result, domain):
    """Display AI analysis results"""
    console.print(f"\n[bold blue]AI Intelligence Report for {domain}[/bold blue]")
    
    # Priority score
    priority = analysis_result.get('overall_priority', 0)
    priority_color = 'red' if priority > 0.7 else 'yellow' if priority > 0.4 else 'green'
    
    console.print(f"[bold]Overall Priority Score:[/bold] [{priority_color}]{priority:.2f}[/{priority_color}]")
    console.print(f"[bold]Confidence:[/bold] {analysis_result.get('confidence', 0):.2f}")
    
    # Reasoning
    if analysis_result.get('reasoning'):
        console.print(f"\n[bold]Analysis Reasoning:[/bold]")
        console.print(Panel(analysis_result['reasoning'], border_style="blue"))
    
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
        for i, rec in enumerate(recommendations[:5], 1):  # Show top 5
            if isinstance(rec, dict):
                console.print(f"{i}. [yellow]{rec.get('action', rec)}[/yellow]")
            else:
                console.print(f"{i}. [yellow]{rec}[/yellow]")

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
    
    elif format == 'txt':
        # Text output
        txt_file = os.path.join(output_dir, f"{base_filename}.txt")
        generate_text_report(findings, analysis_result, domain, txt_file, timestamp)
        console.print(f"[green]Text report saved to: {txt_file}[/green]")

def generate_html_report(findings, analysis_result, domain, filename, timestamp):
    """Generate HTML report"""
    html_content = f"""
    <!DOCTYPE html>
    <html>
    <head>
        <title>ReconGPT Report - {domain}</title>
        <style>
            body {{ font-family: Arial, sans-serif; margin: 40px; }}
            .header {{ background: #2c3e50; color: white; padding: 20px; }}
            .section {{ margin: 20px 0; }}
            .finding {{ border-left: 4px solid #3498db; padding-left: 15px; margin: 10px 0; }}
            .high-risk {{ border-left-color: #e74c3c; }}
            .medium-risk {{ border-left-color: #f39c12; }}
            .low-risk {{ border-left-color: #27ae60; }}
            table {{ width: 100%; border-collapse: collapse; }}
            th, td {{ padding: 10px; text-align: left; border-bottom: 1px solid #ddd; }}
            th {{ background-color: #f2f2f2; }}
        </style>
    </head>
    <body>
        <div class="header">
            <h1>ReconGPT Automapper Report</h1>
            <p>Target: {domain} | Generated: {timestamp}</p>
        </div>
        
        <div class="section">
            <h2>Summary</h2>
            <p>Total Findings: {len(findings)}</p>
        </div>
        
        <div class="section">
            <h2>Findings</h2>
            <table>
                <tr>
                    <th>Tool</th>
                    <th>Type</th>
                    <th>Target</th>
                    <th>Severity</th>
                </tr>
    """
    
    for finding in findings:
        severity_class = {
            'critical': 'high-risk',
            'high': 'high-risk',
            'medium': 'medium-risk',
            'low': 'low-risk'
        }.get(finding.severity, '')
        
        html_content += f"""
                <tr class="{severity_class}">
                    <td>{finding.tool}</td>
                    <td>{finding.finding_type}</td>
                    <td>{finding.target}</td>
                    <td>{finding.severity or 'info'}</td>
                </tr>
        """
    
    html_content += """
            </table>
        </div>
    """
    
    if analysis_result:
        html_content += f"""
        <div class="section">
            <h2>AI Analysis</h2>
            <p><strong>Priority Score:</strong> {analysis_result.get('overall_priority', 0):.2f}</p>
            <p><strong>Confidence:</strong> {analysis_result.get('confidence', 0):.2f}</p>
            <p><strong>Reasoning:</strong> {analysis_result.get('reasoning', 'No reasoning provided')}</p>
        </div>
        """
    
    html_content += """
    </body>
    </html>
    """
    
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