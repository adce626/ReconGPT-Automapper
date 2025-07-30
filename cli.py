#!/usr/bin/env python3
"""
ReconGPT CLI Interface
Command-line interface for running reconnaissance scans and AI analysis
"""

import click
import json
import os
import sys
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.progress import Progress, SpinnerColumn, TextColumn
from rich.syntax import Syntax
from datetime import datetime

# Add the current directory to Python path for imports
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from app import app, db
from models import ReconScan, Finding, AIAnalysis
from recon_engine import ReconEngine
from ai_prioritizer import AIPrioritizer
from graph_builder import GraphBuilder

console = Console()

@click.group()
def cli():
    """ReconGPT - AI-Powered Cybersecurity Reconnaissance Tool"""
    # Initialize Flask app context for CLI operations
    app.app_context().push()

@cli.command()
@click.argument('target')
@click.option('--tools', '-t', multiple=True, default=['amass', 'subfinder', 'httpx'], 
              help='Recon tools to use (amass, subfinder, httpx, nuclei)')
@click.option('--output', '-o', help='Output file for results')
@click.option('--format', '-f', type=click.Choice(['json', 'txt', 'csv']), default='json',
              help='Output format')
@click.option('--analyze', is_flag=True, help='Run AI analysis after scan')
@click.option('--name', help='Custom name for the scan')
def scan(target, tools, output, format, analyze, name):
    """Run reconnaissance scan on target"""
    
    console.print(f"[bold blue]Starting reconnaissance scan for: {target}[/bold blue]")
    
    # Create scan record
    scan_name = name or f"CLI Scan - {target} - {datetime.now().strftime('%Y%m%d_%H%M%S')}"
    scan_record = ReconScan(name=scan_name, target=target, status='running')
    db.session.add(scan_record)
    db.session.commit()
    
    findings = []
    
    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        console=console
    ) as progress:
        
        # Initialize recon engine
        recon_engine = ReconEngine()
        
        # Check available tools
        available_tools = recon_engine.get_available_tools()
        
        for tool in tools:
            if not available_tools.get(tool, False):
                console.print(f"[yellow]Warning: {tool} is not available, will simulate results[/yellow]")
        
        # Run scan
        task = progress.add_task(f"Running scan with tools: {', '.join(tools)}", total=None)
        
        try:
            scan_findings = recon_engine.run_scan(target, tools, scan_record.id)
            findings.extend(scan_findings)
            
            # Update scan record
            scan_record.status = 'completed'
            scan_record.findings_count = len(findings)
            db.session.commit()
            
            progress.update(task, description=f"Scan completed - {len(findings)} findings found")
            
        except Exception as e:
            scan_record.status = 'failed'
            db.session.commit()
            console.print(f"[red]Scan failed: {str(e)}[/red]")
            return
    
    # Display results
    _display_findings(findings)
    
    # Run AI analysis if requested
    if analyze:
        console.print("\n[bold yellow]Running AI analysis...[/bold yellow]")
        try:
            ai_prioritizer = AIPrioritizer()
            analysis_result = ai_prioritizer.analyze_findings(findings)
            
            # Store analysis
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
            
            # Display analysis
            _display_analysis(analysis_result)
            
        except Exception as e:
            console.print(f"[red]AI analysis failed: {str(e)}[/red]")
    
    # Save output if requested
    if output:
        _save_results(findings, output, format, target)
    
    console.print(f"\n[green]Scan completed successfully! Scan ID: {scan_record.id}[/green]")

@cli.command()
@click.argument('scan_id', type=int)
def analyze(scan_id):
    """Run AI analysis on existing scan"""
    
    scan = ReconScan.query.get(scan_id)
    if not scan:
        console.print(f"[red]Scan with ID {scan_id} not found[/red]")
        return
    
    findings = Finding.query.filter_by(scan_id=scan_id).all()
    if not findings:
        console.print(f"[yellow]No findings found for scan {scan_id}[/yellow]")
        return
    
    console.print(f"[bold blue]Running AI analysis for scan: {scan.name}[/bold blue]")
    
    try:
        ai_prioritizer = AIPrioritizer()
        analysis_result = ai_prioritizer.analyze_findings(findings)
        
        # Store analysis
        analysis = AIAnalysis(
            scan_id=scan_id,
            analysis_type='prioritization',
            priority_score=analysis_result.get('overall_priority', 0.5),
            confidence=analysis_result.get('confidence', 0.5),
            reasoning=analysis_result.get('reasoning', ''),
            recommendations=analysis_result.get('recommendations', []),
            targets=analysis_result.get('high_priority_targets', [])
        )
        db.session.add(analysis)
        db.session.commit()
        
        # Display analysis
        _display_analysis(analysis_result)
        
    except Exception as e:
        console.print(f"[red]AI analysis failed: {str(e)}[/red]")

@cli.command()
def list():
    """List all scans"""
    
    scans = ReconScan.query.order_by(ReconScan.created_at.desc()).all()
    
    if not scans:
        console.print("[yellow]No scans found[/yellow]")
        return
    
    table = Table(title="ReconGPT Scans")
    table.add_column("ID", style="cyan", no_wrap=True)
    table.add_column("Name", style="magenta")
    table.add_column("Target", style="green")
    table.add_column("Status", style="yellow")
    table.add_column("Findings", style="blue")
    table.add_column("Created", style="white")
    
    for scan in scans:
        status_color = {
            'completed': 'green',
            'running': 'yellow',
            'failed': 'red',
            'pending': 'blue'
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

@cli.command()
@click.argument('scan_id', type=int)
@click.option('--format', '-f', type=click.Choice(['json', 'txt', 'csv']), default='txt',
              help='Output format')
def show(scan_id, format):
    """Show detailed scan results"""
    
    scan = ReconScan.query.get(scan_id)
    if not scan:
        console.print(f"[red]Scan with ID {scan_id} not found[/red]")
        return
    
    findings = Finding.query.filter_by(scan_id=scan_id).all()
    analyses = AIAnalysis.query.filter_by(scan_id=scan_id).all()
    
    # Display scan info
    console.print(Panel(
        f"[bold]Name:[/bold] {scan.name}\n"
        f"[bold]Target:[/bold] {scan.target}\n"
        f"[bold]Status:[/bold] {scan.status}\n"
        f"[bold]Findings:[/bold] {scan.findings_count}\n"
        f"[bold]Created:[/bold] {scan.created_at}\n",
        title=f"Scan Details - ID: {scan_id}",
        expand=False
    ))
    
    # Display findings
    if findings:
        _display_findings(findings)
    
    # Display analyses
    if analyses:
        console.print("\n[bold yellow]AI Analysis Results:[/bold yellow]")
        for analysis in analyses:
            _display_analysis({
                'overall_priority': analysis.priority_score,
                'confidence': analysis.confidence,
                'reasoning': analysis.reasoning,
                'recommendations': analysis.get_recommendations_list(),
                'high_priority_targets': analysis.get_targets_list()
            })

@cli.command()
@click.argument('scan_id', type=int)
def graph(scan_id):
    """Generate graph visualization for scan"""
    
    scan = ReconScan.query.get(scan_id)
    if not scan:
        console.print(f"[red]Scan with ID {scan_id} not found[/red]")
        return
    
    findings = Finding.query.filter_by(scan_id=scan_id).all()
    if not findings:
        console.print(f"[yellow]No findings found for scan {scan_id}[/yellow]")
        return
    
    console.print(f"[bold blue]Generating graph for scan: {scan.name}[/bold blue]")
    
    try:
        graph_builder = GraphBuilder()
        nodes, edges = graph_builder.build_graph(findings)
        
        # Get graph statistics
        stats = graph_builder.get_graph_statistics(nodes, edges)
        
        # Display statistics
        console.print(Panel(
            f"[bold]Nodes:[/bold] {stats['total_nodes']}\n"
            f"[bold]Edges:[/bold] {stats['total_edges']}\n"
            f"[bold]Components:[/bold] {stats['connected_components']}\n"
            f"[bold]Average Degree:[/bold] {stats['average_degree']:.2f}\n"
            f"[bold]Density:[/bold] {stats['density']:.4f}",
            title="Graph Statistics",
            expand=False
        ))
        
        # Export to GraphML if networkx is available
        try:
            output_file = f"scan_{scan_id}_graph.graphml"
            graph_builder.export_graphml(nodes, edges, output_file)
            console.print(f"[green]Graph exported to {output_file}[/green]")
        except Exception as e:
            console.print(f"[yellow]Could not export GraphML: {str(e)}[/yellow]")
        
        # Save JSON representation
        json_output = {
            'nodes': nodes,
            'edges': edges,
            'statistics': stats
        }
        
        json_file = f"scan_{scan_id}_graph.json"
        with open(json_file, 'w') as f:
            json.dump(json_output, f, indent=2)
        
        console.print(f"[green]Graph data saved to {json_file}[/green]")
        console.print(f"[blue]View interactive graph at: http://localhost:5000/scan/{scan_id}/graph[/blue]")
        
    except Exception as e:
        console.print(f"[red]Graph generation failed: {str(e)}[/red]")

@cli.command()
@click.argument('scan_id', type=int)
def delete(scan_id):
    """Delete a scan and all associated data"""
    
    scan = ReconScan.query.get(scan_id)
    if not scan:
        console.print(f"[red]Scan with ID {scan_id} not found[/red]")
        return
    
    if click.confirm(f"Are you sure you want to delete scan '{scan.name}'?"):
        try:
            db.session.delete(scan)
            db.session.commit()
            console.print(f"[green]Scan {scan_id} deleted successfully[/green]")
        except Exception as e:
            console.print(f"[red]Failed to delete scan: {str(e)}[/red]")

def _display_findings(findings):
    """Display findings in a formatted table"""
    if not findings:
        console.print("[yellow]No findings to display[/yellow]")
        return
    
    table = Table(title="Reconnaissance Findings")
    table.add_column("Tool", style="cyan", no_wrap=True)
    table.add_column("Type", style="magenta")
    table.add_column("Target", style="green")
    table.add_column("Severity", style="yellow")
    table.add_column("Details", style="white")
    
    for finding in findings[:50]:  # Limit display to 50 findings
        details = ""
        data = finding.get_data_dict()
        
        if finding.finding_type == 'http_service':
            status = data.get('status_code', 'N/A')
            title = data.get('title', 'N/A')[:30]
            details = f"Status: {status}, Title: {title}"
        elif finding.finding_type == 'vulnerability':
            vuln_name = data.get('info', {}).get('name', 'Unknown')[:40]
            details = vuln_name
        elif finding.finding_type == 'subdomain':
            source = data.get('source', finding.tool)
            details = f"Source: {source}"
        
        severity_color = {
            'critical': 'red',
            'high': 'red',
            'medium': 'yellow',
            'low': 'green',
            'info': 'blue'
        }.get(finding.severity, 'white')
        
        table.add_row(
            finding.tool,
            finding.finding_type,
            finding.target,
            f"[{severity_color}]{finding.severity or 'N/A'}[/{severity_color}]",
            details
        )
    
    console.print(table)
    
    if len(findings) > 50:
        console.print(f"[yellow]... and {len(findings) - 50} more findings[/yellow]")

def _display_analysis(analysis_result):
    """Display AI analysis results"""
    
    # Overall assessment
    priority = analysis_result.get('overall_priority', 0)
    confidence = analysis_result.get('confidence', 0)
    
    priority_color = 'red' if priority > 0.7 else 'yellow' if priority > 0.4 else 'green'
    
    console.print(Panel(
        f"[bold]Priority Score:[/bold] [{priority_color}]{priority:.2f}[/{priority_color}]\n"
        f"[bold]Confidence:[/bold] {confidence:.2f}\n"
        f"[bold]Summary:[/bold] {analysis_result.get('summary', 'No summary available')}",
        title="AI Analysis Overview",
        expand=False
    ))
    
    # Reasoning
    reasoning = analysis_result.get('reasoning', '')
    if reasoning:
        console.print("\n[bold yellow]Analysis Reasoning:[/bold yellow]")
        console.print(Panel(reasoning, expand=False))
    
    # High priority targets
    targets = analysis_result.get('high_priority_targets', [])
    if targets:
        console.print("\n[bold red]High Priority Targets:[/bold red]")
        target_table = Table()
        target_table.add_column("Target", style="cyan")
        target_table.add_column("Priority", style="red")
        target_table.add_column("Risk Factors", style="yellow")
        
        for target in targets[:10]:  # Show top 10
            risk_factors = ', '.join(target.get('risk_factors', []))
            target_table.add_row(
                target.get('target', 'N/A'),
                f"{target.get('priority_score', 0):.2f}",
                risk_factors[:50] + '...' if len(risk_factors) > 50 else risk_factors
            )
        
        console.print(target_table)
    
    # Recommendations
    recommendations = analysis_result.get('recommendations', [])
    if recommendations:
        console.print("\n[bold green]Recommendations:[/bold green]")
        for i, rec in enumerate(recommendations, 1):
            console.print(f"  {i}. {rec}")

def _save_results(findings, output_file, format, target):
    """Save results to file"""
    
    try:
        if format == 'json':
            results = {
                'target': target,
                'timestamp': datetime.now().isoformat(),
                'findings_count': len(findings),
                'findings': [
                    {
                        'tool': f.tool,
                        'type': f.finding_type,
                        'target': f.target,
                        'severity': f.severity,
                        'data': f.get_data_dict()
                    }
                    for f in findings
                ]
            }
            
            with open(output_file, 'w') as f:
                json.dump(results, f, indent=2)
        
        elif format == 'csv':
            import csv
            with open(output_file, 'w', newline='') as f:
                writer = csv.writer(f)
                writer.writerow(['Tool', 'Type', 'Target', 'Severity', 'Data'])
                
                for finding in findings:
                    writer.writerow([
                        finding.tool,
                        finding.finding_type,
                        finding.target,
                        finding.severity,
                        json.dumps(finding.get_data_dict())
                    ])
        
        elif format == 'txt':
            with open(output_file, 'w') as f:
                f.write(f"ReconGPT Results for: {target}\n")
                f.write(f"Generated: {datetime.now().isoformat()}\n")
                f.write(f"Total Findings: {len(findings)}\n")
                f.write("=" * 50 + "\n\n")
                
                for finding in findings:
                    f.write(f"Tool: {finding.tool}\n")
                    f.write(f"Type: {finding.finding_type}\n")
                    f.write(f"Target: {finding.target}\n")
                    f.write(f"Severity: {finding.severity}\n")
                    f.write(f"Data: {json.dumps(finding.get_data_dict(), indent=2)}\n")
                    f.write("-" * 30 + "\n")
        
        console.print(f"[green]Results saved to {output_file}[/green]")
        
    except Exception as e:
        console.print(f"[red]Failed to save results: {str(e)}[/red]")

if __name__ == '__main__':
    cli()
