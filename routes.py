from flask import render_template, request, redirect, url_for, flash, jsonify
from app import app, db
from models import ReconScan, Finding, AIAnalysis, GraphData
from recon_engine import ReconEngine
from ai_prioritizer import AIPrioritizer
from graph_builder import GraphBuilder
import json
import logging

@app.route('/')
def index():
    """Main dashboard showing recent scans and statistics"""
    recent_scans = ReconScan.query.order_by(ReconScan.created_at.desc()).limit(10).all()
    total_scans = ReconScan.query.count()
    total_findings = Finding.query.count()
    
    # Get some basic statistics
    stats = {
        'total_scans': total_scans,
        'total_findings': total_findings,
        'active_scans': ReconScan.query.filter_by(status='running').count(),
        'high_priority_findings': Finding.query.filter_by(severity='high').count()
    }
    
    return render_template('index.html', recent_scans=recent_scans, stats=stats)

@app.route('/scan/new', methods=['GET', 'POST'])
def new_scan():
    """Create a new reconnaissance scan"""
    if request.method == 'POST':
        target = request.form.get('target', '').strip()
        scan_name = request.form.get('scan_name', '').strip()
        tools = request.form.getlist('tools')
        
        if not target or not scan_name:
            flash('Target and scan name are required', 'error')
            return render_template('index.html')
        
        # Create new scan
        scan = ReconScan(name=scan_name, target=target, status='running')
        db.session.add(scan)
        db.session.commit()
        
        try:
            # Initialize recon engine and start scan
            recon_engine = ReconEngine()
            findings = recon_engine.run_scan(target, tools, scan.id)
            
            # Update scan status and findings count
            scan.status = 'completed'
            scan.findings_count = len(findings)
            db.session.commit()
            
            flash(f'Scan completed successfully! Found {len(findings)} findings.', 'success')
            return redirect(url_for('scan_detail', scan_id=scan.id))
            
        except Exception as e:
            logging.error(f"Scan failed: {str(e)}")
            scan.status = 'failed'
            db.session.commit()
            flash(f'Scan failed: {str(e)}', 'error')
            return redirect(url_for('index'))
    
    return render_template('index.html')

@app.route('/scan/<int:scan_id>')
def scan_detail(scan_id):
    """View detailed scan results"""
    scan = ReconScan.query.get_or_404(scan_id)
    findings = Finding.query.filter_by(scan_id=scan_id).all()
    
    # Group findings by tool and type
    findings_by_tool = {}
    findings_by_severity = {'low': 0, 'medium': 0, 'high': 0, 'critical': 0}
    
    for finding in findings:
        if finding.tool not in findings_by_tool:
            findings_by_tool[finding.tool] = []
        findings_by_tool[finding.tool].append(finding)
        
        if finding.severity:
            findings_by_severity[finding.severity] = findings_by_severity.get(finding.severity, 0) + 1
    
    return render_template('analysis.html', 
                         scan=scan, 
                         findings=findings,
                         findings_by_tool=findings_by_tool,
                         findings_by_severity=findings_by_severity)

@app.route('/scan/<int:scan_id>/analyze', methods=['POST'])
def analyze_scan(scan_id):
    """Run AI analysis on scan results"""
    scan = ReconScan.query.get_or_404(scan_id)
    findings = Finding.query.filter_by(scan_id=scan_id).all()
    
    if not findings:
        flash('No findings to analyze', 'warning')
        return redirect(url_for('scan_detail', scan_id=scan_id))
    
    try:
        # Run AI analysis
        ai_prioritizer = AIPrioritizer()
        analysis_result = ai_prioritizer.analyze_findings(findings)
        
        # Store analysis results
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
        
        flash('AI analysis completed successfully!', 'success')
        
    except Exception as e:
        logging.error(f"AI analysis failed: {str(e)}")
        flash(f'AI analysis failed: {str(e)}', 'error')
    
    return redirect(url_for('scan_detail', scan_id=scan_id))

@app.route('/scan/<int:scan_id>/graph')
def scan_graph(scan_id):
    """View interactive graph visualization"""
    scan = ReconScan.query.get_or_404(scan_id)
    findings = Finding.query.filter_by(scan_id=scan_id).all()
    
    # Check if graph data exists
    graph_data = GraphData.query.filter_by(scan_id=scan_id).first()
    
    if not graph_data:
        # Generate graph data
        try:
            graph_builder = GraphBuilder()
            nodes, edges = graph_builder.build_graph(findings)
            
            graph_data = GraphData(
                scan_id=scan_id,
                nodes=nodes,
                edges=edges,
                layout_data={'force': True, 'charge': -300}
            )
            db.session.add(graph_data)
            db.session.commit()
            
        except Exception as e:
            logging.error(f"Graph generation failed: {str(e)}")
            flash(f'Graph generation failed: {str(e)}', 'error')
            return redirect(url_for('scan_detail', scan_id=scan_id))
    
    return render_template('graph.html', scan=scan, graph_data=graph_data)

@app.route('/api/scan/<int:scan_id>/graph-data')
def graph_data_api(scan_id):
    """API endpoint for graph data"""
    graph_data = GraphData.query.filter_by(scan_id=scan_id).first()
    
    if not graph_data:
        return jsonify({'error': 'Graph data not found'}), 404
    
    return jsonify({
        'nodes': graph_data.get_nodes_list(),
        'edges': graph_data.get_edges_list(),
        'layout': graph_data.layout_data or {}
    })

@app.route('/reports')
def reports():
    """Reports dashboard"""
    scans = ReconScan.query.order_by(ReconScan.created_at.desc()).all()
    
    # Generate summary statistics
    total_findings = Finding.query.count()
    severity_stats = db.session.query(
        Finding.severity, 
        db.func.count(Finding.id)
    ).group_by(Finding.severity).all()
    
    tool_stats = db.session.query(
        Finding.tool,
        db.func.count(Finding.id)
    ).group_by(Finding.tool).all()
    
    return render_template('reports.html', 
                         scans=scans,
                         total_findings=total_findings,
                         severity_stats=dict(severity_stats),
                         tool_stats=dict(tool_stats))

@app.route('/scan/<int:scan_id>/delete', methods=['POST'])
def delete_scan(scan_id):
    """Delete a scan and all associated data"""
    scan = ReconScan.query.get_or_404(scan_id)
    
    try:
        # Delete associated data (handled by cascade)
        db.session.delete(scan)
        db.session.commit()
        flash('Scan deleted successfully', 'success')
    except Exception as e:
        logging.error(f"Failed to delete scan: {str(e)}")
        flash('Failed to delete scan', 'error')
    
    return redirect(url_for('index'))

@app.errorhandler(404)
def not_found(error):
    return render_template('base.html'), 404

@app.errorhandler(500)
def internal_error(error):
    db.session.rollback()
    return render_template('base.html'), 500
