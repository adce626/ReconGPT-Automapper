from app import db
from datetime import datetime
from sqlalchemy import JSON
import json

class ReconScan(db.Model):
    """Model for storing recon scan metadata"""
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(200), nullable=False)
    target = db.Column(db.String(500), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    status = db.Column(db.String(50), default='pending')
    findings_count = db.Column(db.Integer, default=0)
    
    # Relationships
    findings = db.relationship('Finding', backref='scan', lazy=True, cascade='all, delete-orphan')
    analyses = db.relationship('AIAnalysis', backref='scan', lazy=True, cascade='all, delete-orphan')

class Finding(db.Model):
    """Model for storing individual findings from recon tools"""
    id = db.Column(db.Integer, primary_key=True)
    scan_id = db.Column(db.Integer, db.ForeignKey('recon_scan.id'), nullable=False)
    tool = db.Column(db.String(100), nullable=False)  # amass, subfinder, httpx, nuclei
    finding_type = db.Column(db.String(100), nullable=False)  # subdomain, port, vulnerability, etc.
    target = db.Column(db.String(500), nullable=False)
    data = db.Column(JSON)  # Raw finding data as JSON
    severity = db.Column(db.String(50))  # low, medium, high, critical
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    
    def get_data_dict(self):
        """Helper method to get data as dictionary"""
        if isinstance(self.data, str):
            try:
                return json.loads(self.data)
            except json.JSONDecodeError:
                return {}
        return self.data or {}

class AIAnalysis(db.Model):
    """Model for storing AI analysis results"""
    id = db.Column(db.Integer, primary_key=True)
    scan_id = db.Column(db.Integer, db.ForeignKey('recon_scan.id'), nullable=False)
    analysis_type = db.Column(db.String(100), nullable=False)  # prioritization, relationship, vulnerability
    priority_score = db.Column(db.Float)  # 0.0 to 1.0
    confidence = db.Column(db.Float)  # 0.0 to 1.0
    reasoning = db.Column(db.Text)
    recommendations = db.Column(JSON)
    targets = db.Column(JSON)  # High-priority targets identified
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    
    def get_recommendations_list(self):
        """Helper method to get recommendations as list"""
        if isinstance(self.recommendations, str):
            try:
                return json.loads(self.recommendations)
            except json.JSONDecodeError:
                return []
        return self.recommendations or []
    
    def get_targets_list(self):
        """Helper method to get targets as list"""
        if isinstance(self.targets, str):
            try:
                return json.loads(self.targets)
            except json.JSONDecodeError:
                return []
        return self.targets or []

class GraphData(db.Model):
    """Model for storing graph visualization data"""
    id = db.Column(db.Integer, primary_key=True)
    scan_id = db.Column(db.Integer, db.ForeignKey('recon_scan.id'), nullable=False)
    nodes = db.Column(JSON)  # Graph nodes data
    edges = db.Column(JSON)  # Graph edges data
    layout_data = db.Column(JSON)  # D3.js layout configuration
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    
    def get_nodes_list(self):
        """Helper method to get nodes as list"""
        if isinstance(self.nodes, str):
            try:
                return json.loads(self.nodes)
            except json.JSONDecodeError:
                return []
        return self.nodes or []
    
    def get_edges_list(self):
        """Helper method to get edges as list"""
        if isinstance(self.edges, str):
            try:
                return json.loads(self.edges)
            except json.JSONDecodeError:
                return []
        return self.edges or []
