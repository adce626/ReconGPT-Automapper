import json
import logging
from collections import defaultdict
from urllib.parse import urlparse
import networkx as nx

class GraphBuilder:
    """Build interactive relationship graphs from reconnaissance findings"""
    
    def __init__(self):
        self.graph = nx.Graph()
        self.node_colors = {
            'domain': '#3498db',      # Blue
            'subdomain': '#2ecc71',   # Green
            'ip': '#e74c3c',          # Red
            'port': '#f39c12',        # Orange
            'service': '#9b59b6',     # Purple
            'vulnerability': '#e67e22', # Dark Orange
            'technology': '#1abc9c'   # Turquoise
        }
        
        self.severity_colors = {
            'critical': '#c0392b',    # Dark Red
            'high': '#e74c3c',        # Red
            'medium': '#f39c12',      # Orange
            'low': '#f1c40f',         # Yellow
            'info': '#3498db'         # Blue
        }
    
    def build_graph(self, findings):
        """Build graph from reconnaissance findings"""
        nodes = []
        edges = []
        
        try:
            # Process findings to extract nodes and relationships
            domain_nodes = {}
            subdomain_nodes = {}
            service_nodes = {}
            vulnerability_nodes = {}
            
            for finding in findings:
                self._process_finding(finding, domain_nodes, subdomain_nodes, 
                                    service_nodes, vulnerability_nodes)
            
            # Convert to node/edge format for D3.js
            nodes.extend(self._create_nodes_from_dict(domain_nodes, 'domain'))
            nodes.extend(self._create_nodes_from_dict(subdomain_nodes, 'subdomain'))
            nodes.extend(self._create_nodes_from_dict(service_nodes, 'service'))
            nodes.extend(self._create_nodes_from_dict(vulnerability_nodes, 'vulnerability'))
            
            # Create edges based on relationships
            edges = self._create_edges(findings, nodes)
            
            # Add NetworkX analysis
            self._add_network_analysis(nodes, edges)
            
        except Exception as e:
            logging.error(f"Error building graph: {str(e)}")
            # Return minimal graph structure
            nodes = [{'id': 'error', 'label': 'Graph Generation Failed', 'type': 'error'}]
            edges = []
        
        return nodes, edges
    
    def _process_finding(self, finding, domain_nodes, subdomain_nodes, 
                        service_nodes, vulnerability_nodes):
        """Process individual finding to extract graph elements"""
        try:
            target = finding.target
            data = finding.get_data_dict()
            
            if finding.finding_type == 'subdomain':
                self._process_subdomain_finding(finding, target, data, 
                                               domain_nodes, subdomain_nodes)
            
            elif finding.finding_type == 'http_service':
                self._process_http_service_finding(finding, target, data, service_nodes)
            
            elif finding.finding_type == 'vulnerability':
                self._process_vulnerability_finding(finding, target, data, vulnerability_nodes)
            
        except Exception as e:
            logging.error(f"Error processing finding: {str(e)}")
    
    def _process_subdomain_finding(self, finding, target, data, domain_nodes, subdomain_nodes):
        """Process subdomain findings"""
        if target:
            # Extract domain from subdomain
            parts = target.split('.')
            if len(parts) >= 2:
                domain = '.'.join(parts[-2:])
                
                # Add domain node
                if domain not in domain_nodes:
                    domain_nodes[domain] = {
                        'id': domain,
                        'label': domain,
                        'type': 'domain',
                        'findings': []
                    }
                
                # Add subdomain node
                subdomain_nodes[target] = {
                    'id': target,
                    'label': target,
                    'type': 'subdomain',
                    'domain': domain,
                    'tool': finding.tool,
                    'severity': finding.severity,
                    'findings': [finding.id]
                }
    
    def _process_http_service_finding(self, finding, target, data, service_nodes):
        """Process HTTP service findings"""
        if target:
            parsed_url = urlparse(target)
            host = parsed_url.netloc or parsed_url.path
            
            service_id = f"http_{host}"
            service_nodes[service_id] = {
                'id': service_id,
                'label': f"HTTP: {host}",
                'type': 'service',
                'host': host,
                'url': target,
                'status_code': data.get('status_code'),
                'title': data.get('title'),
                'tech': data.get('tech', []),
                'severity': finding.severity,
                'tool': finding.tool,
                'findings': [finding.id]
            }
    
    def _process_vulnerability_finding(self, finding, target, data, vulnerability_nodes):
        """Process vulnerability findings"""
        if target:
            vuln_id = data.get('template-id', f"vuln_{finding.id}")
            vuln_name = data.get('info', {}).get('name', 'Unknown Vulnerability')
            
            vulnerability_nodes[vuln_id] = {
                'id': vuln_id,
                'label': vuln_name,
                'type': 'vulnerability',
                'target': target,
                'severity': finding.severity,
                'tool': finding.tool,
                'description': data.get('info', {}).get('description', ''),
                'findings': [finding.id]
            }
    
    def _create_nodes_from_dict(self, node_dict, node_type):
        """Convert node dictionary to list format"""
        nodes = []
        for node_id, node_data in node_dict.items():
            node = {
                'id': node_id,
                'label': node_data.get('label', node_id),
                'type': node_type,
                'color': self._get_node_color(node_data),
                'size': self._get_node_size(node_data),
                'data': node_data
            }
            nodes.append(node)
        
        return nodes
    
    def _get_node_color(self, node_data):
        """Determine node color based on type and severity"""
        node_type = node_data.get('type', 'unknown')
        severity = node_data.get('severity', 'info')
        
        # Use severity color for vulnerabilities
        if node_type == 'vulnerability':
            return self.severity_colors.get(severity, '#95a5a6')
        
        # Use type color for other nodes
        return self.node_colors.get(node_type, '#95a5a6')
    
    def _get_node_size(self, node_data):
        """Determine node size based on importance"""
        node_type = node_data.get('type', 'unknown')
        severity = node_data.get('severity', 'info')
        
        base_size = 10
        
        # Size based on type
        type_multipliers = {
            'domain': 1.5,
            'subdomain': 1.0,
            'service': 1.2,
            'vulnerability': 1.3
        }
        
        # Size based on severity
        severity_multipliers = {
            'critical': 2.0,
            'high': 1.5,
            'medium': 1.2,
            'low': 1.0,
            'info': 0.8
        }
        
        size = base_size * type_multipliers.get(node_type, 1.0)
        size *= severity_multipliers.get(severity, 1.0)
        
        return max(size, 5)  # Minimum size of 5
    
    def _create_edges(self, findings, nodes):
        """Create edges between related nodes"""
        edges = []
        node_lookup = {node['id']: node for node in nodes}
        
        # Create relationships
        for finding in findings:
            target = finding.target
            
            if finding.finding_type == 'subdomain':
                # Connect subdomain to domain
                if target in node_lookup:
                    parts = target.split('.')
                    if len(parts) >= 2:
                        domain = '.'.join(parts[-2:])
                        if domain in node_lookup:
                            edges.append({
                                'source': domain,
                                'target': target,
                                'type': 'subdomain_of',
                                'label': 'subdomain of'
                            })
            
            elif finding.finding_type == 'http_service':
                # Connect service to host
                parsed_url = urlparse(target)
                host = parsed_url.netloc or parsed_url.path
                service_id = f"http_{host}"
                
                if service_id in node_lookup and host in node_lookup:
                    edges.append({
                        'source': host,
                        'target': service_id,
                        'type': 'hosts_service',
                        'label': 'hosts'
                    })
            
            elif finding.finding_type == 'vulnerability':
                # Connect vulnerability to target
                data = finding.get_data_dict()
                vuln_id = data.get('template-id', f"vuln_{finding.id}")
                
                if vuln_id in node_lookup and target in node_lookup:
                    edges.append({
                        'source': target,
                        'target': vuln_id,
                        'type': 'has_vulnerability',
                        'label': 'vulnerable to',
                        'severity': finding.severity
                    })
        
        return edges
    
    def _add_network_analysis(self, nodes, edges):
        """Add network analysis metrics to nodes"""
        try:
            # Build NetworkX graph for analysis
            G = nx.Graph()
            
            for node in nodes:
                G.add_node(node['id'], **node['data'])
            
            for edge in edges:
                G.add_edge(edge['source'], edge['target'])
            
            # Calculate centrality measures
            degree_centrality = nx.degree_centrality(G)
            betweenness_centrality = nx.betweenness_centrality(G)
            closeness_centrality = nx.closeness_centrality(G)
            
            # Add metrics to nodes
            for node in nodes:
                node_id = node['id']
                node['metrics'] = {
                    'degree_centrality': degree_centrality.get(node_id, 0),
                    'betweenness_centrality': betweenness_centrality.get(node_id, 0),
                    'closeness_centrality': closeness_centrality.get(node_id, 0),
                    'degree': G.degree(node_id) if node_id in G else 0
                }
            
        except Exception as e:
            logging.error(f"Error in network analysis: {str(e)}")
    
    def export_graphml(self, nodes, edges, filename):
        """Export graph to GraphML format"""
        try:
            G = nx.Graph()
            
            for node in nodes:
                G.add_node(node['id'], **node.get('data', {}))
            
            for edge in edges:
                G.add_edge(edge['source'], edge['target'], **edge)
            
            nx.write_graphml(G, filename)
            logging.info(f"Graph exported to {filename}")
            
        except Exception as e:
            logging.error(f"Error exporting graph: {str(e)}")
    
    def get_graph_statistics(self, nodes, edges):
        """Get basic graph statistics"""
        try:
            G = nx.Graph()
            
            for node in nodes:
                G.add_node(node['id'])
            
            for edge in edges:
                G.add_edge(edge['source'], edge['target'])
            
            stats = {
                'total_nodes': len(nodes),
                'total_edges': len(edges),
                'connected_components': nx.number_connected_components(G),
                'average_degree': sum(dict(G.degree()).values()) / len(G) if len(G) > 0 else 0,
                'density': nx.density(G)
            }
            
            return stats
            
        except Exception as e:
            logging.error(f"Error calculating graph statistics: {str(e)}")
            return {
                'total_nodes': len(nodes),
                'total_edges': len(edges),
                'connected_components': 1,
                'average_degree': 0,
                'density': 0
            }
