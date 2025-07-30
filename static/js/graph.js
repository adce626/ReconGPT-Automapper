/**
 * ReconGPT Graph Visualization
 * Interactive D3.js network graph for attack surface mapping
 */

let svg, g, simulation, nodes, links;
let currentNodes = [], currentLinks = [];
let selectedNode = null;
let zoom, width, height;
let showLabels = true;

/**
 * Initialize the graph visualization
 */
function initializeGraph(scanId) {
    // Show loading overlay
    document.getElementById('loadingOverlay').style.display = 'flex';
    
    // Set up SVG dimensions
    const container = document.getElementById('graph-container');
    width = container.clientWidth;
    height = container.clientHeight;
    
    svg = d3.select('#graph-svg')
        .attr('width', width)
        .attr('height', height);
    
    // Clear any existing content
    svg.selectAll('*').remove();
    
    // Create main group for zoomable content
    g = svg.append('g');
    
    // Set up zoom behavior
    zoom = d3.zoom()
        .scaleExtent([0.1, 10])
        .on('zoom', handleZoom);
    
    svg.call(zoom);
    
    // Load graph data from API
    loadGraphData(scanId);
}

/**
 * Load graph data from the backend API
 */
function loadGraphData(scanId) {
    fetch(`/api/scan/${scanId}/graph-data`)
        .then(response => {
            if (!response.ok) {
                throw new Error(`HTTP error! status: ${response.status}`);
            }
            return response.json();
        })
        .then(data => {
            currentNodes = data.nodes || [];
            currentLinks = data.edges || [];
            
            // Update statistics
            updateStatistics(data);
            
            // Create the graph
            createGraph();
            
            // Hide loading overlay
            document.getElementById('loadingOverlay').style.display = 'none';
        })
        .catch(error => {
            console.error('Error loading graph data:', error);
            
            // Show error message
            showErrorMessage('Failed to load graph data. Please try again.');
            
            // Hide loading overlay
            document.getElementById('loadingOverlay').style.display = 'none';
        });
}

/**
 * Create the D3.js force simulation and render the graph
 */
function createGraph() {
    // Clear existing graph
    g.selectAll('*').remove();
    
    if (currentNodes.length === 0) {
        showErrorMessage('No graph data available for this scan.');
        return;
    }
    
    // Create force simulation
    simulation = d3.forceSimulation(currentNodes)
        .force('link', d3.forceLink(currentLinks).id(d => d.id).distance(80))
        .force('charge', d3.forceManyBody().strength(-200))
        .force('center', d3.forceCenter(width / 2, height / 2))
        .force('collision', d3.forceCollide().radius(d => d.size + 5));
    
    // Create links
    const link = g.append('g')
        .attr('class', 'links')
        .selectAll('line')
        .data(currentLinks)
        .enter().append('line')
        .attr('class', 'link')
        .attr('stroke', '#6c757d')
        .attr('stroke-width', d => Math.sqrt(d.value) || 1)
        .attr('stroke-opacity', 0.6);
    
    // Create nodes
    const node = g.append('g')
        .attr('class', 'nodes')
        .selectAll('circle')
        .data(currentNodes)
        .enter().append('circle')
        .attr('class', 'node')
        .attr('r', d => d.size || 8)
        .attr('fill', d => d.color || '#0dcaf0')
        .attr('stroke', '#fff')
        .attr('stroke-width', 2)
        .style('cursor', 'pointer')
        .call(d3.drag()
            .on('start', dragStarted)
            .on('drag', dragged)
            .on('end', dragEnded))
        .on('click', handleNodeClick)
        .on('mouseover', handleNodeMouseOver)
        .on('mouseout', handleNodeMouseOut);
    
    // Create labels
    const label = g.append('g')
        .attr('class', 'labels')
        .selectAll('text')
        .data(currentNodes)
        .enter().append('text')
        .attr('class', 'label')
        .text(d => d.label || d.id)
        .attr('font-size', '12px')
        .attr('font-family', 'monospace')
        .attr('fill', '#ffffff')
        .attr('text-anchor', 'middle')
        .attr('dy', '.35em')
        .style('pointer-events', 'none')
        .style('display', showLabels ? 'block' : 'none');
    
    // Store references for updates
    nodes = node;
    links = link;
    
    // Update positions on simulation tick
    simulation.on('tick', () => {
        links
            .attr('x1', d => d.source.x)
            .attr('y1', d => d.source.y)
            .attr('x2', d => d.target.x)
            .attr('y2', d => d.target.y);
        
        nodes
            .attr('cx', d => d.x)
            .attr('cy', d => d.y);
        
        label
            .attr('x', d => d.x)
            .attr('y', d => d.y);
    });
}

/**
 * Handle zoom events
 */
function handleZoom(event) {
    g.attr('transform', event.transform);
}

/**
 * Handle node drag events
 */
function dragStarted(event, d) {
    if (!event.active) simulation.alphaTarget(0.3).restart();
    d.fx = d.x;
    d.fy = d.y;
}

function dragged(event, d) {
    d.fx = event.x;
    d.fy = event.y;
}

function dragEnded(event, d) {
    if (!event.active) simulation.alphaTarget(0);
    d.fx = null;
    d.fy = null;
}

/**
 * Handle node click events
 */
function handleNodeClick(event, d) {
    selectedNode = d;
    
    // Highlight selected node
    nodes.attr('stroke-width', n => n === d ? 4 : 2);
    
    // Show node details
    showNodeDetails(d);
}

/**
 * Handle node mouse events
 */
function handleNodeMouseOver(event, d) {
    // Highlight connected nodes
    const connectedNodeIds = new Set();
    currentLinks.forEach(link => {
        if (link.source.id === d.id) connectedNodeIds.add(link.target.id);
        if (link.target.id === d.id) connectedNodeIds.add(link.source.id);
    });
    
    nodes.attr('opacity', n => 
        n.id === d.id || connectedNodeIds.has(n.id) ? 1.0 : 0.3
    );
    
    links.attr('opacity', l => 
        l.source.id === d.id || l.target.id === d.id ? 1.0 : 0.1
    );
}

function handleNodeMouseOut(event, d) {
    // Reset opacity
    nodes.attr('opacity', 1.0);
    links.attr('opacity', 0.6);
}

/**
 * Show node details in modal
 */
function showNodeDetails(node) {
    const modal = new bootstrap.Modal(document.getElementById('nodeDetailsModal'));
    const content = document.getElementById('nodeDetailsContent');
    
    const data = node.data || {};
    
    let detailsHtml = `
        <div class="row mb-3">
            <div class="col-md-6">
                <h6>Node Information</h6>
                <table class="table table-sm">
                    <tr><td><strong>ID:</strong></td><td><code>${node.id}</code></td></tr>
                    <tr><td><strong>Label:</strong></td><td>${node.label || node.id}</td></tr>
                    <tr><td><strong>Type:</strong></td><td><span class="badge bg-info">${node.type}</span></td></tr>
                    <tr><td><strong>Size:</strong></td><td>${node.size || 'N/A'}</td></tr>
                </table>
            </div>
            <div class="col-md-6">
                <h6>Metrics</h6>
                <table class="table table-sm">
    `;
    
    if (node.metrics) {
        detailsHtml += `
            <tr><td><strong>Degree:</strong></td><td>${node.metrics.degree}</td></tr>
            <tr><td><strong>Centrality:</strong></td><td>${(node.metrics.degree_centrality * 100).toFixed(2)}%</td></tr>
            <tr><td><strong>Betweenness:</strong></td><td>${(node.metrics.betweenness_centrality * 100).toFixed(2)}%</td></tr>
        `;
    } else {
        detailsHtml += '<tr><td colspan="2" class="text-muted">No metrics available</td></tr>';
    }
    
    detailsHtml += `
                </table>
            </div>
        </div>
    `;
    
    // Add specific data based on node type
    if (data.severity) {
        detailsHtml += `
            <div class="mb-3">
                <h6>Security Information</h6>
                <p>Severity: <span class="badge bg-${getSeverityColor(data.severity)}">${data.severity}</span></p>
            </div>
        `;
    }
    
    if (data.tool) {
        detailsHtml += `
            <div class="mb-3">
                <h6>Discovery Tool</h6>
                <p>Found by: <span class="badge bg-secondary">${data.tool}</span></p>
            </div>
        `;
    }
    
    // Add raw data
    detailsHtml += `
        <div class="mb-3">
            <h6>Raw Data</h6>
            <pre class="bg-dark text-light p-3 rounded"><code>${JSON.stringify(data, null, 2)}</code></pre>
        </div>
    `;
    
    content.innerHTML = detailsHtml;
    modal.show();
}

/**
 * Update graph statistics display
 */
function updateStatistics(data) {
    document.getElementById('nodeCount').textContent = currentNodes.length;
    document.getElementById('edgeCount').textContent = currentLinks.length;
    
    // Calculate connected components (simplified)
    const visited = new Set();
    let components = 0;
    
    for (const node of currentNodes) {
        if (!visited.has(node.id)) {
            components++;
            const stack = [node.id];
            
            while (stack.length > 0) {
                const nodeId = stack.pop();
                if (visited.has(nodeId)) continue;
                
                visited.add(nodeId);
                
                // Find connected nodes
                for (const link of currentLinks) {
                    if (link.source.id === nodeId && !visited.has(link.target.id)) {
                        stack.push(link.target.id);
                    }
                    if (link.target.id === nodeId && !visited.has(link.source.id)) {
                        stack.push(link.source.id);
                    }
                }
            }
        }
    }
    
    document.getElementById('componentCount').textContent = components;
    
    // Calculate density
    const maxEdges = currentNodes.length * (currentNodes.length - 1) / 2;
    const density = maxEdges > 0 ? (currentLinks.length / maxEdges) : 0;
    document.getElementById('densityValue').textContent = (density * 100).toFixed(1) + '%';
}

/**
 * Filter functions
 */
function filterNodes() {
    const filter = document.getElementById('nodeFilter').value;
    
    if (filter === 'all') {
        // Show all nodes
        nodes.style('display', 'block');
        g.select('.labels').selectAll('text').style('display', showLabels ? 'block' : 'none');
    } else {
        // Filter by node type
        nodes.style('display', d => d.type === filter ? 'block' : 'none');
        g.select('.labels').selectAll('text').style('display', d => 
            d.type === filter ? (showLabels ? 'block' : 'none') : 'none'
        );
    }
}

function filterBySeverity() {
    const severity = document.getElementById('severityFilter').value;
    
    if (severity === 'all') {
        nodes.style('display', 'block');
        g.select('.labels').selectAll('text').style('display', showLabels ? 'block' : 'none');
    } else {
        nodes.style('display', d => {
            const nodeSeverity = d.data?.severity;
            return nodeSeverity === severity ? 'block' : 'none';
        });
        g.select('.labels').selectAll('text').style('display', d => {
            const nodeSeverity = d.data?.severity;
            return nodeSeverity === severity ? (showLabels ? 'block' : 'none') : 'none';
        });
    }
}

/**
 * Control functions
 */
function resetGraph() {
    if (!svg) return;
    
    // Reset zoom
    svg.transition().duration(750).call(
        zoom.transform,
        d3.zoomIdentity
    );
    
    // Reset node positions
    if (simulation) {
        simulation.alpha(1).restart();
    }
}

function toggleLabels() {
    showLabels = !showLabels;
    g.select('.labels').selectAll('text')
        .style('display', showLabels ? 'block' : 'none');
}

function updateForce(value) {
    document.getElementById('forceValue').textContent = value;
    
    if (simulation) {
        simulation.force('charge', d3.forceManyBody().strength(-value));
        simulation.alpha(0.3).restart();
    }
}

function zoomIn() {
    svg.transition().duration(300).call(
        zoom.scaleBy, 1.5
    );
}

function zoomOut() {
    svg.transition().duration(300).call(
        zoom.scaleBy, 1 / 1.5
    );
}

function centerGraph() {
    svg.transition().duration(750).call(
        zoom.transform,
        d3.zoomIdentity.translate(width / 2, height / 2).scale(1)
    );
}

function highlightConnected() {
    if (!selectedNode) return;
    
    const connectedNodeIds = new Set([selectedNode.id]);
    
    // Find all connected nodes
    currentLinks.forEach(link => {
        if (link.source.id === selectedNode.id) connectedNodeIds.add(link.target.id);
        if (link.target.id === selectedNode.id) connectedNodeIds.add(link.source.id);
    });
    
    // Highlight connected nodes
    nodes.attr('stroke', n => connectedNodeIds.has(n.id) ? '#ffc107' : '#fff')
         .attr('stroke-width', n => connectedNodeIds.has(n.id) ? 3 : 2);
    
    // Highlight connected links
    links.attr('stroke', l => 
        l.source.id === selectedNode.id || l.target.id === selectedNode.id ? '#ffc107' : '#6c757d'
    ).attr('stroke-width', l =>
        l.source.id === selectedNode.id || l.target.id === selectedNode.id ? 3 : 1
    );
}

function exportGraph() {
    // Create export data
    const exportData = {
        nodes: currentNodes,
        links: currentLinks,
        timestamp: new Date().toISOString(),
        metadata: {
            nodeCount: currentNodes.length,
            linkCount: currentLinks.length
        }
    };
    
    // Create and download JSON file
    const blob = new Blob([JSON.stringify(exportData, null, 2)], {
        type: 'application/json'
    });
    
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `graph_export_${new Date().toISOString().split('T')[0]}.json`;
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    URL.revokeObjectURL(url);
}

/**
 * Utility functions
 */
function getSeverityColor(severity) {
    const colors = {
        'critical': 'danger',
        'high': 'danger',
        'medium': 'warning',
        'low': 'success',
        'info': 'info'
    };
    return colors[severity] || 'secondary';
}

function showErrorMessage(message) {
    const container = document.getElementById('graph-container');
    container.innerHTML = `
        <div class="d-flex align-items-center justify-content-center h-100">
            <div class="text-center">
                <i class="fas fa-exclamation-triangle fa-3x text-warning mb-3"></i>
                <h5 class="text-muted">${message}</h5>
                <button class="btn btn-primary mt-3" onclick="location.reload()">
                    <i class="fas fa-refresh me-1"></i>Retry
                </button>
            </div>
        </div>
    `;
}

// Handle window resize
window.addEventListener('resize', () => {
    const container = document.getElementById('graph-container');
    const newWidth = container.clientWidth;
    const newHeight = container.clientHeight;
    
    if (svg && (newWidth !== width || newHeight !== height)) {
        width = newWidth;
        height = newHeight;
        
        svg.attr('width', width).attr('height', height);
        
        if (simulation) {
            simulation.force('center', d3.forceCenter(width / 2, height / 2));
            simulation.alpha(0.3).restart();
        }
    }
});
