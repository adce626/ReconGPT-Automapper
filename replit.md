# ReconGPT - AI-Powered Cybersecurity Reconnaissance Tool

## Overview

ReconGPT Automapper is a professional CLI-based cybersecurity reconnaissance tool that combines multiple reconnaissance tools (Amass, Subfinder, HTTPx, Nuclei) with AI-powered analysis using OpenAI's GPT-4o model. The tool focuses on professional penetration testing workflows, providing intelligent attack surface analysis, target prioritization, and actionable security recommendations through a clean command-line interface.

## User Preferences

Preferred communication style: Simple, everyday language.
Tool preference: CLI-based tool for professional use, avoiding web interface complexity and security risks.
Focus: Professional penetration testing workflows with direct tool integration.
Interface requirements: Minimize reliance on complex GUIs, focus on excellent CLI experience with clear outputs (HTML and JSON only).
AI role: AI as assistant, not controller - let it suggest, classify, and recommend but users must have option to review/modify analysis.
Filtering: Smart filtering for results with unusual ports, no HTTPS, keywords like admin/dev/test/internal.
Integration: Easy integration with other tools, pipeable JSON outputs for httpx, nuclei, custom scripts.
Reports: Clean, lightweight HTML reports without excessive graphics or heavy JavaScript.

## System Architecture

The application follows a traditional Flask web application architecture with the following key components:

### Frontend Architecture
- **Web Interface**: Flask templates with Bootstrap dark theme and Font Awesome icons
- **Interactive Visualizations**: D3.js for network graph visualizations of attack surfaces
- **Responsive Design**: Bootstrap-based responsive UI with dark theme support
- **Real-time Updates**: JavaScript-based auto-refresh for active scans

### Backend Architecture
- **Web Framework**: Flask with SQLAlchemy ORM
- **Database**: SQLite (default) with support for PostgreSQL via DATABASE_URL environment variable
- **CLI Interface**: Click-based command-line interface with Rich for enhanced output formatting
- **Tool Integration**: Subprocess-based execution of external reconnaissance tools

### Core Components
- **Reconnaissance Engine**: Orchestrates multiple security tools (Amass, Subfinder, HTTPx, Nuclei)
- **AI Analysis Engine**: OpenAI GPT-4o integration for intelligent finding prioritization
- **Graph Builder**: NetworkX-based relationship mapping and D3.js visualization
- **Data Parsers**: Tool-specific output parsers for normalizing findings

## Key Components

### Database Models
- **ReconScan**: Stores scan metadata, status, and relationships
- **Finding**: Individual discoveries from reconnaissance tools with JSON data storage
- **AIAnalysis**: AI-generated insights, priorities, and recommendations

### Reconnaissance Tools Integration
- **Amass**: Subdomain enumeration with JSON output parsing
- **Subfinder**: Additional subdomain discovery
- **HTTPx**: HTTP service discovery and analysis
- **Nuclei**: Vulnerability scanning and detection

### AI-Powered Analysis
- **Priority Scoring**: Automatic ranking of findings based on security impact
- **Relationship Analysis**: Identifying connections between discovered assets
- **Risk Assessment**: Confidence scoring and actionable recommendations

### Graph Visualization
- **Interactive Network Graphs**: D3.js-based visualization of asset relationships
- **Node Types**: Domains, subdomains, services, vulnerabilities, technologies
- **Filtering and Navigation**: Real-time filtering and zoom/pan capabilities

## Data Flow

1. **Scan Initiation**: User creates scan via web interface or CLI
2. **Tool Execution**: ReconEngine runs selected tools against target
3. **Data Parsing**: Tool outputs are parsed and normalized into Finding objects
4. **Database Storage**: Findings are stored with JSON metadata
5. **AI Analysis**: Optional GPT-4o analysis for prioritization and insights
6. **Visualization**: Graph builder creates interactive relationship maps
7. **Reporting**: Results presented through web dashboard or CLI output

## External Dependencies

### AI Services
- **OpenAI API**: GPT-4o model for intelligent analysis (requires OPENAI_API_KEY)
- **Fallback Mode**: Mock analysis when API key unavailable

### Security Tools
- **Amass**: Subdomain enumeration (external binary)
- **Subfinder**: Subdomain discovery (external binary)
- **HTTPx**: HTTP service probing (external binary)
- **Nuclei**: Vulnerability scanning (external binary)

### Python Libraries
- **Flask/SQLAlchemy**: Web framework and ORM
- **Click/Rich**: CLI interface and enhanced terminal output
- **NetworkX**: Graph algorithms and data structures
- **OpenAI**: Official OpenAI Python client

### Frontend Libraries
- **Bootstrap**: UI framework with dark theme
- **D3.js**: Data visualization and interactive graphs
- **Font Awesome**: Icon library

## Deployment Strategy

### Environment Configuration
- **SESSION_SECRET**: Flask session security (defaults to development key)
- **DATABASE_URL**: Database connection string (defaults to SQLite)
- **OPENAI_API_KEY**: Required for AI analysis features

### Database Setup
- **Automatic Migration**: Tables created automatically on startup
- **SQLite Default**: File-based database for development
- **PostgreSQL Support**: Production-ready with proper DATABASE_URL

### Tool Dependencies
- External reconnaissance tools must be installed and available in system PATH
- CLI interface provides feedback for missing tools
- Web interface handles tool failures gracefully

### Scalability Considerations
- **Database Pooling**: Configured connection pooling for production
- **Session Management**: Secure session handling with configurable secrets
- **Proxy Support**: ProxyFix middleware for deployment behind reverse proxies

The architecture emphasizes modularity, allowing components to function independently while providing rich integration when all services are available. The system gracefully degrades when external dependencies (AI API, tools) are unavailable.