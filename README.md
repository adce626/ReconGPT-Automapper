# ReconGPT Automapper - The Smart Tool for Reconnaissance and Attack Surface Analysis

## Overview

ReconGPT Automapper is an advanced cybersecurity reconnaissance tool that combines traditional reconnaissance techniques with artificial intelligence to create an intelligent picture of a target's infrastructure and identify the most vulnerable attack points.

## Features

### 🎯 What the tool does:
- **Aggregates data** from well-known recon tools:
  - `amass` – for discovering subdomains
  - `subfinder` – for additional subdomain enumeration  
  - `httpx` – for scanning open protocols and ports
  - `nuclei` – for surface vulnerability analysis

- **AI-powered analysis** using GPT to:
  - Classify domains by importance and risk level
  - Detect suspicious patterns (e.g., dev, staging, admin, test)
  - Provide target prioritization
  - Generate actionable recommendations

- **Interactive attack surface mapping**:
  - Visual relationships between targets
  - Domain hierarchy and connections
  - Key touchpoints identification
  - Integration suggestions for complementary tools

### 🧠 AI Capabilities

| Function | Practical Example |
|----------|-------------------|
| Target classification | "This domain runs on Port 8080, without HTTPS → High risk." |
| Pattern detection | "The word 'internal' in internal.api.example.com indicates an internal environment → Test SSRF." |
| Relationship analysis | "login.example.com uses SSO linked to api.example.com ← Try Auth Bypass." |
| Complementary tools | "Run JSFlow AI on these domains to extract more API endpoints from JavaScript." |

### 🧾 Outputs

- Visual map showing domain structure, services, protocols, and critical points
- AI-generated intelligence report with smart recommendations  
- JSON, HTML, and TXT outputs for integration or documentation
- Prioritized attack lists with confidence scoring

## Installation

1. Clone the repository and install dependencies:
```bash
pip install -r requirements.txt
```

2. Set up your OpenAI API key:
```bash
export OPENAI_API_KEY="your-api-key-here"
```

3. (Optional) Install reconnaissance tools for full functionality:
```bash
# Install tools based on your OS
# amass, subfinder, httpx, nuclei
```

## Usage

### Basic Usage

```bash
python recongpt.py scan target.com
```

### Professional Red Team / Bug Bounty Examples

```bash
# Review AI analysis without applying automatically (professional workflow)
python recongpt.py scan target.com --ai-review-only --format html

# Filter for high-value targets (dev/admin/test domains)
python recongpt.py scan target.com --filter "domain~='dev|admin|test|staging'"

# Focus on unusual ports (not 80/443)
python recongpt.py scan target.com --filter "port!=443 && port!=80"

# Extended tool set for comprehensive reconnaissance
python recongpt.py scan target.com \
    --tools amass subfinder httpx nuclei dnsx waybackurls \
    --output ./results \
    --format json \
    --ai-review-only \
    --verbose

# Clean, professional HTML reports
python recongpt.py scan target.com --format html --output ./reports

# Integration-ready JSON output
python recongpt.py scan target.com --format json --output ./integration
```

### List Previous Scans

```bash
# List all scans
python recongpt.py list

# View specific scan details
python recongpt.py list --scan-id 1
```

## Command Options

### `scan` command:
- `DOMAIN` - Target domain to scan
- `--tools` - Specify tools to use (default: amass, subfinder, httpx, nuclei, dnsx, waybackurls)
- `--output` - Output directory for results  
- `--format` - Output format: json, html (optimized for integration and reporting)
- `--analyze/--no-analyze` - Enable/disable AI analysis (default: enabled)
- `--ai-review-only` - **NEW**: Run AI analysis for review only, don't apply automatically
- `--filter` - **NEW**: Smart filtering with syntax like `"port!=443 && domain~='dev|admin'"`
- `--show-graphs/--no-graphs` - Optional graph generation (disabled by default for CLI focus)
- `--verbose` - Enable verbose output

### Professional Filtering Examples:
```bash
--filter "domain~='dev|admin|test|staging'"    # High-value keywords
--filter "port!=443 && port!=80"               # Unusual ports only  
--filter "domain~='api' && port!=443"          # API endpoints without HTTPS
```

## Example Workflow

```bash
# 1. Run comprehensive scan
python recongpt.py scan target.com --output ./target_results --verbose

# 2. Review results
python recongpt.py list --scan-id 1

# 3. Generate different format reports
python recongpt.py scan target.com --format html --output ./reports
```

## Output Structure

### JSON Output
```json
{
  "scan_info": {
    "domain": "target.com",
    "scan_id": 1,
    "timestamp": "20240101_120000",
    "total_findings": 150
  },
  "findings": [...],
  "ai_analysis": {
    "overall_priority": 0.8,
    "confidence": 0.9,
    "high_priority_targets": [...],
    "recommendations": [...]
  }
}
```

### AI Analysis Features

- **Priority Scoring**: Automatic ranking of findings based on security impact
- **Pattern Recognition**: Identifies suspicious subdomain patterns (dev, admin, test, staging)
- **Relationship Mapping**: Discovers connections between services and domains
- **Risk Assessment**: Confidence scoring and actionable recommendations
- **Attack Path Analysis**: Suggests logical progression for security testing

## Professional Use Case

**Scenario**: You target `target.com`

1. **Run ReconGPT Automapper**:
   ```bash
   python recongpt.py scan target.com
   ```

2. **Get comprehensive results**:
   - 100+ subdomains discovered
   - Prioritized attack list with risk scores
   - Interactive attack surface map
   - AI-driven offensive recommendations

3. **Follow AI recommendations**:
   - Start with high-priority targets
   - Test identified vulnerability patterns
   - Investigate suspicious subdomain relationships

## Professional Integration Features

### Smart AI Assistant (Not Controller)
- **Review Mode**: `--ai-review-only` lets you review AI suggestions before applying
- **Intelligent Linking**: Detects SSRF risks between API and auth domains
- **Pattern Recognition**: Identifies suspicious keywords and port configurations
- **Confidence Scoring**: Provides confidence levels with all recommendations

### Advanced Filtering System
```bash
# Examples of professional filtering
--filter "domain~='dev|admin|test'"           # Development/admin interfaces
--filter "port!=443 && domain~='api'"         # Unencrypted API endpoints
--filter "domain~='staging|internal'"         # Internal staging environments
```

### Integration Examples (Displayed after each scan)
```bash
# Pipe high-priority targets to httpx
cat output.json | jq -r '.ai_analysis.high_priority_targets[]? | .target?' | httpx -silent

# Extract subdomains for nuclei scanning
cat output.json | jq -r '.findings[] | select(.type=="subdomain") | .target' | nuclei -silent

# Generate custom wordlists from patterns
cat output.json | jq -r '.findings[].target' | cut -d'.' -f1 | sort -u > wordlist.txt
```

### Tool Advantages for Red Team / Bug Bounty
- **CLI-focused**: No web interface security risks, perfect for headless environments
- **Lightweight HTML**: Clean reports without heavy JavaScript or graphics
- **Extended tool support**: amass, subfinder, httpx, nuclei, dnsx, waybackurls
- **Smart prioritization**: AI identifies unusual ports, suspicious patterns, potential SSRF
- **Integration-ready**: JSON output designed for piping to other tools

## Requirements

- Python 3.11+
- OpenAI API key (for AI analysis features)
- Optional: amass, subfinder, httpx, nuclei tools for full functionality

## License

Professional cybersecurity tool for authorized testing only.