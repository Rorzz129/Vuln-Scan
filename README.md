# A.C.R Vuln

<p align="center">

  <img src="https://img.shields.io/badge/version-V8-111111?style=for-the-badge" />
  <img src="https://img.shields.io/badge/Python-3.11+-111111?style=for-the-badge&logo=python&logoColor=white" />
  <img src="https://img.shields.io/badge/PySide6-Desktop-111111?style=for-the-badge" />
  <img src="https://img.shields.io/badge/Status-Active-111111?style=for-the-badge" />

</p>

<p align="center">
  <strong>Map the attack surface. Understand the technology. Correlate the evidence.</strong>
</p>

<p align="center">
  A modular vulnerability analysis platform designed around reconnaissance,
  evidence correlation and practical pentest workflows.
</p>

---

## About

A.C.R Vuln is a desktop vulnerability analysis platform built to transform
raw reconnaissance data into structured security intelligence.

Instead of treating every detected service, technology or endpoint as an
isolated result, A.C.R Vuln connects information across the entire scan.

```text
                    TARGET
                       │
                       ▼
                ASSET DISCOVERY
                       │
             ┌─────────┴─────────┐
             ▼                   ▼
           DNS                SERVICES
             │                   │
             └─────────┬─────────┘
                       ▼
                  HTTP ANALYSIS
                       │
          ┌────────────┼────────────┐
          ▼            ▼            ▼
       CRAWLER        JS/API       TLS
          │            │            │
          └────────────┼────────────┘
                       ▼
              TECHNOLOGY INTEL
                       │
                       ▼
                 CPE RESOLUTION
                       │
                       ▼
                CVE CORRELATION
                       │
                       ▼
                FINDING ENGINE
                       │
                       ▼
             VERIFICATION / RISK
                       │
                       ▼
                 PENTEST REPORT

The objective is simple:

discover more, correlate better, report only what the evidence supports.

Core capabilities
Asset Discovery

Build a structured view of the target's exposed surface.

DNS enumeration
A / AAAA / MX / NS / TXT / CNAME
service discovery
port enumeration
HTTP services
exposed application surfaces
scope-aware discovery
asset classification
Web Analysis

A.C.R Vuln analyzes the HTTP layer before attempting deeper checks.

HTTP status analysis
security headers
cookies
CORS
HTTP methods
transport configuration
sensitive paths
exposed files
application metadata
server disclosure
Endpoint Intelligence

Discovered URLs are not treated equally.

The scanner attempts to classify application surfaces such as:

/api
/api/v1
/api/v2
/admin
/login
/auth
/graphql
/upload
/websocket

Endpoints can then be connected with:

technologies
parameters
forms
JavaScript references
API information
security findings
JavaScript Analysis

Modern applications expose a large amount of information through client-side JavaScript.

A.C.R Vuln can inspect discovered JavaScript resources for useful intelligence such as:

API routes
Endpoints
Parameters
WebSocket references
Technology indicators
Source map references

This information can feed the endpoint and API analysis pipeline.

API Intelligence

Automatic identification of common API surfaces:

REST-style endpoints
GraphQL
OpenAPI / Swagger references
API paths
HTTP methods
parameters
exposed API documentation

The goal is to produce an application map rather than simply report that an endpoint exists.

Technology Intelligence

Technology detection combines multiple pieces of evidence.

Nmap
Headers
HTML
Cookies
JavaScript
Service banners
Application signatures

Each technology can receive:

Identity
Version
Confidence
Intel Score
Version Confidence
Sources
Aliases
Evidence

This distinction is important because:

Detecting a product is not the same thing as reliably identifying its version.

CPE / CVE Intelligence

One of the main components of A.C.R Vuln is the vulnerability correlation pipeline.

Detected technology
        │
        ▼
Evidence collection
        │
        ▼
Identity normalization
        │
        ▼
Version confidence
        │
        ▼
CPE resolution
        │
        ▼
Version range matching
        │
        ▼
CVE applicability

The scanner attempts to avoid blindly associating CVEs based only on product names.

CVE results can therefore be evaluated against:

vendor identity
product identity
aliases
detected version
version ranges
CPE evidence
detection confidence
applicability evidence
Finding Verification

Every result is not automatically treated as a confirmed vulnerability.

A.C.R Vuln separates findings into verification states:

State	Meaning
CONFIRMED	Strong evidence confirms the issue
LIKELY	Evidence strongly suggests the issue
DETECTED	An indicator was detected
FALSE_POSITIVE	Evidence suggests the result is invalid

This makes the final result easier to interpret during manual assessment.

Risk & Priority

The scanner calculates a priority based on multiple signals instead of relying only on severity.

Severity
Confidence
Verification
Exposure
Reachability
Evidence quality
CVE applicability
        │
        ▼
Priority Engine
        │
        ▼
P1 ─ Critical
P2 ─ High
P3 ─ Medium
P4 ─ Low

Example:

P1
Score: 93/100

CONFIRMED
HIGH confidence
Publicly reachable
Applicable vulnerability
Strong evidence
Template Engine

A.C.R Vuln uses a modular template system for extensible security checks.

Templates can define:

requests
paths
matchers
AND / OR conditions
extractors
technology requirements
HTTP status requirements
severity
confidence
recommendations

Templates are designed to be readable and easy to extend.

Example:

id: example-check

info:
  name: Example Security Check
  severity: medium
  confidence: high

conditions:
  technologies:
    - ExampleTechnology

requests:
  - method: GET
    path: /example

matchers:
  condition: AND

  items:
    - type: status
      value: 200

    - type: word
      words:
        - example
Scope Engine

Scanning should respect the intended target.

The scope system supports concepts such as:

Root domain
Subdomains
IP addresses
CIDR ranges
Allowed assets
Excluded assets

Out-of-scope requests can be blocked automatically.

This is particularly useful for larger authorized assessments.

Scan Profiles

Three profiles are available:

FAST
│
└── Quick reconnaissance

NORMAL
│
└── Balanced analysis

DEEP
│
└── Extended analysis

The scanner adjusts the amount of analysis performed according to the selected profile.

Cache & Resume

Long scans should not need to restart from zero.

A.C.R Vuln includes infrastructure for:

HTTP caching
DNS caching
CVE result reuse
scan state persistence
interrupted scan recovery
project history

This reduces unnecessary requests and improves repeatability.

TLS Intelligence

TLS analysis can provide information about:

certificate
expiration
SAN entries
certificate metadata
TLS versions
cipher configuration
transport issues

TLS findings can then be incorporated into the global result model.

Correlation Engine

The main difference between a simple scanner and an analysis platform is correlation.

Example:

/api/v2/users
       │
       ├── REST API
       │
       ├── Parameter discovered
       │
       ├── Technology: Example Framework
       │
       ├── Version: 4.2.x
       │
       ├── CPE matched
       │
       └── CVE candidate
                │
                ▼
         Finding Correlation
                │
                ▼
           Risk Priority

Instead of producing hundreds of disconnected lines,
A.C.R Vuln attempts to explain how the discovered information is related.

Pentest Reporting

Reports are designed to be useful after the scan has finished.

A report can contain:

Executive Summary
Methodology
Target Scope
Attack Surface
Assets
Technologies
Endpoints
Findings
CVE / CPE Information
Evidence
Risk Assessment
Remediation
Technical Appendix

The goal is to turn scanner output into something that can actually be reviewed during an assessment.

Desktop Interface

A.C.R Vuln uses PySide6 for its graphical interface.

The interface is intentionally divided into a small number of primary sections rather than creating a huge navigation tree.

Dashboard
New Scan
Results
Project
Settings

Advanced information is displayed inside the relevant result views.

The design focuses on:

dark UI
compact information density
readable severity indicators
consistent panels
structured result views
minimal visual noise
Architecture

A.C.R Vuln is designed as a modular system.

acr-vuln/
│
├── analysis/
│   ├── correlation
│   ├── endpoint intelligence
│   ├── javascript analysis
│   ├── priority engine
│   └── verification
│
├── assets/
│   ├── discovery
│   └── scope
│
├── cve/
│   ├── CPE resolver
│   ├── CVE engine
│   └── range matching
│
├── scanners/
│   ├── DNS
│   ├── HTTP
│   ├── Nmap
│   └── TLS
│
├── templates/
│
├── reports/
│
├── gui/
│
└── main.pyw

The important principle is that modules exchange structured data rather than operating as isolated scanners.

Data Flow
Asset Discovery
      ↓
HTTP Crawler
      ↓
Endpoint Intelligence
      ↓
JavaScript / API Analysis
      ↓
Technology Intelligence
      ↓
Template Selection
      ↓
CPE / CVE Intelligence
      ↓
Finding Verification
      ↓
Correlation
      ↓
Priority
      ↓
Report

This architecture makes it possible to progressively improve individual modules without rebuilding the entire application.

Installation
Requirements
Python 3.11+
Nmap
Windows / Linux / macOS

Install Python dependencies:

pip install -r requirements-gui.txt

Run:

python main.pyw
Responsible Use

A.C.R Vuln is intended for:

authorized penetration tests
security research
laboratory environments
CTFs
systems you own
systems for which you have explicit permission to test

Do not scan systems without authorization.

The tool is designed primarily around reconnaissance, analysis and safe security checks.
