<p align="center">
  
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

```

# to use :
```text
python main.py
```
# OR
```text
Run the .exe in the ".EXE" file and if it’s not there, click on "build_GUI" and the .exe will exit into the DIST folder

