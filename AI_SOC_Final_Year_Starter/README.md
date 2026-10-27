# AI-Powered SOC Threat Triage and Incident Response Assistant

A final-year B.Tech CSE starter project. It currently provides a Streamlit dashboard, CSV log ingestion, explainable rule-based severity assignment, basic event correlation, candidate IOC extraction, SQLite incident history, and CSV exports.

## Current status
- Implemented: dashboard, CSV upload and validation, rule-based detection, simple failed-then-successful login correlation, IOC pattern extraction, SQLite history, CSV export.
- Not implemented yet: real-time SIEM ingestion, trained ML model, LLM integration, RAG, verified threat-intelligence lookups, automatic blocking/isolation.

## Requirements
- Python 3.10+ recommended
- VS Code
- Internet access for initial package installation

## Windows setup (VS Code terminal)
```powershell
python --version
python -m venv .venv
.\.venv\Scripts\python.exe -m pip install -r requirements.txt
.\.venv\Scripts\python.exe -m streamlit run app.py
```
If the virtual environment is activated, you can instead use:
```powershell
python -m pip install -r requirements.txt
python -m streamlit run app.py
```
Open the local URL printed by Streamlit, usually http://localhost:8501.

## CSV input format
The CSV must contain these columns:
`timestamp,event_type,username,src_ip,host,details`

Use ISO timestamps, for example `2026-10-18T10:32:14Z`. Start by using `data/sample_logs.csv`.

## How to test
1. Launch the dashboard and verify the sample events appear.
2. Filter severity to Critical; simulated PowerShell and data-exfiltration events should appear.
3. Select an event in Investigate and check the detection rationale.
4. In IOC Extraction, verify IP-like values and `example.test` are shown as candidates.
5. Click **Save displayed events to incident history** and open Incident History.
6. Download the analyzed events CSV.
7. Upload a copy of the sample CSV with one event changed and verify the dashboard updates.

## Academic honesty and safe use
The included events are simulated. The project does not establish that a host or IP is malicious. Do not upload sensitive production logs without permission. Do not implement automatic blocking or host isolation until it is explicitly approved, tested in a lab, and protected with analyst confirmation.

## Suggested next milestones
1. Add unit tests for rules and correlation.
2. Add a documented MITRE ATT&CK mapping table with evidence and confidence.
3. Add an optional LLM explanation module that cites the log fields it used.
4. Add an evaluation dataset with labeled benign/suspicious events and report precision, recall, F1, and false-positive rate.
5. Add role-based access and audit logging if the project is deployed beyond a local demo.
