# Final-Year Project Report Outline

## Proposed title
AI-Powered SOC Threat Triage and Incident Response Assistant

## 1. Abstract
Security Operations Center analysts review large volumes of security events and need to prioritize suspicious activity quickly. This project proposes a dashboard that ingests structured security logs, applies explainable detection rules, correlates selected authentication events, extracts candidate indicators of compromise, and stores investigation records. The current prototype uses simulated data and is designed to be extended with AI-generated explanations and controlled response workflows. Its performance must be evaluated against labeled test data before making claims about detection effectiveness.

## 2. Problem statement
Manual review of separate security logs can make it difficult to connect related events and prioritize investigations. A lightweight tool is needed to normalize log records, identify configured suspicious patterns, provide transparent reasons for alerts, and produce reusable incident records.

## 3. Objectives
- Import and validate structured security logs.
- Apply explainable detection rules and simple event correlation.
- Assign preliminary severity levels with reasons.
- Extract candidate IP addresses, domains, and hashes.
- Store investigation records locally in SQLite.
- Export analyzed events for review.
- Evaluate the system using labeled test cases.

## 4. Scope and limitations
The initial version is a local prototype using simulated or authorized CSV logs. It is not a production SIEM, does not prove maliciousness from an IOC pattern alone, and does not automatically block addresses or isolate systems. AI, RAG, and ML are future extensions unless implemented and evaluated separately.

## 5. Proposed architecture
CSV / authorized lab logs -> validation and normalization -> rule-based detection and correlation -> severity and rationale -> IOC extraction -> dashboard / SQLite history / CSV export -> analyst review.

## 6. Modules
1. Log ingestion and validation
2. Detection rules and event correlation
3. Severity and rationale generation
4. IOC extraction
5. Incident history database
6. Dashboard and reporting
7. Future AI explanation module

## 7. Methodology
Describe the input schema, rules, correlation assumptions, severity logic, IOC regex patterns, database schema, and user workflow. Document every rule so another student can reproduce the results.

## 8. Testing and evaluation
Create a labeled dataset of benign and suspicious events. Report true positives, false positives, true negatives, and false negatives. Calculate precision, recall, F1 score, and false-positive rate. Measure processing time on a stated dataset size. Do not claim a metric until it has been measured.

## 9. Security, privacy, and ethics
Use only authorized logs. Remove credentials, personal information, and secrets from test data. Treat extracted IPs/domains as candidate indicators, not proof of maliciousness. Keep response actions manual and analyst-approved in the prototype.

## 10. Future work
- Add MITRE ATT&CK mapping with evidence and confidence.
- Add optional LLM explanations that refer to the exact log evidence.
- Add RAG over trusted security documentation.
- Add authorized lab sources such as exported Windows/Linux logs or packet-analysis summaries.
- Add role-based access, audit records, and safe analyst-approved response integrations.

## 11. Conclusion
Summarize implemented functions, measured test results, limitations, and future extensions. Clearly distinguish completed features from proposed features.
