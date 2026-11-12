\# 🛡️ Cyber Shield AI



\*\*AI-powered suspicious URL detection and blocking system using Machine Learning, heuristic analysis, and optional threat intelligence.\*\*



Cyber Shield AI is a cybersecurity project designed to analyze URLs and identify potentially malicious or phishing links before a user accesses them. The system combines a trained Machine Learning model with rule-based security heuristics and optional VirusTotal threat intelligence.



\---



\## 🚀 Key Features



\- 🤖 Machine Learning URL Classification

\- 🔍 Heuristic-based phishing detection

\- 🧠 Combined risk scoring

\- 🚫 Automatic blocking of high-risk URLs

\- 📊 Scan history and statistics dashboard

\- 🌐 Web-based interface using Flask

\- 🛡️ Optional VirusTotal threat intelligence

\- ⚡ Windows standalone executable support

\- 📈 Model evaluation and testing scripts



\---



\## 🧠 How It Works



Cyber Shield AI uses multiple detection layers:



```text

&#x20;                   User enters URL

&#x20;                          │

&#x20;                          ▼

&#x20;                ┌──────────────────┐

&#x20;                │ URL Feature       │

&#x20;                │ Extraction        │

&#x20;                └────────┬─────────┘

&#x20;                         │

&#x20;            ┌────────────┼────────────┐

&#x20;            ▼            ▼            ▼

&#x20;       Machine       Heuristic     Threat

&#x20;       Learning      Analysis      Intelligence

&#x20;            │            │            │

&#x20;            └────────────┼────────────┘

&#x20;                         ▼

&#x20;                 Risk Score Engine

&#x20;                         │

&#x20;             ┌───────────┼───────────┐

&#x20;             ▼           ▼           ▼

&#x20;           SAFE       WARNING     SUSPICIOUS

&#x20;                                     │

&#x20;                                     ▼

&#x20;                                   BLOCK

