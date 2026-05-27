# MalvAI Analyzer: GenAI-Powered End-to-End Fraudulent APK Analysis Platform

MalvAI Analyzer is an advanced, automated, and end-to-end security analysis system designed to deconstruct, analyze, and report on fraudulent Android applications (APKs) using a hybrid approach of traditional reverse-engineering tools and **Google's Gemini API** as the core GenAI backbone.

Unlike standard rule-based scanners or basic ML tabular classifiers, MalvAI Analyzer serves as an automated AI-reverse engineer. It extracts structural blueprints, bytecode, and network signatures from unknown APKs, correlates them with global threat intelligence via Retrieval-Augmented Generation (RAG), and uses **Gemini's** advanced code interpretation capabilities to explain *exactly* what malicious code sections do in plain, actionable human language.

---

## 🚀 Key Differentiators & Why This Wins

1. **True GenAI Centricity:** Instead of bolting on an LLM as a superficial chatbot, MalvAI integrates **Google Gemini** directly into the core analysis pipeline—interpreting decompiled Smali/Java code, translating obfuscated control flows, and drafting high-fidelity risk assessments.

2. **Visceral Demo Story:** A highly interactive frontend dashboard allows judges and users to upload a live malicious APK and watch a real-time asynchronous pipeline disassemble the app, flag runtime risks, and stream a comprehensive AI threat analysis report.

3. **Defense-in-Depth Pipeline:** Combines industry-standard static analysis, dynamic sandboxing, and runtime instrumentation into a unified asynchronous orchestrator.

---

## 🛠️ System Architecture & Tech Stack

```
                     ┌────────────────────────────────────────────────────────┐
                     │                   React / Next.js UI                   │
                     └───────────────────────────┬────────────────────────────┘
                                                 │ (Upload APK / Event Stream)
                                                 ▼
                     ┌────────────────────────────────────────────────────────┐
                     │                Python FastAPI Backend                  │
                     └───────────────────────────┬────────────────────────────┘
                                                 │
                                  ┌──────────────┴──────────────┐
                                  ▼ (Broker)                    ▼ (Cache)
                           ┌──────────────┐              ┌──────────────┐
                           │    Redis     │              │ PostgreSQL / │
                           └──────┬───────┘              │  Vector DB   │
                                  │                      └──────────────┘
                                  ▼
                     ┌────────────────────────────────────────────────────────┐
                     │             Celery Async Worker Cluster                │
                     └────┬──────────────────────┬───────────────────────┬────┘
                          │                      │                       │
                          ▼ (Static Engine)      ▼ (Dynamic Engine)      ▼ (GenAI Layer)
                    ┌───────────────────┐  ┌───────────────────┐   ┌─────────────────────────┐
                    │ • APKTool / Jadx  │  │ • Android Emulator│   │ • Gemini Code Interp.   │
                    │ • MobSF (Core)    │  │ • Frida Hooking   │   │ • RAG (CVE / Mitre ATT) │
                    │ • YARA Signatures │  │ • Tcpdump PCAP    │   │ • WeasyPrint PDF Gen    │
                    └───────────────────┘  └───────────────────┘   └─────────────────────────┘
```

### 📦 Components Breakdown

* **Frontend Dashboard:** Built with **React / Next.js**, **TailwindCSS**, and **Shadcn/ui**. Displays real-time analysis logs, risk scoring rings, interactive call graphs, and a comprehensive, sectioned AI analysis page.

* **Backend Orchestrator:** **FastAPI** manages file ingestion, WebSocket connections for live progress streaming, and metadata management.

* **Asynchronous Processing:** **Celery** backed by **Redis** handles long-running analysis pipelines to avoid request timeouts during reverse engineering.

* **Static Analysis Engine:**
    * `APKTool` & `Jadx` for structural extraction and decompilation to Java/Smali.
    * `MobSF` (integrated via API/CLI) for rapid extraction of hardcoded API keys, permissions, and broadcast receivers.
    * `YARA` rules to identify pre-existing signatures of known malware families.

* **Dynamic Analysis Sandbox:**
    * Android Virtual Device (AVD) / Genymotion running inside a sandboxed environment.
    * `Frida` scripts to intercept encryption APIs, root-detection bypasses, and SSL pinning.
    * `Tcpdump` to capture network traffic (`.pcap`), identifying remote Command & Control (C2) servers.

* **GenAI Layer & RAG Engine:**
    * **`Google Gemini 2.5 Flash`** API acts as the expert reverse engineer, leveraging its massive context window for analyzing large decompiled codebases in a single pass.
    * `ChromaDB` / `Qdrant` vector database storing embedded entries of **CVE Databases**, **MITRE ATT&CK mobile frameworks**, and known Android threat feeds. Embeddings generated via **Gemini's `text-embedding-004` model**.
    * `WeasyPrint` for converting structured JSON evaluation payloads into publication-grade executive PDF threat reports.

---

## 📋 Directory Structure

```text
malvai-analyzer/
├── .github/workflows/       # CI/CD Automated Pipelines
├── backend/                 # FastAPI Application Core
│   ├── app/
│   │   ├── api/             # V1 Endpoints (auth, analysis, reports)
│   │   ├── core/            # Configs, Security, Celery Inits
│   │   ├── db/              # Postgres Models & Vector DB Connectors
│   │   ├── engines/         # Underlying Analysis Connectors
│   │   │   ├── static.py    # Jadx/YARA orchestrator
│   │   │   ├── dynamic.py   # Frida/Emulator runtime controller
│   │   │   └── genai.py     # Gemini Code Interpreter & RAG Pipeline
│   │   ├── tasks/           # Celery Async Tasks
│   │   └── templates/       # HTML templates for WeasyPrint PDF generation
│   ├── Dockerfile
│   └── requirements.txt
├── frontend/                # Next.js Dashboard Client
│   ├── src/
│   │   ├── components/      # UI Cards, Progress Bars, Report Views
│   │   ├── pages/           # Upload Panel, Dashboard Overview, Report View
│   │   └── utils/           # WebSockets & API hooks
│   ├── Dockerfile
│   └── package.json
├── sandbox/                 # Dynamic Analysis Sandbox Utilities
│   ├── frida_hooks/         # Custom JavaScript hooks for API interception
│   ├── yara_rules/          # Custom malware signature definitions
│   └── setup_emulator.sh    # Emulator initialization & config script
├── docker-compose.yml       # Full application multi-container stack orchestration
└── README.md                # Project documentation
```

---

## ⚡ Execution Pipeline

```text
[APK Upload] ──> [Celery Task Created]
                      │
                      ├──> [1. Static Analysis]
                      │     ├── Decompile source code via Jadx
                      │     ├── Scan permissions & run YARA rules
                      │     └── Extract suspicious code blocks & string constants
                      │
                      ├──> [2. Dynamic Analysis]
                      │     ├── Spin up sandboxed Android Emulator
                      │     ├── Install APK & inject Frida instrumentation hooks
                      │     ├── Capture runtime file access & SMS read attempts
                      │     └── Log network traffic (.pcap)
                      │
                      └──> [3. GenAI Contextualization Engine (Gemini)]
                            ├── Query Vector DB (RAG) for CVEs / MITRE patterns
                            ├── Generate embeddings via Gemini text-embedding-004
                            ├── Pass decompiled code chunks + runtime logs to Gemini 2.5 Flash
                            ├── Gemini synthesizes behavior & drafts human-readable summaries
                            └── Compile unified JSON -> Export PDF report via WeasyPrint
```

---

## 🛠️ Local Setup & Installation

### Prerequisites

* Docker & Docker Compose
* Python 3.10+
* Android SDK (for local emulator access, if running outside dockerized dynamic environments)
* **Google Gemini API Key** — Obtain from [Google AI Studio](https://aistudio.google.com/apikey)

### Configuration Environment

Create a `.env` file within the `backend/` directory:

```env
GEMINI_API_KEY=AIzaSy...
DATABASE_URL=postgresql://user:password@db:5432/malvai
REDIS_URL=redis://redis:6379/0
VECTOR_DB_URL=http://chroma:8000
EMULATOR_HOST=localhost:5555
```

### Spin up the Entire Stack

Using Docker Compose, you can launch the database, caching layers, backend workers, and web frontend concurrently:

```bash
# Clone the repository
git clone https://github.com/SairajTripathy-0077/BOI-Hackathon.git
cd BOI-Hackathon

# Boot up the multi-container stack
docker-compose up --build
```

Once the containers finish building and boot up:

* **Frontend Dashboard:** Available at `http://localhost:3000`
* **FastAPI Interactive Swagger Docs:** Available at `http://localhost:8000/docs`

---

## 🔍 Core Focus: The GenAI Advantage

Traditional analysis stops at showing an engineer a line of cryptic decompiled assembly/smali code like:

```smali
invoke-virtual {v0, v1, v2}, Landroid/telephony/SmsManager;->sendTextMessage(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Landroid/app/PendingIntent;Landroid/app/PendingIntent;)V
```

**MalvAI's Gemini-Powered GenAI Layer transforms this into:**

> ⚠️ **Critical Threat Detected:** This application contains hidden routines attempting to silently transmit SMS messages without user consent. The code targeted at line `0x3F2` specifically pulls the address `C2_SERVER_IP` from your dynamic network log, posing a severe financial fraud risk by potentially subscribing the user to premium-rate messaging services. (Matches **MITRE Mobile T1448 - Exfiltration Over Alternative Channel**).

---

## 🤖 Why Gemini?

| Feature | Benefit for MalvAI |
|---|---|
| **1M+ Token Context Window** | Analyze entire decompiled APK codebases in a single pass without chunking or context loss |
| **Native Code Understanding** | Superior comprehension of Java, Smali, and obfuscated bytecode patterns |
| **Multimodal Capabilities** | Process screenshots, network flow diagrams, and code simultaneously for richer threat context |
| **`text-embedding-004`** | High-quality embeddings for the RAG pipeline, improving CVE/MITRE ATT&CK retrieval accuracy |
| **Cost-Effective at Scale** | Gemini 2.5 Flash delivers strong reasoning at significantly lower cost per token vs. alternatives |
| **Google Cloud Ecosystem** | Seamless integration with Vertex AI, Cloud Run, and GKE for production deployment |

---

## 📄 License

Distributed under the MIT License. See `LICENSE` for more information.
