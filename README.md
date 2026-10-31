# AdaptShield
### Adaptive Semantic Defense for LLM Prompt Injection Attacks

AdaptShield is a prototype security middleware designed to detect and mitigate prompt injection attacks targeting Large Language Model (LLM) applications.

It analyzes user prompts and uploaded documents before they reach an LLM, combining rule-based detection, semantic analysis, document inspection, and risk-based decision-making.

## Key Features

- **Direct Prompt Inspection:** Detects suspicious instructions and known prompt injection patterns.
- **Document Security Analysis:** Inspects uploaded documents for suspicious and hidden content.
- **Semantic Analysis:** Uses embedding-based analysis to identify potentially malicious instructions, including paraphrased attacks.
- **Intent Divergence Detection:** Evaluates whether document instructions conflict with the user's intended task.
- **Risk-Based Decisions:** Classifies inputs into SAFE, WARN, or BLOCK.
- **Multiple Interfaces:** Provides a browser-based interface and a native Windows desktop application.
- **LLM Integration:** Supports Groq API integration for LLM-powered functionality.

## System Architecture

AdaptShield uses a layered defense pipeline.

1. **Layer 1 – Direct Input Guard (`input_guard.py`)**
   - Examines user prompts.
   - Uses suspicious-pattern detection and semantic checks.
   - Produces the direct input risk score (R1).

2. **Layer 2A – Document Inspection (`document_engine/`)**
   - Parses uploaded documents.
   - Checks for suspicious or hidden document content.
   - Identifies techniques such as invisible text and concealed instructions.

3. **Layer 2B – Semantic Document Analysis (`document_analyzer.py`)**
   - Analyzes document instructions in context.
   - Checks for instruction overrides, concealment, and possible data-exfiltration intent.
   - Evaluates semantic risk and intent divergence (R2).

4. **Layer 3 – Unified Risk Scoring (`unified_scorer.py`)**
   - Combines the risk signals.
   - Produces the final SAFE, WARN, or BLOCK decision.
   - Applies high-confidence attack overrides.

5. **Application Layer (`server.py`)**
   - Coordinates the defense pipeline.
   - Provides API endpoints and serves the browser interface.

## Technology Stack

- **Language:** Python
- **Backend:** FastAPI, Uvicorn
- **Desktop Interface:** PySide6, Qt WebEngine
- **Browser Interface:** HTML, CSS, JavaScript
- **Semantic Analysis:** Sentence Transformers
- **Machine Learning:** Scikit-learn
- **Document Processing:** Python document-parsing libraries
- **Database:** SQLite
- **LLM Integration:** Groq API

## Project Structure

```text
AdaptShield/
│
├── server.py
├── desktop_app.py
├── input_guard.py
├── document_analyzer.py
├── embedding_engine.py
├── unified_scorer.py
├── keywords.py
│
├── document_engine/
│   ├── __init__.py
│   └── document_engine.py
│
├── static_app/
│   ├── index.html
│   ├── app.js
│   └── style.css
│
├── website/
│   ├── index.html
│   ├── app.js
│   └── style.css
│
├── scripts/
├── tests/
├── data/
├── requirements.txt
└── README.md
```

## Installation

### Prerequisites

- Windows 10/11 or a compatible Python environment
- Python 3.11
- Git
- Groq API key for LLM-powered functionality

### 1. Clone the repository

```bash
git clone https://github.com/anu1964/Adaptsheild.git
cd Adaptsheild
```

### 2. Create a virtual environment

```bash
python -m venv .venv
```

Activate it in Windows PowerShell:

```powershell
.\.venv\Scripts\Activate.ps1
```

### 3. Install dependencies

```bash
python -m pip install -r requirements.txt
```

### 4. Configure the Groq API key

Keep your API key private. Do not commit `config.env` to GitHub.

For the browser application, start the server and open:

```text
http://127.0.0.1:8000/setup
```

Configure the key through the setup interface. Alternatively, create a local `config.env` file in the project root:

```env
GROQ_API_KEY=your_actual_groq_api_key
```

Replace the placeholder with your own key.

## Running AdaptShield

### Option 1: Browser Application

Run:

```bash
python server.py
```

Open the local application:

```text
http://127.0.0.1:8000
```

The server uses FastAPI and Uvicorn.

### Option 2: Native Windows Desktop Application

Run:

```bash
python desktop_app.py
```

The desktop application embeds the existing interface using PySide6 and Qt WebEngine. It invokes the security backend directly and does not start a separate localhost HTTP server.

## Testing

Run the project tests using:

```bash
python -m pytest tests/ -v
```

The project also includes scripts for detection validation, document parsing, and result generation in the `scripts/` directory.

## Decision Categories

| Decision | Meaning |
|---|---|
| SAFE | No significant malicious indicators detected |
| WARN | Suspicious indicators require caution |
| BLOCK | High-risk or confirmed attack indicators detected |

## Security Considerations

- API keys and local configuration files must not be committed.
- Uploaded documents should be treated as untrusted input.
- Detection decisions are based on multiple signals and are not a guarantee of identifying every attack.
- AdaptShield is a research and academic prototype, not a production-certified security solution.

## Project Objective

The objective of AdaptShield is to explore a layered, model-agnostic approach to defending LLM applications against prompt injection attacks by analyzing both direct user inputs and potentially malicious instructions embedded in external documents.

---

**AdaptShield – Securing LLM Interactions Through Adaptive, Layered Defense.**