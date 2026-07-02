# SecureDoc AI - DLP & Compliance Analysis Platform

SecureDoc AI is an enterprise-grade Data Loss Prevention (DLP) platform. It detects sensitive information in uploaded documents, assesses compliance risks across major frameworks, generates security reports, and provides an interactive AI chatbot for document-based question answering.

---

## Table of Contents

- [Features](#features)
- [Technology Stack](#technology-stack)
- [Architecture](#architecture)
- [Installation](#installation)
- [Environment Variables](#environment-variables)
- [Running Locally](#running-locally)
- [Running with Docker](#running-with-docker)
- [Deployment](#deployment)
- [AI/ML Approach](#aiml-approach)
- [Project Structure](#project-structure)
- [Testing](#testing)

---

## Features

### Core Capabilities
- **Document Upload:** Support for PDF, TXT, and CSV formats.
- **Sensitive Data Detection:** Hybrid detection using Regex, NER, and LLMs to identify over 25 entity types.
- **Data Redaction:** Automatic masking of sensitive data (e.g., credit cards, PII) in uploaded documents.
- **OCR Support:** Fallback extraction using Tesseract for scanned PDFs or images.
- **Risk Assessment:** Weighted scoring system (0-100) categorizing risk into Low, Medium, High, and Critical.
- **Compliance Reports:** Automated reporting covering GDPR, HIPAA, PCI DSS, ISO 27001, SOC 2, and the DPDP Act.
- **Interactive Q&A:** RAG-powered chatbot for natural language document queries.
- **Exporting:** Download analysis results as JSON or CSV.

### Detected Entity Types
- **PII:** Aadhaar, PAN, Passport, Driving License, Employee ID, Customer ID, SSN
- **Contact:** Email, Phone, Physical Address
- **Financial:** Credit/Debit Card, Bank Account, IFSC, UPI ID
- **Auth Secrets:** Passwords, API Keys, JWT/OAuth Tokens, SSH Keys, AWS/Azure/GCP Credentials
- **Business:** Confidentiality Markers, Salary Info, Contract References

---

## Technology Stack

- **Frontend:** Streamlit, Plotly, Custom CSS
- **Backend:** Python 3.11+
- **AI/NLP:** Google Gemini API, spaCy, sentence-transformers
- **Detection Engine:** Custom Regex patterns, spaCy NER, LLM reasoning
- **Vector DB:** FAISS
- **Data Processing:** Pandas, pdfplumber, PyMuPDF, pytesseract, pdf2image
- **Testing:** pytest
- **Deployment:** Docker, Docker Compose

---

## Architecture

### Data Flow

1. **Document Upload:** Extracts text natively or falls back to OCR if the document is scanned.
2. **Sensitive Data Detection:** Runs text through Regex, spaCy NER, and Gemini LLM.
3. **Deduplication:** Aggregates and filters detected entities.
4. **Risk & Compliance:** Performs risk scoring and checks against compliance frameworks.
5. **Dashboard & RAG:** Generates reports, builds a FAISS index for Q&A, and displays results to the user.

---

## Installation

### Prerequisites

- Python 3.11+
- pip
- Google Gemini API key
- Tesseract OCR (Optional, required for local OCR support)

### Setup

```bash
# Clone the repository
git clone https://github.com/yourusername/securedoc-ai.git
cd securedoc-ai

# Create a virtual environment
python -m venv venv

# On Windows:
venv\Scripts\activate
# On macOS/Linux:
source venv/bin/activate

# Install dependencies
pip install -r requirements.txt

# Download spaCy language model
python -m spacy download en_core_web_sm

# Set up environment variables
cp .env.example .env
# Edit .env and add your GEMINI_API_KEY
```

---

## Environment Variables

Create a `.env` file in the project root:

| Variable | Required | Default | Description |
|----------|----------|---------|-------------|
| `GEMINI_API_KEY` | Yes | - | Google Gemini API key |
| `GEMINI_MODEL` | No | `gemini-2.0-flash` | Gemini model name |
| `GEMINI_TEMPERATURE` | No | `0.3` | AI response temperature |
| `GEMINI_MAX_TOKENS` | No | `4096` | Max AI response tokens |
| `MAX_FILE_SIZE_MB` | No | `50` | Max upload file size |
| `CHUNK_SIZE` | No | `512` | RAG chunk size (words) |
| `CHUNK_OVERLAP` | No | `64` | RAG chunk overlap |
| `EMBEDDING_MODEL` | No | `all-MiniLM-L6-v2` | Sentence embedding model |
| `LOG_LEVEL` | No | `INFO` | Logging level |

---

## Running Locally

```bash
streamlit run app.py
```
The application will open at http://localhost:8501.

---

## Running with Docker

```bash
docker-compose up --build
```
Access the application at http://localhost:8501.

---

## Deployment

### Streamlit Cloud / Render / Hugging Face Spaces
Ensure that the `GEMINI_API_KEY` is configured in the environment secrets of your chosen hosting platform. Add the spaCy model download command (`python -m spacy download en_core_web_sm`) to your build process.

---

## AI/ML Approach

### Sensitive Data Detection (Hybrid Pipeline)

The detection engine uses a three-layer approach:
1. **Regex Layer:** High-speed pattern matching with 25+ pre-compiled regular expressions covering government IDs, financial data, authentication secrets, and business markers.
2. **NER Layer:** spaCy's `en_core_web_sm` model extracts named entities that regex might miss.
3. **LLM Layer:** Google Gemini analyzes document text for contextual entities like internal project names or proprietary information.

### Risk Scoring Algorithm

A weighted penalty model computes the security score based on entity severity (Critical, High, Medium, Low) and category multipliers (Auth Secrets, Financial, Gov IDs, PII, Business).

### RAG (Retrieval-Augmented Generation)

For question answering, the document is chunked, embedded using `all-MiniLM-L6-v2`, and indexed with FAISS. User queries retrieve the top relevant chunks to feed into a Gemini prompt for accurate answers.

---

## Project Structure

```
securedoc-ai/
├── app.py                    # Main Streamlit application
├── config.py                 # Configuration management
├── requirements.txt          # Python dependencies
├── .env.example              # Environment variable template
├── Dockerfile                # Docker build file
├── docker-compose.yml        # Docker Compose configuration
├── README.md                 # Project documentation
│
├── services/                 # Core business logic
│   ├── parser.py             # Document parsing and OCR
│   ├── detector.py           # Sensitive data detection engine
│   ├── classifier.py         # Risk assessment
│   ├── compliance.py         # Compliance framework analysis
│   ├── summarizer.py         # AI report generation
│   └── rag.py                # RAG-based Q&A engine
│
├── models/                   # Data models
│   └── schemas.py            # Pydantic schemas & enums
│
├── utils/                    # Utilities
│   ├── patterns.py           # Regex patterns
│   └── helpers.py            # Text processing and masking
│
├── prompts/                  # AI prompt templates
│   └── templates.py          # Structured prompts for Gemini
│
└── tests/                    # Unit tests
```

---

## Testing

```bash
# Run all tests
python -m pytest tests/ -v

# Run with coverage
python -m pytest tests/ -v --cov=services --cov-report=term-missing
```

---

## License

This project is developed for educational and assessment purposes.
