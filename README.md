# 🛡️ Spam Buster — AI Powered Scam & Fraud Detector

An intelligent scam-detection assistant built with **Python**, **LangChain**, and **OpenRouter AI**, featuring a dark cyber-fintech dashboard with real-time risk gauges and forensic fraud breakdown.

---

## ✨ Features

- **Multi-Vector Threat Detection**: Identifies bank KYC phishing, WhatsApp lottery traps, Telegram job deposit scams, courier delivery fees, and credential theft.
- **Dynamic Circular Risk Gauge**: 
  - 🟢 **Low Risk (0–34)**: Safe messages, legitimate receipts, and OTPs.
  - 🟡 **Medium Risk (35–69)**: Suspicious links and unverified outreach.
  - 🔴 **High Risk (70–100)**: Malicious phishing and advance-fee coercion.
- **Deep Forensic Breakdown**:
  - 🎯 **Detected Message Intent**
  - 📋 **AI Fraud Assessment Summary**
  - 🔍 **Detected Warning Signs & Quoted Evidence**
  - 🛡️ **Positive / Neutral Indicators**
  - 📄 **4-Point Technical Signals**
- **Persistence & History**: Local SQLite database storage with search, category filtering, and detailed inspection modal.
- **Export Capabilities**: Instant Markdown report copying and raw JSON export.

---

## 🚀 Quick Start

### 1. Prerequisites
- Python 3.10+
- OpenRouter API Key ([Get a key](https://openrouter.ai/keys))

### 2. Installation
```bash
git clone https://github.com/shaikshabreen04/scamshield-agent.git
cd scamshield-agent

# Create and activate virtual environment
python -m venv .venv
# Windows:
.\.venv\Scripts\activate
# macOS/Linux:
source .venv/bin/activate

# Install dependencies
pip install langchain langchain-openai python-dotenv
```

### 3. Configure API Key
Create a `.env` file in the project root:
```env
OPENROUTER_API_KEY=your_openrouter_api_key_here
```

### 4. Run Application
```bash
python server.py
```
Open **`http://localhost:5000`** in your browser.

---

## 📁 Project Structure

```
scamshield-agent/
├── agent.py               # LangChain AI agent with structured forensic prompts
├── server.py              # Lightweight REST bridge & SQLite database persistence
├── scam_history.db        # SQLite database storing scan results
├── frontend/
│   ├── index.html         # Cyber-fintech dashboard & navigation views
│   ├── styles.css         # Styling, circular risk gauges, and neon glows
│   ├── app.js             # Client logic, live API bridge, and dynamic rendering
│   └── assets/            # Hero artwork and badge icons
├── .env.example           # Example configuration template
└── README.md              # Project documentation
```
