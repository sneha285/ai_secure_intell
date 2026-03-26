# AI Secure Data Intelligence Platform

This repository provides a modular backend (FastAPI) and frontend (React / Vite) for log analysis + risk detection.

## Features

- `POST /analyze` endpoint supports:
  - `text`, `file`, `sql`, `chat`, `log`
- line-by-line log analyzer + regex detection
- optional AI insights (OpenAI key)
- risk levels: `low`, `medium`, `high`, `critical`
- policy engine for `action: allowed | masked | blocked`
- frontend file upload + line viewer + insights panel

---

## Prerequisites

- Python 3.10+
- Node.js 18+ (or latest LTS)
- npm (bundled with Node)
- Git (optional)

---
## Frontend Setup

The frontend is a React + Vite application that provides a user-friendly interface for the AI Secure Data Intelligence Platform.

### Prerequisites

- Node.js 18+ (or latest LTS)
- npm (bundled with Node.js)

### Installation

1. Navigate to the frontend directory:
   ```powershell
   cd c:\Users\user_name\Desktop\ai_secure_intell\frontend
   npm run build
   npm run preview
   
## Backend Setup

1. Open terminal:
   - `cd c:\Users\user_name\Desktop\ai_secure_intell\backend`

2. Install dependencies:
   - `pip install -r requirements.txt`

3. Optional: set OpenAI key for AI insights
   - Windows PowerShell (current session):
     - `$Env:OPENAI_API_KEY="your_key_here"`
   - Windows PowerShell (persistent):
     - `setx OPENAI_API_KEY "your_key_here"`

4. Start server:
   - `uvicorn app.main:app --host 0.0.0.0 --port 8000 --reload`

5. Verify in browser:
   - `http://localhost:8000/docs` (Swagger UI)
   - `http://localhost:8000/redoc` (alternative docs)

### Test API with curl

```powershell
curl -X POST "http://localhost:8000/analyze" -H "Content-Type: application/json" ^
 -d "{\"text\": \"this is a test log line\"}"
