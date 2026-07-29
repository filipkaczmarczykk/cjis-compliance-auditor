# Security Posture

## 1. Document Handling

Key is making sure that files aren't getting stored.

```python
# backend/main.py
from fastapi import FastAPI, UploadFile, File, Form, HTTPException
from fastapi.middleware.cors import CORSMiddleware
import PyPDF2
import io
import hashlib
from datetime import datetime

# CRITICAL: Set file size limit
MAX_FILE_SIZE = 10 * 1024 * 1024  # 10MB limit

@app.post("/api/analyze")
async def analyze_policy(
    file: UploadFile = File(None),
    policy_text: str = Form(None),
    section: str = Form("authenticator_management")
):
    policy_content = None

    # Extract text but NEVER save to disk
    if file:
        # Validate file type
        if not file.filename.endswith(('.pdf', '.docx', '.txt')):
            raise HTTPException(status_code=400, detail="Invalid file type")

        # Check file size
        content = await file.read()
        if len(content) > MAX_FILE_SIZE:
            raise HTTPException(status_code=413, detail="File too large")

        # Process in memory only
        if file.filename.endswith('.pdf'):
            pdf_reader = PyPDF2.PdfReader(io.BytesIO(content))
            policy_content = ''.join([page.extract_text() for page in pdf_reader.pages])
        else:
            policy_content = content.decode('utf-8')

        # Immediately clear content from memory
        del content
    else:
        policy_content = policy_text

    # Process and return results
    checker = CJISComplianceChecker()
    results = checker.check_section(section, policy_content)

    # Clear sensitive data from memory before returning
    del policy_content

    return {"results": results}
```

## 2. HTTPS Only

Enforce encryption while in transit.

```python
# backend/main.py
from fastapi.middleware.trustedhost import TrustedHostMiddleware

app = FastAPI()

# Force HTTPS in production
@app.middleware("http")
async def force_https(request, call_next):
    if request.url.scheme != "https" and not request.url.hostname in ["localhost", "127.0.0.1"]:
        return RedirectResponse(
            url=str(request.url).replace("http://", "https://"),
            status_code=301
        )
    return await call_next(request)
```

## 3. Audit Logging

Tracking access. Making sure who can get in and when they are getting in, etc.

```python
import logging
from datetime import datetime

# Configure secure logging
logging.basicConfig(
    filename='audit.log',
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)

@app.post("/api/analyze")
async def analyze_policy(...):
    # Log every document analysis (no PII in logs)
    logging.info(f"Analysis started - Section: {section}, File: {file.filename if file else 'text_input'}, Size: {len(content) if file else len(policy_text)}")

    # ... process ...

    logging.info(f"Analysis completed - Section: {section}, Results: {len(results)} checks")
    return results
```

## 4. Input Sanitization

Preventing injection attacks.

```python
import re

def sanitize_policy_text(text: str) -> str:
    """Remove potentially malicious content"""
    # Remove script tags, SQL injection attempts, etc.
    text = re.sub(r'<script.*?</script>', '', text, flags=re.DOTALL)
    text = re.sub(r'javascript:', '', text, flags=re.IGNORECASE)
    text = re.sub(r'on\w+\s*=', '', text)  # Remove event handlers
    return text.strip()

@app.post("/api/analyze")
async def analyze_policy(...):
    if policy_text:
        policy_text = sanitize_policy_text(policy_text)
```

## 5. LLM Integration Draft

### Azure OpenAI - CJIS Compliant

```python
# Azure OpenAI has BAA (Business Associate Agreement) for HIPAA
# and can be configured for CJIS compliance
from openai import AzureOpenAI

client = AzureOpenAI(
    api_key=os.getenv("AZURE_OPENAI_KEY"),
    api_version="2024-02-01",
    azure_endpoint=os.getenv("AZURE_OPENAI_ENDPOINT")
)

# Azure keeps data in your region, offers data residency
```

### Environment Variables

No hardcoding of secrets. Add an `.env` file and add it to `.gitignore`.

```bash
# .env
OPENAI_API_KEY=your_key_here
AZURE_OPENAI_ENDPOINT=your_endpoint
DATABASE_URL=your_db_connection
SECRET_KEY=your_secret_key
```

```python
# backend/main.py
from dotenv import load_dotenv
import os

load_dotenv()

# Access securely
api_key = os.getenv("OPENAI_API_KEY")
```

## Rollout Phases

**Phase 1 (Now):**
- Memory-only processing
- HTTPS enforcement
- File validation
- Audit logging

**Phase 2 (Before LLM):**
- Authentication system
- Role-based access
- Deploy to private network

**Phase 3 (LLM Integration):**
- Use Azure OpenAI (CJIS-friendly) OR self-hosted model
- Never send full documents to external APIs
- Implement data masking for PII before LLM analysis
