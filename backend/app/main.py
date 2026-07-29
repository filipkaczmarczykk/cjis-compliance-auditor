# --- Imports ---
import docx  # Library to read .docx files
import io    # Used for handling file streams in memory
from fastapi import FastAPI, UploadFile, File, Form # FastAPI framework components
from fastapi.middleware.cors import CORSMiddleware  # Middleware for handling Cross-Origin Resource Sharing
from fastapi.responses import HTMLResponse          # Used to send HTML files back to the browser
import PyPDF2 # Library to read .pdf files

# Import the compliance checking logic from the other file
from compliance_checker import CJISComplianceChecker, ComplianceStatus

# --- FastAPI App Initialization ---
app = FastAPI(title="CJIS Compliance Auditor") # Create the main FastAPI application instance

# --- Middleware Configuration ---
# Enable CORS to allow requests from any origin (e.g., your Render frontend)
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"], # Allows all origins
    allow_methods=["*"], # Allows all methods (GET, POST, etc.)
    allow_headers=["*"], # Allows all headers
)

# --- Route Definitions ---

# Route for the main page (serves the HTML frontend)
@app.get("/")
async def root():
    """Serves the main index.html file."""
    try:
        with open("index.html", "r", encoding="utf-8") as f:
            return HTMLResponse(content=f.read())
    except FileNotFoundError:
        return HTMLResponse(content="<h1>Error: index.html not found</h1>", status_code=500)

# Route for handling the analysis API requests
@app.post("/api/analyze")
async def analyze_policy(
    # These parameters are automatically extracted from the incoming request data
    file: UploadFile = File(None),         # Optional file upload
    policy_text: str = Form(None),         # Optional text from the textarea
    section: str = Form("authenticator_management") # Selected CJIS section (defaults if not provided)
):
    """
    Analyzes the provided policy text (from file or direct input)
    against the specified CJIS section.
    """
    # --- 1. Extract Text from Input ---
    text = ""
    if file: # If a file was uploaded
        content = await file.read() # Read the raw byte content of the file

        # Check file extension and extract text accordingly
        if file.filename.endswith('.pdf'):
            try:
                pdf_reader = PyPDF2.PdfReader(io.BytesIO(content))
                # Join text from all pages that actually contain text
                text = ''.join([page.extract_text() for page in pdf_reader.pages if page.extract_text()])
            except Exception as e:
                print(f"PDF Error: {e}") # Log error
                return {"error": f"Error reading PDF file: {str(e)}"}

        elif file.filename.endswith('.docx'):
            try:
                doc_stream = io.BytesIO(content) # Treat bytes as a file
                doc = docx.Document(doc_stream)  # Open the docx file
                # Join text from all paragraphs that contain text
                text = '\n'.join([para.text for para in doc.paragraphs if para.text])
            except Exception as e:
                print(f"DOCX Error: {e}") # Log error
                return {"error": f"Error reading .docx file: {str(e)}"}

        # --- NEW: Explicitly handle .txt files ---
        elif file.filename.endswith('.txt'):
             try:
                 # Decode assuming standard UTF-8 text encoding
                 text = content.decode('utf-8')
             except UnicodeDecodeError:
                 print(f"TXT Decode Error for file: {file.filename}") # Log error
                 return {"error": "Could not read .txt file. Ensure it is UTF-8 encoded."}
        # --- End of new .txt handling ---

        else: # If the file is not pdf, docx, or txt, return an error
             print(f"Unsupported file type received: {file.filename}") # Log error
             return {"error": "Uploaded file is not a supported format. Please use .pdf, .docx, or .txt."}

    elif policy_text: # If no file, use the text from the textarea
        text = policy_text
    else:
        # If neither file nor text was provided
        return {"error": "No policy text or file provided."}

    # Validate that text was successfully extracted
    if not text or not text.strip():
        return {"error": "The provided document is empty or text could not be extracted."}

    # --- 2. Perform Compliance Analysis ---
    try:
        # Create an instance of the compliance checker "brain"
        checker = CJISComplianceChecker()
        # Run the analysis for the specified section using the extracted text
        compliance_results = checker.check_section(section, text)
        # Format the results into a JSON-friendly dictionary for the frontend
        audit_checklist = checker.generate_audit_checklist(compliance_results)
        # Return the successful analysis results
        return audit_checklist

    except ValueError as e: # Catch 'Unknown CJIS section' errors from the checker
        print(f"ValueError during analysis: {e}") # Log error
        return {"error": str(e)}
    except Exception as e: # Catch any other unexpected errors during the analysis phase
        print(f"Unexpected Analysis Error: {e}") # Log the full error to the terminal
        return {"error": f"An unexpected error occurred during analysis: {str(e)}"}

# --- Main Execution Block ---
# This block runs only if the script is executed directly (e.g., `python main.py`)
if __name__ == "__main__":
    import uvicorn # Import uvicorn here so it's only needed for direct execution

    print("Starting Uvicorn server locally for development...")
    # Run the FastAPI app using Uvicorn server
    # 'reload=True' automatically restarts the server when code changes are saved
    uvicorn.run("main:app", host="127.0.0.1", port=8000, reload=True)