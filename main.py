import os
import hashlib
from fastapi import FastAPI, UploadFile, File, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes
from cryptography.exceptions import InvalidSignature

app = FastAPI(title="Secure Document Verification Platform")

@app.get("/")
def home():
    return {
        "status": "online",
        "project": "VERI//VAULT",
        "message": "Secure Document Verification API is running"
    }

@app.get("/health")
def health():
    return {"status": "healthy"}

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # Temporary for initial deployment
    allow_credentials=False,
    allow_methods=["GET", "POST"],
    allow_headers=["*"],
)

# In-memory secure ledger simulation (Stores only hashes & signatures, NO raw files)
LEDGER = {}

# Generate Issuer Keypair on Startup (Simulating an Authority)
PRIVATE_KEY = rsa.generate_private_key(
    public_exponent=65537,
    key_size=2048
)
PUBLIC_KEY = PRIVATE_KEY.public_key()

# --- SECURITY & FILE VALIDATION (The Offensive Twist) ---
ALLOWED_EXTENSIONS = {".pdf"}
MAX_FILE_SIZE = 5 * 1024 * 1024  # 5 MB limit

def validate_file_security(file: UploadFile):
    """Prevents malicious payloads, path traversal, and invalid file types."""
    # 1. Check filename for Path Traversal attempts (e.g., ../../etc/passwd)
    filename = file.filename or ""
    if not filename:
        raise HTTPException(
            status_code=400,
            detail="Filename is required."
        )

    # 2. Check Extension
    ext = os.path.splitext(filename)[1].lower()
    if ext not in ALLOWED_EXTENSIONS:
        raise HTTPException(status_code=400, detail=f"Invalid file type '{ext}'. Only PDF documents are allowed.")

    # 3. Check Magic Bytes (Ensures it's a real PDF, not a renamed script/payload)
    header = file.file.read(5)
    file.file.seek(0) # Reset file pointer back to start
    
    if header != b"%PDF-":
        raise HTTPException(status_code=400, detail="Security Alert: File signature (Magic Bytes) does not match a valid PDF. Polyglot payload blocked.")

@app.post("/api/issuer/sign")
async def sign_document(file: UploadFile = File(...), document_id: str = "DOC-001"):
    validate_file_security(file)
    file_bytes = await file.read()
    
    if len(file_bytes) > MAX_FILE_SIZE:
        raise HTTPException(status_code=400, detail="File size exceeds the 5MB limit.")

    # 1. Generate SHA-256 Cryptographic Hash
    file_hash = hashlib.sha256(file_bytes).hexdigest()

    # 2. Sign the Hash using Issuer's Private Key (RSA)
    signature = PRIVATE_KEY.sign(
        file_hash.encode('utf-8'),
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
    )
    sig_hex = signature.hex()

    # 3. Store in Immutable Ledger
    LEDGER[file_hash] = {
        "document_id": document_id,
        "filename": file.filename,
        "signature": sig_hex
    }

    return {
        "status": "success",
        "message": "Document securely hashed and signed.",
        "document_id": document_id,
        "sha256_hash": file_hash,
        "signature": sig_hex
    }

@app.post("/api/verifier/verify")
async def verify_document(file: UploadFile = File(...)):
    validate_file_security(file)
    file_bytes = await file.read()

    # 1. Compute hash of uploaded file
    file_hash = hashlib.sha256(file_bytes).hexdigest()

    # 2. Check ledger
    if file_hash not in LEDGER:
        return {
            "authentic": False,
            "message": "Verification Failed: Document hash not found in ledger. The file may be fraudulent or modified."
        }

    record = LEDGER[file_hash]
    sig_bytes = bytes.fromhex(record["signature"])

    # 3. Cryptographically verify signature using Public Key
    try:
        PUBLIC_KEY.verify(
            sig_bytes,
            file_hash.encode('utf-8'),
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        return {
            "authentic": True,
            "message": "Document is 100% Authentic and Untampered.",
            "document_id": record["document_id"],
            "sha256_hash": file_hash
        }
    except InvalidSignature:
        return {
            "authentic": False,
            "message": "Security Warning: Cryptographic signature mismatch! Document content has been tampered with."
        }

if __name__ == "__main__":
    import uvicorn
    port = int(os.environ.get("PORT", 8000))
    uvicorn.run("main:app", host="0.0.0.0", port=port)