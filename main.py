import os
from fastapi import FastAPI, File, UploadFile, HTTPException
from fastapi.responses import Response
from fastapi.middleware.cors import CORSMiddleware
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.serialization import load_pem_private_key

# Initialize the backend server
app = FastAPI(title="WorldSign Security API")

# Security Rule: Allow your WordPress site to send upload requests
app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "https://3dxchatstore.com",       # REPLACE with your real WordPress website URL
        "https://www.3dxchatstore.com",   # Include www version if your site uses it
    ],
    allow_credentials=True,
    allow_methods=["*"],                # Allows file uploads and downloads
    allow_headers=["*"],
)

# Unique markers used to attach the digital seal to .world files
FOOTER_TAG = b"WORLDSIGN_V1"
SIGNATURE_SIZE = 256  # RSA 2048-bit signatures are 256 bytes
FOOTER_TOTAL_SIZE = SIGNATURE_SIZE + len(FOOTER_TAG)


def get_keys():
    """Fetches the private key stored safely in Railway settings."""
    pem_private_key = os.getenv("PRIVATE_KEY")
    if not pem_private_key:
        raise HTTPException(
            status_code=500, 
            detail="Server error: PRIVATE_KEY environment variable is missing on Railway."
        )

    try:
        # Load the private key from Railway memory
        private_key = load_pem_private_key(
            pem_private_key.encode("utf-8"), 
            password=None
        )
        # Automatically generate the matching public key to check signatures
        public_key = private_key.public_key()
        return private_key, public_key
    except Exception as err:
        raise HTTPException(status_code=500, detail=f"Invalid RSA key format: {str(err)}")


@app.get("/")
def health_check():
    """Simple check to make sure your API server is running."""
    return {"status": "WorldSign API is active and running!"}


@app.post("/sign")
async def sign_world_file(file: UploadFile = File(...)):
    """
    STATION 1: Stamping endpoint
    Takes a vendor's .world file, calculates a digital seal using your private key,
    attaches the seal to the end of the file, and lets the vendor download it.
    """
    private_key, _ = get_keys()
    
    # Read the contents of the uploaded file
    original_bytes = await file.read()
    if not original_bytes:
        raise HTTPException(status_code=400, detail="Uploaded file is empty.")

    # Create the cryptographic digital signature
    signature = private_key.sign(
        original_bytes,
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
    )

    # Attach the signature and marker tag to the end of the map file
    signed_file_bytes = original_bytes + signature + FOOTER_TAG

    # Return the newly stamped file back to the browser for download
    return Response(
        content=signed_file_bytes,
        media_type="application/octet-stream",
        headers={
            "Content-Disposition": f"attachment; filename=signed_{file.filename}"
        }
    )


@app.post("/verify")
async def verify_world_file(file: UploadFile = File(...)):
    """
    STATION 2: Audit endpoint
    Scans a suspect .world file, checks if the digital seal is present,
    and confirms if any blocks/bytes inside were changed.
    """
    _, public_key = get_keys()

    file_bytes = await file.read()
    
    # Check if file is too small to contain our digital signature
    if len(file_bytes) <= FOOTER_TOTAL_SIZE:
        return {
            "status": "invalid",
            "message": "File is missing digital signature or is corrupted."
        }

    # Read the last few bytes to see if our marker tag is present
    extracted_tag = file_bytes[-len(FOOTER_TAG):]
    if extracted_tag != FOOTER_TAG:
        return {
            "status": "unsigned",
            "message": "No WorldSign digital seal detected on this file."
        }

    # Separate the map data from the digital seal
    original_content = file_bytes[:-FOOTER_TOTAL_SIZE]
    signature = file_bytes[-FOOTER_TOTAL_SIZE:-len(FOOTER_TAG)]

    # Validate the signature
    try:
        public_key.verify(
            signature,
            original_content,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        return {
            "status": "authentic",
            "message": "File signature is valid. Original creator identity confirmed!"
        }
    except Exception:
        return {
            "status": "tampered",
            "message": "File modified! The digital signature does not match the content."
        }