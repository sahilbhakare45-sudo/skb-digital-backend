
import os
import uuid
import shutil
import secrets
import hashlib
import hmac

from pathlib import Path

from dotenv import load_dotenv
from itsdangerous import (
    URLSafeTimedSerializer,
    BadSignature,
    SignatureExpired
)

from fastapi import (
    FastAPI,
    Header,
    HTTPException,
    UploadFile,
    File,
    Form
)

from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse
from pydantic import BaseModel

from database import SessionLocal, FileRecord, create_database


# CONFIGURATION

BASE_DIR = Path(__file__).resolve().parent

load_dotenv(BASE_DIR / ".env")

ADMIN_SECRET_KEY = os.getenv("ADMIN_SECRET_KEY")

UPLOAD_DIR = BASE_DIR / "uploads"
UPLOAD_DIR.mkdir(exist_ok=True)

TOKEN_MAX_AGE = 8 * 60 * 60
DOWNLOAD_TOKEN_MAX_AGE = 5 * 60

PASSWORD_ITERATIONS = 310000
MIN_PASSWORD_LENGTH = 4

ALLOWED_CATEGORIES = {
    "applications",
    "documents",
    "projects",
    "all-resources"
}

serializer = (
    URLSafeTimedSerializer(
        ADMIN_SECRET_KEY,
        salt="skb-digital-admin-session"
    )
    if ADMIN_SECRET_KEY else None
)

download_serializer = (
    URLSafeTimedSerializer(
        ADMIN_SECRET_KEY,
        salt="skb-digital-download-session"
    )
    if ADMIN_SECRET_KEY else None
)


app = FastAPI(
    title="SKB DIGITAL API",
    description="Backend API for SKB DIGITAL",
    version="5.0.0"
)


app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "http://localhost:5173",
        "http://127.0.0.1:5173"
    ],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"]
)


@app.on_event("startup")
def startup():
    create_database()


# REQUEST MODELS

class LoginRequest(BaseModel):
    secret_key: str


class PasswordRequest(BaseModel):
    password: str


# PASSWORD SECURITY

def hash_password(password: str):

    salt = secrets.token_bytes(16)

    password_hash = hashlib.pbkdf2_hmac(
        "sha256",
        password.encode("utf-8"),
        salt,
        PASSWORD_ITERATIONS
    )

    return (
        f"pbkdf2_sha256${PASSWORD_ITERATIONS}"
        f"${salt.hex()}${password_hash.hex()}"
    )


def verify_password(password: str, stored_hash: str):

    try:
        algorithm, iterations, salt_hex, hash_hex = (
            stored_hash.split("$")
        )

        if algorithm != "pbkdf2_sha256":
            return False

        calculated_hash = hashlib.pbkdf2_hmac(
            "sha256",
            password.encode("utf-8"),
            bytes.fromhex(salt_hex),
            int(iterations)
        )

        return hmac.compare_digest(
            calculated_hash.hex(),
            hash_hex
        )

    except (ValueError, TypeError):
        return False


def validate_file_password(password: str):

    if not password or len(password.strip()) < MIN_PASSWORD_LENGTH:
        raise HTTPException(
            status_code=400,
            detail="Password is required and must contain at least 4 characters."
        )


# ADMIN AUTHENTICATION

def verify_admin(authorization: str = ""):

    if not ADMIN_SECRET_KEY or not serializer:
        raise HTTPException(
            status_code=500,
            detail="Admin secret is not configured"
        )

    if not authorization.startswith("Bearer "):
        raise HTTPException(
            status_code=401,
            detail="Admin login required"
        )

    token = authorization.replace("Bearer ", "", 1)

    try:
        data = serializer.loads(
            token,
            max_age=TOKEN_MAX_AGE
        )

        if data.get("admin") is not True:
            raise HTTPException(
                status_code=401,
                detail="Invalid admin session"
            )

    except (BadSignature, SignatureExpired):
        raise HTTPException(
            status_code=401,
            detail="Session expired. Please login again."
        )


# FILE RESPONSE FORMAT

def file_data(item):

    return {
        "file_id": item.id,
        "filename": item.filename,
        "file_size": item.file_size,
        "category": item.category or "all-resources",
        "is_password_protected": bool(item.password_hash),
        "created_at": (
            item.created_at.isoformat()
            if item.created_at else None
        ),
        "download_url": f"/download/{item.id}"
    }


# HOME

@app.get("/")
def home():

    return {
        "status": "success",
        "message": "Welcome to SKB DIGITAL API"
    }


@app.get("/health")
def health():

    return {
        "status": "healthy",
        "project": "SKB DIGITAL"
    }


# PUBLIC FILE LIST

@app.get("/files")
def public_files():

    db = SessionLocal()

    try:
        records = (
            db.query(FileRecord)
            .filter(FileRecord.is_active == True)
            .order_by(FileRecord.created_at.desc())
            .all()
        )

        return {
            "status": "success",
            "total_files": len(records),
            "files": [
                file_data(item)
                for item in records
            ]
        }

    finally:
        db.close()


# PUBLIC SHARE PAGE DETAILS

@app.get("/share/{file_id}")
def get_share_details(file_id: str):

    db = SessionLocal()

    try:
        record = (
            db.query(FileRecord)
            .filter(
                FileRecord.id == file_id,
                FileRecord.is_active == True
            )
            .first()
        )

        if not record:
            raise HTTPException(
                status_code=404,
                detail="File not found"
            )

        return {
            "status": "success",
            "file_id": record.id,
            "filename": record.filename,
            "file_size": record.file_size,
            "category": record.category or "all-resources",
            "is_password_protected": bool(record.password_hash)
        }

    finally:
        db.close()


# ADMIN LOGIN

@app.post("/admin/login")
def admin_login(data: LoginRequest):

    if not ADMIN_SECRET_KEY or not serializer:
        raise HTTPException(
            status_code=500,
            detail="Admin secret is not configured"
        )

    if not secrets.compare_digest(
        data.secret_key,
        ADMIN_SECRET_KEY
    ):
        raise HTTPException(
            status_code=401,
            detail="Incorrect admin password"
        )

    token = serializer.dumps({"admin": True})

    return {
        "status": "success",
        "message": "Admin login successful",
        "access_token": token,
        "token_type": "bearer"
    }


# CHECK ADMIN SESSION

@app.get("/admin/check")
def admin_check(
    authorization: str = Header(default="")
):

    verify_admin(authorization)

    return {
        "status": "success",
        "message": "Admin authentication successful"
    }


# ADMIN UPLOAD - PASSWORD MANDATORY

@app.post("/admin/upload")
def upload_file(
    file: UploadFile = File(...),
    category: str = Form(...),
    password: str = Form(...),
    authorization: str = Header(default="")
):

    verify_admin(authorization)

    if not file.filename:
        raise HTTPException(
            status_code=400,
            detail="File name is required"
        )

    if category not in ALLOWED_CATEGORIES:
        raise HTTPException(
            status_code=400,
            detail="Invalid file category"
        )

    validate_file_password(password)
    password = password.strip()

    original_name = Path(file.filename).name

    file_id = uuid.uuid4().hex
    extension = Path(original_name).suffix

    stored_name = file_id + extension
    file_path = UPLOAD_DIR / stored_name

    db = SessionLocal()

    try:

        with file_path.open("wb") as buffer:
            shutil.copyfileobj(file.file, buffer)

        file_size = file_path.stat().st_size

        record = FileRecord(
            id=file_id,
            filename=original_name,
            stored_name=stored_name,
            file_size=file_size,
            category=category,
            password_hash=hash_password(password)
        )

        db.add(record)
        db.commit()
        db.refresh(record)

        return {
            "status": "success",
            "message": "Password-protected file uploaded successfully",
            **file_data(record)
        }

    except Exception:

        db.rollback()

        if file_path.exists():
            file_path.unlink()

        raise HTTPException(
            status_code=500,
            detail="File upload failed"
        )

    finally:
        db.close()
        file.file.close()


# ADMIN FILE LIST

@app.get("/admin/files")
def admin_files(
    authorization: str = Header(default="")
):

    verify_admin(authorization)

    db = SessionLocal()

    try:

        records = (
            db.query(FileRecord)
            .filter(FileRecord.is_active == True)
            .order_by(FileRecord.created_at.desc())
            .all()
        )

        return {
            "status": "success",
            "total_files": len(records),
            "files": [
                file_data(item)
                for item in records
            ]
        }

    finally:
        db.close()


# ADMIN CHANGE PASSWORD - REMOVAL NOT ALLOWED

@app.put("/admin/files/{file_id}/password")
def update_file_password(
    file_id: str,
    data: PasswordRequest,
    authorization: str = Header(default="")
):

    verify_admin(authorization)

    validate_file_password(data.password)
    new_password = data.password.strip()

    db = SessionLocal()

    try:

        record = (
            db.query(FileRecord)
            .filter(
                FileRecord.id == file_id,
                FileRecord.is_active == True
            )
            .first()
        )

        if not record:
            raise HTTPException(
                status_code=404,
                detail="File not found"
            )

        record.password_hash = hash_password(new_password)

        db.commit()

        return {
            "status": "success",
            "message": "File password updated successfully",
            "is_password_protected": True
        }

    finally:
        db.close()


# ADMIN DELETE FILE

@app.delete("/admin/files/{file_id}")
def delete_file(
    file_id: str,
    authorization: str = Header(default="")
):

    verify_admin(authorization)

    db = SessionLocal()

    try:

        record = (
            db.query(FileRecord)
            .filter(
                FileRecord.id == file_id,
                FileRecord.is_active == True
            )
            .first()
        )

        if not record:
            raise HTTPException(
                status_code=404,
                detail="File not found"
            )

        file_path = UPLOAD_DIR / record.stored_name

        record.is_active = False
        db.commit()

        if file_path.is_file():
            file_path.unlink()

        return {
            "status": "success",
            "message": "File deleted successfully",
            "file_id": file_id
        }

    finally:
        db.close()


# VERIFY DOWNLOAD PASSWORD

@app.post("/download/{file_id}/verify")
def verify_download_password(
    file_id: str,
    data: PasswordRequest
):

    if not download_serializer:
        raise HTTPException(
            status_code=500,
            detail="Download security is not configured"
        )

    db = SessionLocal()

    try:

        record = (
            db.query(FileRecord)
            .filter(
                FileRecord.id == file_id,
                FileRecord.is_active == True
            )
            .first()
        )

        if not record:
            raise HTTPException(
                status_code=404,
                detail="File not found"
            )

        if not record.password_hash:
            raise HTTPException(
                status_code=403,
                detail="File password has not been configured. Contact admin."
            )

        if not verify_password(
            data.password,
            record.password_hash
        ):
            raise HTTPException(
                status_code=401,
                detail="Incorrect file password"
            )

        token = download_serializer.dumps({
            "file_id": record.id,
            "purpose": "download"
        })

        return {
            "status": "success",
            "message": "Password verified successfully",
            "download_url": (
                f"/download/{record.id}?token={token}"
            ),
            "expires_in": DOWNLOAD_TOKEN_MAX_AGE
        }

    finally:
        db.close()


# DOWNLOAD FILE

@app.get("/download/{file_id}")
def download_file(
    file_id: str,
    token: str = ""
):

    db = SessionLocal()

    try:

        record = (
            db.query(FileRecord)
            .filter(
                FileRecord.id == file_id,
                FileRecord.is_active == True
            )
            .first()
        )

        if not record:
            raise HTTPException(
                status_code=404,
                detail="File not found"
            )

        # Every file must have a password configured
        if not record.password_hash:
            raise HTTPException(
                status_code=403,
                detail="File password has not been configured. Contact admin."
            )

        if not token or not download_serializer:
            raise HTTPException(
                status_code=401,
                detail="PASSWORD_REQUIRED"
            )

        try:

            token_data = download_serializer.loads(
                token,
                max_age=DOWNLOAD_TOKEN_MAX_AGE
            )

            if (
                token_data.get("file_id") != file_id
                or token_data.get("purpose") != "download"
            ):
                raise HTTPException(
                    status_code=403,
                    detail="Invalid download token"
                )

        except (BadSignature, SignatureExpired):
            raise HTTPException(
                status_code=401,
                detail="Download link expired. Enter password again."
            )

        file_path = UPLOAD_DIR / record.stored_name

        if not file_path.is_file():
            raise HTTPException(
                status_code=404,
                detail="File is missing from storage"
            )

        return FileResponse(
            path=str(file_path),
            filename=record.filename,
            content_disposition_type="attachment"
        )

    finally:
        db.close()
