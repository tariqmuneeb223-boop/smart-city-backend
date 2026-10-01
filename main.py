from fastapi import FastAPI, HTTPException, File, UploadFile, Form, Depends, status, Request
from pydantic import BaseModel, EmailStr
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import OAuth2PasswordBearer
from datetime import datetime, timedelta
from jose import JWTError, jwt,ExpiredSignatureError

import psycopg2
import os
import logging
import time
from dotenv import load_dotenv
from psycopg2.extras import RealDictCursor
from passlib.context import CryptContext
from typing import Optional, List
import httpx
import asyncio
import base64

# ✅ Rate limiting imports
from slowapi import Limiter, _rate_limit_exceeded_handler
from slowapi.util import get_remote_address
from slowapi.errors import RateLimitExceeded

# ✅ Load environment variables
load_dotenv()

# ✅ Environment Configuration
ENVIRONMENT = os.getenv("ENVIRONMENT", "development")
DATABASE_URL = os.getenv("DATABASE_URL")
SECRET_KEY = os.getenv("SECRET_KEY")
ALGORITHM = os.getenv("ALGORITHM", "HS256")

# ✅ Role-based token expiry
ACCESS_TOKEN_EXPIRE_MINUTES_CITIZEN = int(os.getenv("ACCESS_TOKEN_EXPIRE_MINUTES_CITIZEN", 1))      # 7 days
ACCESS_TOKEN_EXPIRE_MINUTES_AUTHORITY = int(os.getenv("ACCESS_TOKEN_EXPIRE_MINUTES_AUTHORITY", 30))     # 30 min
ACCESS_TOKEN_EXPIRE_MINUTES_SUPERADMIN = int(os.getenv("ACCESS_TOKEN_EXPIRE_MINUTES_SUPERADMIN", 30))   # 30 min

AI_SERVICE_URL = os.getenv("AI_SERVICE_URL")
AI_SERVICE_KEY = os.getenv("AI_SERVICE_KEY")

# ✅ Logging Configuration
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s | %(levelname)-8s | %(message)s',
    datefmt='%Y-%m-%d %H:%M:%S'
)
logger = logging.getLogger("smart-city-api")

# Silence overly verbose logs
logging.getLogger("uvicorn.access").setLevel(logging.WARNING)
logging.getLogger("httpx").setLevel(logging.WARNING)

app = FastAPI()

# ==================== JWT CONFIGURATION ====================
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="login")

def create_access_token(data: dict, role: str = "citizen"):
    """Create JWT token with role-based expiry"""
    to_encode = data.copy()

    # ✅ Choose expiry based on role
    if role == "citizen":
        minutes = ACCESS_TOKEN_EXPIRE_MINUTES_CITIZEN
    elif role == "authority":
        minutes = ACCESS_TOKEN_EXPIRE_MINUTES_AUTHORITY
    elif role == "super_admin":
        minutes = ACCESS_TOKEN_EXPIRE_MINUTES_SUPERADMIN
    else:
        minutes = ACCESS_TOKEN_EXPIRE_MINUTES_AUTHORITY  # safe default

    expire = datetime.utcnow() + timedelta(minutes=minutes)
    to_encode.update({"exp": expire, "role": role})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    logger.info(f"Token created for role '{role}' — expires in {minutes} minutes")
    return encoded_jwt

def verify_token(token: str) -> dict:
    """Verify JWT token. Raises HTTPException with specific messages."""
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        return payload
    except ExpiredSignatureError:
        # 🔴 Token was valid but expired
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Token expired",
            headers={"WWW-Authenticate": "Bearer"},
        )
    except JWTError:
        # 🔴 Token is malformed / wrong signature
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid token",
            headers={"WWW-Authenticate": "Bearer"},
        )
# ✅ Rate Limiting Setup (per-user, IP fallback)
def get_rate_limit_key(request: Request) -> str:
    """Rate limit by user ID from JWT, fallback to IP."""
    auth_header = request.headers.get("Authorization")
    if auth_header and auth_header.startswith("Bearer "):
        token = auth_header.replace("Bearer ", "")
        payload = verify_token(token)
        if payload and payload.get("id"):
            return f"user_{payload['id']}"
    return get_remote_address(request)

limiter = Limiter(key_func=get_rate_limit_key)
app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)

# ✅ CORS
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ✅ Request Logging Middleware
@app.middleware("http")
async def log_requests(request: Request, call_next):
    start_time = time.time()
    request_id = f"{int(time.time() * 1000) % 100000:05d}"

    logger.info(f"[{request_id}] → {request.method} {request.url.path}")

    try:
        response = await call_next(request)
        process_time = (time.time() - start_time) * 1000

        log_level = logging.INFO
        if response.status_code >= 500:
            log_level = logging.ERROR
        elif response.status_code >= 400:
            log_level = logging.WARNING

        logger.log(
            log_level,
            f"[{request_id}] ← {request.method} {request.url.path} "
            f"[{response.status_code}] {process_time:.1f}ms"
        )

        response.headers["X-Request-ID"] = request_id
        return response

    except Exception as e:
        process_time = (time.time() - start_time) * 1000
        logger.error(
            f"[{request_id}] ✗ {request.method} {request.url.path} "
            f"[ERROR] {process_time:.1f}ms | {str(e)}"
        )
        raise

# Password hashing
pwd_context = CryptContext(schemes=["pbkdf2_sha256"], deprecated="auto")

def get_password_hash(password):
    password_str = str(password)
    return pwd_context.hash(password_str)

def verify_password(plain_password, hashed_password):
    plain_str = str(plain_password)
    return pwd_context.verify(plain_str, hashed_password)

# ✅ Database connection
def get_db():
    conn = psycopg2.connect(DATABASE_URL, cursor_factory=RealDictCursor)
    return conn

async def get_current_user(token: str = Depends(oauth2_scheme)):
    """Dependency to get current authenticated user"""
    payload = verify_token(token)  # Will raise if invalid/expired
    return payload

async def get_current_authority(user: dict = Depends(get_current_user)):
    """Dependency to ensure user is an authority"""
    if user.get("role") not in ["authority", "super_admin"]:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Only authorities can access this resource"
        )
    return user

# Department mapping
DEPARTMENT_MAP = {
    "garbage": "Sanitation Department",
    "pothole": "Roads Department",
    "streetlight": "Electricity Department",
    "traffic": "Traffic Police"
}

# ==================== MODELS ====================

class UserCreate(BaseModel):
    name: str
    email: EmailStr
    password: str
    role: str = "citizen"

class UserLogin(BaseModel):
    email: EmailStr
    password: str

class UserResponse(BaseModel):
    id: int
    name: str
    email: str
    role: str
    created_at: str

class ReportCreate(BaseModel):
    title: str
    description: Optional[str] = None
    category: str
    latitude: Optional[float] = None
    longitude: Optional[float] = None
    address: Optional[str] = None
    image_url: Optional[str] = None

class ReportResponse(BaseModel):
    id: int
    user_id: int
    title: str
    description: Optional[str]
    category: str
    image_url: Optional[str] = None
    latitude: Optional[float]
    longitude: Optional[float]
    address: Optional[str]
    status: str
    created_at: str
    updated_at: str
    material_type: Optional[str] = None
    material_category: Optional[str] = None
    material_confidence: Optional[float] = None

class ReportStatusUpdate(BaseModel):
    status: str

# ==================== SYNC DATABASE HELPERS ====================
def create_report_sync(user_id, title, description, category, assigned_dept,
                       latitude, longitude, address, image_url,
                       material_type=None, material_category=None, material_confidence=None):
    conn = get_db()
    cur = conn.cursor()
    try:
        cur.execute("""
            INSERT INTO reports (
                user_id, title, description, category, assigned_dept,
                image_url, latitude, longitude, address, status,
                material_type, material_category, material_confidence
            )
            VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
            RETURNING id, created_at, updated_at
        """, (user_id, title, description, category, assigned_dept,
              image_url, latitude, longitude, address, "pending",
              material_type, material_category, material_confidence))
        new_report = cur.fetchone()
        conn.commit()
        return new_report
    finally:
        cur.close()
        conn.close()

# ==================== API ENDPOINTS ====================

@app.get("/")
def root():
    return {"message": "Smart City Attock Backend Running"}

@app.post("/register", response_model=UserResponse)
@limiter.limit("2/minute")
def register(request: Request, user: UserCreate):
    conn = None
    cur = None
    try:
        conn = get_db()
        cur = conn.cursor()
        cur.execute("SELECT * FROM users WHERE email = %s", (user.email,))
        existing = cur.fetchone()
        if existing:
            raise HTTPException(status_code=400, detail="Email already registered")
        hashed_password = get_password_hash(user.password)
        cur.execute("""
            INSERT INTO users (name, email, password, role)
            VALUES (%s, %s, %s, %s)
            RETURNING id, name, email, role, created_at
        """, (user.name, user.email, hashed_password, user.role))
        new_user = cur.fetchone()
        conn.commit()
        new_user['created_at'] = str(new_user['created_at'])
        return new_user
    except HTTPException:
        raise
    except Exception as e:
        if conn:
            conn.rollback()
        print(f"Error: {str(e)}")
        raise HTTPException(status_code=500, detail=str(e))
    finally:
        if cur:
            cur.close()
        if conn:
            conn.close()

@app.post("/login")
@limiter.limit("10/minute")
def login(request: Request, user: UserLogin):
    conn = None
    cur = None
    try:
        logger.info(f"Login attempt: {user.email}")
        conn = get_db()
        cur = conn.cursor()
        cur.execute("SELECT * FROM users WHERE email = %s", (user.email,))
        existing = cur.fetchone()
        if not existing:
            logger.warning(f"Login failed (user not found): {user.email}")
            raise HTTPException(status_code=401, detail="Invalid email or password")
        if not verify_password(user.password, existing['password']):
            logger.warning(f"Login failed (wrong password): {user.email}")
            raise HTTPException(status_code=401, detail="Invalid email or password")

        logger.info(f"Login success: {user.email} (role: {existing['role']})")

        department = existing.get('department') if existing['role'] == 'authority' else None

        # ✅ Role-based token expiry
        access_token = create_access_token(
            {
                "sub": existing['email'],
                "id": existing['id'],
                "role": existing['role'],
                "department": department
            },
            role=existing['role']
        )

        return {
            "access_token": access_token,
            "token_type": "bearer",
            "id": existing['id'],
            "name": existing['name'],
            "email": existing['email'],
            "role": existing['role'],
            "department": department,
            "message": "Login successful"
        }
    except HTTPException:
        raise
    except Exception as e:
        print(f"Error: {str(e)}")
        raise HTTPException(status_code=500, detail=str(e))
    finally:
        if cur:
            cur.close()
        if conn:
            conn.close()

# ==================== PUBLIC ENDPOINTS (No Auth Required) ====================

@app.get("/public/stats")
def get_public_stats():
    """
    Public endpoint - returns only aggregate stats (no sensitive data).
    Used by the app's welcome screen before login.
    """
    conn = None
    cur = None
    try:
        conn = get_db()
        cur = conn.cursor()
        cur.execute("""
            SELECT 
                COUNT(*) as total,
                COUNT(*) FILTER (WHERE status = 'pending') as pending,
                COUNT(*) FILTER (WHERE status = 'in_progress') as in_progress,
                COUNT(*) FILTER (WHERE status = 'resolved') as resolved
            FROM reports
        """)
        result = cur.fetchone()
        return {
            "total": result["total"] or 0,
            "pending": result["pending"] or 0,
            "in_progress": result["in_progress"] or 0,
            "resolved": result["resolved"] or 0,
        }
    except Exception as e:
        print(f"Error: {str(e)}")
        raise HTTPException(status_code=500, detail=str(e))
    finally:
        if cur:
            cur.close()
        if conn:
            conn.close()

# ==================== AI-POWERED REPORT ENDPOINT ====================

@app.post("/reports/ai")
@limiter.limit("5/minute")
async def create_report_ai(
    request: Request,
    title: str = Form(...),
    description: Optional[str] = Form(None),
    category: Optional[str] = Form(None),
    latitude: Optional[float] = Form(None),
    longitude: Optional[float] = Form(None),
    address: Optional[str] = Form(None),
    user_id: int = Form(...),
    file: Optional[UploadFile] = File(None),
    current_user: dict = Depends(get_current_user)
):
    logger.info(f"Creating report: '{title}' by user #{user_id}")

    ai_issue = None
    final_category = category
    image_url = None

    material_type = None
    material_category = None
    material_confidence = None

    if file:
        image_bytes = await file.read()
        encoded_string = base64.b64encode(image_bytes).decode('utf-8')
        image_url = f"data:{file.content_type};base64,{encoded_string}"

        async with httpx.AsyncClient(timeout=30.0) as client:
            issue_resp = await client.post(
                f"{AI_SERVICE_URL}/classify-issue",
                files={"file": (file.filename, image_bytes, file.content_type)},
                headers={"X-API-Key": AI_SERVICE_KEY}
            )
            if issue_resp.status_code == 200:
                ai_issue = issue_resp.json()
                if ai_issue.get("success") and not final_category:
                    final_category = ai_issue["class"]

                if final_category == "garbage" and ai_issue:
                    material_type = ai_issue.get("material_type")
                    material_category = ai_issue.get("material_category")
                    material_confidence = ai_issue.get("material_confidence")

    if not final_category:
        final_category = "other"

    assigned_dept = DEPARTMENT_MAP.get(final_category, "General Administration")

    from concurrent.futures import ThreadPoolExecutor
    executor = ThreadPoolExecutor(max_workers=1)
    loop = asyncio.get_event_loop()
    new_report = await loop.run_in_executor(
        executor,
        create_report_sync,
        user_id, title, description, final_category, assigned_dept,
        latitude, longitude, address, image_url,
        material_type, material_category, material_confidence
    )
    executor.shutdown(wait=False)

    logger.info(f"Report created: #{new_report['id']} → {assigned_dept}")

    return {
        "success": True,
        "report_id": new_report["id"],
        "created_at": str(new_report["created_at"]),
        "assigned_department": assigned_dept,
        "image_url": image_url,
        "material_type": material_type,
        "material_category": material_category,
        "material_confidence": material_confidence,
        "ai_suggestions": {
            "issue": ai_issue
        }
    }

# ==================== REPORT CRUD ENDPOINTS ====================

@app.post("/reports", response_model=ReportResponse)
def create_report(
    report: ReportCreate,
    user_id: int,
    current_user: dict = Depends(get_current_user)
):
    conn = None
    cur = None
    try:
        conn = get_db()
        cur = conn.cursor()
        cur.execute("""
            INSERT INTO reports (
                user_id, title, description, category,
                image_url, latitude, longitude, address, status
            )
            VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s)
            RETURNING id, user_id, title, description, category,
                      image_url, latitude, longitude, address,
                      status, created_at, updated_at
        """, (
            user_id, report.title, report.description, report.category,
            report.image_url, report.latitude, report.longitude, report.address,
            "pending"
        ))
        new_report = cur.fetchone()
        conn.commit()
        new_report['created_at'] = str(new_report['created_at'])
        new_report['updated_at'] = str(new_report['updated_at'])
        return new_report
    except Exception as e:
        if conn:
            conn.rollback()
        print(f"Error: {str(e)}")
        raise HTTPException(status_code=500, detail=str(e))
    finally:
        if cur:
            cur.close()
        if conn:
            conn.close()

@app.get("/reports", response_model=List[ReportResponse])
def get_all_reports(
    department: Optional[str] = None,
    current_user: dict = Depends(get_current_user)
):
    conn = None
    cur = None
    try:
        conn = get_db()
        cur = conn.cursor()
        if department:
            cur.execute("""
                SELECT id, user_id, title, description, category,
                       latitude, longitude, address,
                       status, created_at, updated_at,
                       material_type, material_category, material_confidence
                FROM reports
                WHERE assigned_dept = %s
                ORDER BY created_at DESC
            """, (department,))
        else:
            cur.execute("""
                SELECT id, user_id, title, description, category,
                       latitude, longitude, address,
                       status, created_at, updated_at,
                       material_type, material_category, material_confidence
                FROM reports
                ORDER BY created_at DESC
            """)
        reports = cur.fetchall()
        for report in reports:
            report['created_at'] = str(report['created_at'])
            report['updated_at'] = str(report['updated_at'])
        return reports
    except Exception as e:
        print(f"Error: {str(e)}")
        raise HTTPException(status_code=500, detail=str(e))
    finally:
        if cur:
            cur.close()
        if conn:
            conn.close()

@app.get("/reports/{report_id}/image")
def get_report_image(
    report_id: int,
    current_user: dict = Depends(get_current_user)
):
    conn = None
    cur = None
    try:
        conn = get_db()
        cur = conn.cursor()
        cur.execute("""
            SELECT image_url FROM reports WHERE id = %s
        """, (report_id,))
        result = cur.fetchone()
        if not result:
            raise HTTPException(status_code=404, detail="Report not found")
        return {"image_url": result["image_url"]}
    except HTTPException:
        raise
    except Exception as e:
        print(f"Error: {str(e)}")
        raise HTTPException(status_code=500, detail=str(e))
    finally:
        if cur:
            cur.close()
        if conn:
            conn.close()

@app.get("/reports/user/{user_id}", response_model=List[ReportResponse])
def get_user_reports(
    user_id: int,
    current_user: dict = Depends(get_current_user)
):
    conn = None
    cur = None
    try:
        conn = get_db()
        cur = conn.cursor()
        cur.execute("""
            SELECT id, user_id, title, description, category,
                   latitude, longitude, address,
                   status, created_at, updated_at,
                   material_type, material_category, material_confidence
            FROM reports WHERE user_id = %s ORDER BY created_at DESC
        """, (user_id,))
        reports = cur.fetchall()
        for report in reports:
            report['created_at'] = str(report['created_at'])
            report['updated_at'] = str(report['updated_at'])
        return reports
    except Exception as e:
        print(f"Error: {str(e)}")
        raise HTTPException(status_code=500, detail=str(e))
    finally:
        if cur:
            cur.close()
        if conn:
            conn.close()

@app.put("/reports/{report_id}/status", response_model=ReportResponse)
def update_report_status(
    report_id: int,
    status_update: ReportStatusUpdate,
    current_user: dict = Depends(get_current_authority)
):
    logger.info(
        f"Status update: report #{report_id} → '{status_update.status}' "
        f"by {current_user.get('sub')}"
    )
    conn = None
    cur = None
    try:
        conn = get_db()
        cur = conn.cursor()
        cur.execute("SELECT * FROM reports WHERE id = %s", (report_id,))
        if not cur.fetchone():
            raise HTTPException(status_code=404, detail="Report not found")
        cur.execute("""
            UPDATE reports SET status = %s, updated_at = CURRENT_TIMESTAMP
            WHERE id = %s
            RETURNING id, user_id, title, description, category,
                      image_url, latitude, longitude, address,
                      status, created_at, updated_at,
                      material_type, material_category, material_confidence
        """, (status_update.status, report_id))
        updated_report = cur.fetchone()
        conn.commit()
        updated_report['created_at'] = str(updated_report['created_at'])
        updated_report['updated_at'] = str(updated_report['updated_at'])
        return updated_report
    except HTTPException:
        raise
    except Exception as e:
        if conn:
            conn.rollback()
        print(f"Error: {str(e)}")
        raise HTTPException(status_code=500, detail=str(e))
    finally:
        if cur:
            cur.close()
        if conn:
            conn.close()

# ==================== AI PROXY ENDPOINTS ====================

@app.post("/ai/analyze-issue")
async def analyze_issue(
    file: UploadFile = File(...),
    current_user: dict = Depends(get_current_user)
):
    try:
        async with httpx.AsyncClient(timeout=30.0) as client:
            file_content = await file.read()
            files = {"file": (file.filename, file_content, file.content_type)}
            response = await client.post(
                f"{AI_SERVICE_URL}/classify-issue",
                files=files,
                headers={"X-API-Key": AI_SERVICE_KEY}
            )
            if response.status_code == 200:
                return response.json()
            else:
                return {"success": False, "error": f"AI service error: {response.status_code}"}
    except Exception as e:
        return {"success": False, "error": str(e)}

@app.get("/ai/health")
async def ai_health_check():
    try:
        async with httpx.AsyncClient(timeout=5.0) as client:
            response = await client.get(f"{AI_SERVICE_URL}/health")
            if response.status_code == 200:
                return {"status": "healthy", "ai_service": "online"}
            return {"status": "degraded", "ai_service": "unhealthy"}
    except Exception:
        return {"status": "unhealthy", "ai_service": "offline"}