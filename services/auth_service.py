from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from typing import Optional
import logging
from datetime import datetime, timedelta
from jose import JWTError, jwt
from passlib.context import CryptContext
import os

# Configuration
SECRET_KEY = os.getenv("SECRET_KEY", "your-secret-key-here")
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30

app = FastAPI()

# Setup logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
)
logger = logging.getLogger(__name__)

# Password hashing
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

# Middleware for CORS
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

def verify_password(plain_text_password: str, hashed_password: str) -> bool:
    """Verify if the plain text password matches the hashed password."""
    return pwd_context.verify(plain_text_password, hashed_password)

def get_hashed_password(plain_text_password: str) -> str:
    """Get the hashed version of the plain text password."""
    return pwd_context.hash(plain_text_password)

def create_access_token(data: dict, expires_delta: Optional[timedelta] = None):
    """Create a JWT access token."""
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.utcnow() + expires_delta
    else:
        expire = datetime.utcnow() + timedelta(minutes=15)
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt

@app.post("/auth/register")
async def register(user_data: dict):
    """Register a new user."""
    try:
        # Validate and process user data
        if not user_data.get("email") or not user_data.get("password"):
            raise HTTPException(status_code=400, detail="Email and password are required")

        # Check for existing user
        if User.exists(user_data["email"]):
            raise HTTPException(status_code=409, detail="User already exists")

        # Hash the password
        hashed_password = get_hashed_password(user_data["password"])

        # Create new user
        user = User(email=user_data["email"], 
                   password=hashed_password,
                   created_at=datetime.utcnow())
        user.save()

        logger.info(f"New user registered: {user_data['email']}")
        
        return {"message": "User registered successfully"}

    except Exception as e:
        logger.error(f"Registration failed: {str(e)}")
        raise HTTPException(status_code=500, detail="Internal server error")

@app.post("/auth/login")
async def login(user_credentials: dict):
    """Login existing user and generate access token."""
    try:
        email = user_credentials.get("email", "")
        password = user_credentials.get("password", "")

        if not email or not password:
            raise HTTPException(status_code=400, detail="Email and password are required")

        user = User.find_by_email(email)
        if not user:
            raise HTTPException(status_code=404, detail="User not found")

        if not verify_password(password, user.password):
            raise HTTPException(status_code=401, detail="Incorrect email or password")

        access_token_expires = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
        access_token = create_access_token(
            data={"sub": str(user.id)}, expires_delta=access_token_expires
        )

        logger.info(f"User {user.email} logged in successfully")
        
        return {"access_token": access_token, "token_type": "bearer"}

    except Exception as e:
        logger.error(f"Login failed: {str(e)}")
        raise HTTPException(status_code=500, detail="Internal server error")

@app.post("/auth/subscribe")
async def subscribe(user_id: str):
    """