from fastapi import FastAPI, Depends, HTTPException
from mim import train
from pydantic import BaseModel
from sqlalchemy import create_engine, Column, Float, Boolean, String, Integer, ForeignKey
from sqlalchemy.orm import sessionmaker, Session, declarative_base, relationship 
from typing import Optional
import pandas as pd,pickle ,urllib.parse,os ,requests,bcrypt, jwt
from sqlalchemy.exc import SQLAlchemyError
from sklearn.ensemble import IsolationForest
from datetime import datetime, timedelta
from twilio.rest import Client
from twilio.http.http_client import TwilioHttpClient
from twilio.rest import Client
import psycopg2 , random
from psycopg2.extras import DictCursor
app = FastAPI()


username = "postgres"
password = 'RGS@123'
encoded_password = urllib.parse.quote_plus(password)
DB_URL = f"postgresql://{username}:{encoded_password}@localhost:5432/ryze_db"
engine = create_engine(DB_URL)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()

# Twilio Credentials (Replace with your own credentials)
TWILIO_ACCOUNT_SID = "ACaeba48ab8bc69d0006af428cbb64100a"
TWILIO_AUTH_TOKEN = "60d0bfe39efc87a30cda00052f3c124f"
VERIFY_SERVICE_SID = "VAf7ef7a5886c6a8d580faf5a83e978b47"
proxy_client = TwilioHttpClient()
client = Client(TWILIO_ACCOUNT_SID, TWILIO_AUTH_TOKEN, http_client=proxy_client)
client = Client(TWILIO_ACCOUNT_SID, TWILIO_AUTH_TOKEN)


SECRET_KEY = "your_secret_key"
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 60

class User(Base):
    __tablename__ = "users"
    
    id = Column(Integer, primary_key=True, index=True)
    user_name = Column(String, unique=True, nullable=False)
    email = Column(String, unique=True, nullable=False)
    password = Column(String, nullable=False)
    mobile = Column(String, nullable=False)
    otp = Column(String, nullable=True)
    otp_expiration = Column(String, nullable=True)
    expenses = relationship("ExpensesDB", back_populates="user", cascade="all,delete-orphan")
    loan_details = relationship("LoanDetailsDB", back_populates="user", cascade="all, delete-orphan")
    lifestyle = relationship("LifestyleDB", back_populates="user", uselist=False)
    financial_goals = relationship("FinancialGoalsDB", back_populates="user", uselist=False)

class ExpensesDB(Base):
    __tablename__ = "expenses"
    
    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, ForeignKey("users.id"))
    income = Column(Float)
    rent = Column(Float)
    groceries = Column(Float)
    transportation = Column(Float)
    healthcare = Column(Float)
    dining_out = Column(Float)
    shopping = Column(Float)
    personal_care = Column(Float)
    education = Column(Float)
    electricity = Column(Float)
    water = Column(Float)
    insurance = Column(Float)

    user = relationship("User", back_populates="expenses")
    

class LoanDetailsDB(Base):
    __tablename__ = "loan_details"
    
    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, ForeignKey("users.id", ondelete="CASCADE"))
    loan_exists = Column(Boolean)
    loan_amount = Column(Float, nullable=True)
    monthly_payment = Column(Float, nullable=True)
    loan_term = Column(Integer, nullable=True)
    interest_rate = Column(Float, nullable=True)

    user = relationship("User", back_populates="loan_details")

class LifestyleDB(Base):
    __tablename__ = "lifestyle"
    
    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, ForeignKey("users.id"))
    smoke = Column(Boolean)
    dine_out_frequency = Column(String)
    sports_hobbies = Column(String)

    user = relationship("User", back_populates="lifestyle")

class FinancialGoalsDB(Base):
    __tablename__ = "financial_goals"
    
    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, ForeignKey("users.id"))
    goal = Column(String)

    user = relationship("User", back_populates="financial_goals")

Base.metadata.create_all(bind=engine) # type: ignore

class UserCreate(BaseModel):
    user_name: str
    email: str
    password: str
    mobile: str

class LoginRequest(BaseModel):
    email: str
    password: str
    
class OTPRequest(BaseModel):
    mobile: str
    otp: str        

class ForgotPasswordRequest(BaseModel):
    mobile: str

class OTPVerificationRequest(BaseModel):
    mobile: str
    otp: str

class ResetPasswordRequest(BaseModel):
    id: int
    password: str

def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

def hash_password(password: str) -> str:
    return bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')

def verify_password(plain_password: str, hashed_password: str) -> bool:
    return bcrypt.checkpw(plain_password.encode('utf-8'), hashed_password.encode('utf-8'))

def create_access_token(data: dict, expires_delta: timedelta):
    to_encode = data.copy()
    expire = datetime.utcnow() + expires_delta
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm="HS256")
    return encoded_jwt
@app.post("/Register") 
def register_user(user: UserCreate, db: Session = Depends(get_db)):
    # Check if email or mobile number already exists
    if db.query(User).filter(User.email == user.email).first(): # type: ignore
        return {"status": "0", "message": "User Email already exists", "result": {}}

    if db.query(User).filter(User.mobile == user.mobile).first(): # type: ignore
        return {"status": "0", "message": "Mobile number already registered", "result": {}}

    # Hash password
    hashed_password = hash_password(user.password)
    # Create new user
    db_user = User(
        user_name=user.user_name,  # Allows duplicate usernames # type: ignore
        email=user.email, # type: ignore
        password=hashed_password, # type: ignore
        mobile=user.mobile # type: ignore
    )
    db.add(db_user)
    db.commit()
    db.refresh(db_user)

    return {
        "status": "1",
        "message": "User registered successfully!",
        "id": db_user.id
}
@app.post("/Login")
async def login(request: LoginRequest, db: Session = Depends(get_db)):
    email = request.email.strip()
    user = db.query(User).filter(User.email == email).first() # type: ignore
    if not user or not verify_password(request.password, user.password):
        return {"status": "0", "message": "Invalid credentials",
                "result": {}}
    access_token = create_access_token(data={"sub": user.email}, expires_delta=timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES))
    return {
    "status": "1",
    "message": "Login successful",
    "result": {
        "id": user.id,
        "user_name": user.user_name,
        "email": user.email,
        "password": user.password,
        "type": "User",
        "country_code": "",
        "mobile":user.mobile,
        "image": " ",
        "updated_at": "2025-03-26 18:14:03",
        "created_at": "2025-03-26 18:14:03",
        "device_id": "null",
        "status": "ACTIVE",
        "country": "",
        "otp": "",
        "city": "",
        "district": "",
        "qr_image": "",
        "qr_code": "",
        "point": "0",
        "token": access_token}}
def send_otp(mobile: str, otp: str):
    """Send OTP to the user's mobile number via Twilio."""
    client = Client(TWILIO_ACCOUNT_SID, TWILIO_AUTH_TOKEN)
    try:
        message = client.messages.create(
            body=f"Your OTP code is {otp}. It is valid for 10 minutes.",
            from_=VERIFY_SERVICE_SID,
            to=mobile
        )
        return True  # Indicate success
    except Exception as e:
        print(f"Error sending OTP: {e}")
        return False
@app.post("/forgot-password")
def forgot_password(request: ForgotPasswordRequest, db: Session = Depends(get_db)):
    user = db.query(User).filter(User.mobile == request.mobile).first() # type: ignore
    if not user:
        return {"status": "0", "message": "User not found", "result": {}}
    
    # Generate a random OTP (for production, use a more secure random generator)
    import random
    otp = str(random.randint(1000, 9999))
    
    otp_expiration = (datetime.utcnow() + timedelta(minutes=10)).isoformat()
    user.otp = otp
    user.otp_expiration = otp_expiration
    try:
        db.commit()
        # Send OTP
        send_success = send_otp(user.mobile, otp)
        if send_success:
            return {"status": "1", "message": f"OTP sent to {user.mobile}", "result": {"otp": otp}}
        else:
            return {"status": "0", "message": "Failed to send OTP", "result": {}}
    except Exception as e:
        db.rollback()
        return {"status": "0", "message": f"Error: {str(e)}", "result": {}}

@app.post("/verify-otp")
def verify_otp(request: OTPVerificationRequest, db: Session = Depends(get_db)):
    user = db.query(User).filter(User.mobile == request.mobile).first() # type: ignore
    if not user or user.otp != request.otp:
        return {"status": "0", "message": "Invalid mobile number or OTP","results":{}}
    return { "status": "1",
    "message": "Otp Verify",
    "result": {
        "id": user.id,
        "user_name": user.user_name,
        "email": user.email,
        "password": user.password,
        "type": "User",
        "country_code": "",
        "mobile":user.mobile,
        "image": " ",
        "image": "",
        "updated_at": "2025-03-26 18:25:04",
        "created_at": "2025-03-26 18:19:29",
        "device_id": "null",
        "status": "ACTIVE",
        "country": "",
        "otp": "9999",
        "city": "",
        "district": "",
        "qr_image": "",
        "qr_code": "",
        "point": "0"}}

@app.post("/update-password")
def reset_password(request: ResetPasswordRequest, db: Session = Depends(get_db)):
    user = db.query(User).filter(User.id == request.id).first() # type: ignore
    if not user:
        return {"Status": "0", "Message": "User not found","result":{}}
    user.password = hash_password(request.password)
    db.commit()
    return { "status":"1",
            "message": " Succesfully",
    "user_data": {
         "id": user.id,
        "user_name": user.user_name,
        "email": user.email,
        "password": user.password,
        "type": "User",
        "country_code": "",
        "mobile":user.mobile,
        "image": "",
        "updated_at": "2025-03-26 19:33:45",
        "created_at": "2025-03-26 18:19:29",
        "device_id": "null",
        # "status": "ACTIVE",
        "country": "",
        "otp": "9999",
        "city": "",
        "district": "",
        "qr_image": "",
        "qr_code": "",
        "point": "0"},
    "status": "1"}
    
@app.delete("/users/{user_id}")
def delete_user(user_id: int, db: Session = Depends(get_db)):
    user = db.query(User).filter(User.id == user_id).first()
    if not user:
        return {"status":"0","message":"User not found"}
    db.delete(user)
    db.commit()
    return {"status":"1","message": f"User with id {user_id} deleted successfully"}
    
class Expenses(BaseModel):
    income: float
    rent: float
    groceries: float
    transportation: float
    healthcare: float
    dining_out: float
    shopping: float
    personal_care: float
    education: float
    electricity: float
    water: float
    insurance: float
class LoanDetails(BaseModel):
    loan_exists: bool
    loan_amount: Optional[float] = None
    monthly_payment: Optional[float] = None
    loan_term: Optional[int] = None
    interest_rate: Optional[float] = None
class Lifestyle(BaseModel):
    smoke: bool
    dine_out_frequency: str
    sports_hobbies: str
class FinancialGoals(BaseModel):
    goal: str
class UserFinancialData(BaseModel):
    user_id: int
    monthly_income: float
    expenses: Expenses
    loan_details: LoanDetails
    lifestyle: Lifestyle
    financial_goals: FinancialGoals

@app.post("/financial_data")
def submit_financial_data(data: UserFinancialData, db: Session = Depends(get_db)):
    user = db.query(User).filter(User.id == data.user_id).first() # type: ignore
    if not user:
        return {"status": "0", "message": "User not found","result":{}}
    user.monthly_income = data.monthly_income
    expenses = ExpensesDB(user_id=user.id, **data.expenses.dict()) # type: ignore
    loan_details = LoanDetailsDB(user_id=user.id, **data.loan_details.dict()) # type: ignore
    lifestyle = LifestyleDB(user_id=user.id, **data.lifestyle.dict()) # type: ignore
    financial_goals = FinancialGoalsDB(user_id=user.id, **data.financial_goals.dict()) # type: ignore
    db.add_all([expenses, loan_details, lifestyle, financial_goals])
    db.commit()
    return {
        "status": "1",
        "message": "Financial data stored successfully",
        "user_id": user.id,
        "financial_data": {
            "monthly_income": data.monthly_income,
            "expenses": data.expenses.dict(),
            "loan_details": data.loan_details.dict(),
            "lifestyle": data.lifestyle.dict(),
            "financial_goals": data.financial_goals.dict()} }
#Get method
DB_PATH = "ryze_db"
# Train a new model
iso_forest = IsolationForest()
# Load pre-trained models safely
MODEL_PATH = "E:\\RYZE_APP\\model\\isolation_forest.pkl"
SCALER_PATH = "E:\\RYZE_APP\\model\\scaler.pkl"

with open("isolation_forest.pkl", "wb") as f:
    pickle.dump(iso_forest, f)
try:
    if not os.path.exists(MODEL_PATH):
        raise FileNotFoundError(f"Model file not found: {MODEL_PATH}")
    with open(MODEL_PATH, "rb") as f:
        iso_forest = pickle.load(f)
    if not os.path.exists(SCALER_PATH):
        raise FileNotFoundError(f"Scaler file not found: {SCALER_PATH}")
    with open(SCALER_PATH, "rb") as f:
        scaler = pickle.load(f)
except FileNotFoundError as e:
    raise HTTPException(status_code=500, detail=str(e))
# Column name mapping to match trained model
COLUMN_MAPPING = {
    "income": "Income",
    "rent": "Rent",
    "groceries": "Groceries",
    "transportation": "Transportation",
    "healthcare": "Healthcare",
    "dining_out": "Dining_Out",
    "shopping": "Shopping",
    "personal_care": "Personal_Care",
    "education": "Education",
    "electricity": "Electricity",
    "water": "Water",
    "insurance": "Insurance",} 
DB_CONFIG = {
    "dbname": "ryze_db",
    "user": "postgres",
    "password": 'RGS@123',
    "host": "172.31.10.201",
    "port": "5432" }
# Fetch user data with correct column names
def fetch_user_data(user_id: int, db: Session):
    try:
        result = db.query(ExpensesDB).filter(ExpensesDB.user_id == user_id).first()
        if result:
            user_data = {COLUMN_MAPPING[key]: value for key, value in dict(result.__dict__).items() if key in COLUMN_MAPPING}
            return user_data
        else:
            raise HTTPException(status_code=404, detail=f"User data not found for user_id: {user_id}")
    except SQLAlchemyError as err:
        raise HTTPException(status_code=500, detail=f"Database error: {str(err)}")
def analyze_spending(user_data):
    income = user_data["Income"]
    user_df = pd.DataFrame([user_data])
    user_df["Total Spending"] = user_df.drop(columns=["Income"]).sum(axis=1)
    user_df["Spending Percentage"] = (user_df["Total Spending"] / income) * 100
    try:
        user_df[['Income', 'Total Spending', 'Spending Percentage']] = scaler.transform(
            user_df[['Income', 'Total Spending', 'Spending Percentage']])
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error during scaling: {str(e)}")
    try:
        anomaly_if = iso_forest.predict(user_df[['Income', 'Total Spending', 'Spending Percentage']])[0]
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error during anomaly prediction: {str(e)}")
    spending_categories = {k: v for k, v in user_data.items() if k != "Income"}
    highest_spending_category = max(spending_categories, key=spending_categories.get) # type: ignore
    spending_percentage = user_df['Spending Percentage'][0]

    if spending_percentage <= 75:
        status = "Good"
        advice = "You're managing your spending well. Keep up the good financial habits!"
    elif spending_percentage > 75 and anomaly_if != -1:
        status = "Warning"
        advice = "You might be overspending. Consider cutting back on discretionary expenses."
    else:
        status = "Critical"
        advice = "Your spending pattern is unusual. Review your expenses to prevent financial risks."
    high_expenses = [
        cat for cat, value in spending_categories.items()
        if (cat in ['Rent', 'Education'] and value > (0.3 * income))
        or (cat not in ['Rent', 'Education'] and value > (0.2 * income))]
    overspending_alerts = [f"{cat} exceeds 20% of your income." for cat in high_expenses]
    return {
        "spending_analysis": {
            "status": status,
            "description": f"You are spending {spending_percentage:.2f}% of your income.",
            "highest_spending_category": highest_spending_category,
            "advice": advice,
            "overspending_alerts": overspending_alerts,
            "spending_details": {
                "Income": f"Your monthly income is ${income}. Consider allocating some to savings.",
                "Total Spending": f"You have spent ${user_df['Total Spending'][0]:.2f} this month.",
                "Spending Percentage": f"You are using {spending_percentage:.2f}% of your income.",
                "Breakdown": {
                    "Essentials": {
                        "Rent": f"You spend ${user_data['Rent']} on rent, a significant expense.",
                        "Groceries": f"You allocate ${user_data['Groceries']} to groceries.",
                        "Transportation": f"Your transportation costs are ${user_data['Transportation']}.",
                        "Healthcare": f"You spend ${user_data['Healthcare']} on healthcare.",
                        "Insurance": f"Your insurance costs are ${user_data['Insurance']}.",},
                    "Utilities": {
                        "Electricity": f"Electricity costs are ${user_data['Electricity']}.",
                        "Water": f"Your water bill is ${user_data['Water']}.",},
                    "Discretionary Spending": {
                        "Dining Out": f"Dining out expenses are ${user_data['Dining_Out']}.",
                        "Shopping": f"Shopping costs are ${user_data['Shopping']}.",
                        "Personal Care": f"Personal care expenses are ${user_data['Personal_Care']}.",
                        "Education": f"Education costs amount to ${user_data['Education']}.", }}}}}

@app.get("/predict_spending_behavior/{user_id}")
def predict_spending_behavior(user_id: int, db: Session = Depends(get_db)):
    try:
        user_data = fetch_user_data(user_id, db)
        result = analyze_spending(user_data)
        return result
    except HTTPException as http_exc:
        raise http_exc
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Unexpected error: {str(e)}")
# #END Get
if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000, log_level="debug")