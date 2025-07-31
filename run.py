from fastapi import FastAPI, Request, Depends, HTTPException, status
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from pydantic import BaseModel
from typing import List, Optional
import requests
import csv
import os
from openai import OpenAI
import time
import re
import json
from fastapi.middleware.cors import CORSMiddleware
import mysql.connector
from jose import JWTError, jwt
from passlib.context import CryptContext
from dotenv import load_dotenv

# Load environment variables
load_dotenv()

# MySQL connection details from environment variables
MYSQL_HOST = os.getenv('MYSQL_HOST', 'localhost')
MYSQL_DB = os.getenv('MYSQL_DB', 'cs')
MYSQL_USER = os.getenv('MYSQL_USER', 'root')
MYSQL_PASSWORD = os.getenv('MYSQL_PASSWORD')
MYSQL_PORT = int(os.getenv('MYSQL_PORT', 3306))

app = FastAPI()

# --- USER AUTH SETUP ---
SECRET_KEY = os.getenv('SECRET_KEY')
ALGORITHM = os.getenv('ALGORITHM', 'HS256')
ACCESS_TOKEN_EXPIRE_SECONDS = int(os.getenv('ACCESS_TOKEN_EXPIRE_SECONDS', 4000))
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/login")

# User model for registration
class UserCreate(BaseModel):
    username: str
    password: str

# Helper: get DB connection
def get_db():
    return mysql.connector.connect(
        host=MYSQL_HOST,
        database=MYSQL_DB,
        user=MYSQL_USER,
        password=MYSQL_PASSWORD,
        port=MYSQL_PORT
    )

# Helper: create users table if not exists
def create_users_table():
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INT AUTO_INCREMENT PRIMARY KEY,
            username VARCHAR(255) UNIQUE NOT NULL,
            hashed_password VARCHAR(255) NOT NULL
        )
    """)
    conn.commit()
    cursor.close()
    conn.close()

# Helper: create report history table if not exists
def create_history_table():
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS report_history (
            id INT AUTO_INCREMENT PRIMARY KEY,
            user_id INT NOT NULL,
            idea VARCHAR(255) NOT NULL,
            report_type VARCHAR(50) NOT NULL,
            country VARCHAR(255) NOT NULL,
            state VARCHAR(255),
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
        )
    """)
    conn.commit()
    cursor.close()
    conn.close()

create_users_table()
create_history_table()

# Helper: get user by username
def get_user(username: str):
    conn = get_db()
    cursor = conn.cursor(dictionary=True)
    cursor.execute("SELECT * FROM users WHERE username=%s", (username,))
    user = cursor.fetchone()
    cursor.close()
    conn.close()
    return user

# Helper: create user
def create_user(username: str, password: str):
    hashed_password = pwd_context.hash(password)
    conn = get_db()
    cursor = conn.cursor()
    try:
        cursor.execute("INSERT INTO users (username, hashed_password) VALUES (%s, %s)", (username, hashed_password))
        conn.commit()
    except mysql.connector.IntegrityError:
        cursor.close()
        conn.close()
        return False
    cursor.close()
    conn.close()
    return True

# Helper: verify password
def verify_password(plain_password, hashed_password):
    return pwd_context.verify(plain_password, hashed_password)

# Helper: create JWT token
def create_access_token(data: dict, expires_delta: Optional[int] = None):
    to_encode = data.copy()
    expire = time.time() + (expires_delta or ACCESS_TOKEN_EXPIRE_SECONDS)
    to_encode.update({"exp": int(expire)})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt

# Helper: save report to history
def save_report_history(user_id: int, idea: str, report_type: str, country: str, state: str = None):
    conn = get_db()
    cursor = conn.cursor()
    try:
        cursor.execute("""
            INSERT INTO report_history (user_id, idea, report_type, country, state) 
            VALUES (%s, %s, %s, %s, %s)
        """, (user_id, idea, report_type, country, state))
        conn.commit()
        return cursor.lastrowid
    except Exception as e:
        print(f"Error saving history: {e}")
        return None
    finally:
        cursor.close()
        conn.close()

# Helper: get user's report history
def get_user_history(user_id: int):
    conn = get_db()
    cursor = conn.cursor(dictionary=True)
    try:
        cursor.execute("""
            SELECT id, idea, report_type, country, state, created_at 
            FROM report_history 
            WHERE user_id = %s 
            ORDER BY created_at DESC
        """, (user_id,))
        history = cursor.fetchall()
        return history
    except Exception as e:
        print(f"Error getting history: {e}")
        return []
    finally:
        cursor.close()
        conn.close()

# Register endpoint
@app.post("/register")
def register(user: UserCreate):
    if get_user(user.username):
        raise HTTPException(status_code=400, detail="Username already registered")
    if create_user(user.username, user.password):
        return {"msg": "User registered successfully"}
    else:
        raise HTTPException(status_code=400, detail="Registration failed")

# Login endpoint
@app.post("/login")
def login(form_data: OAuth2PasswordRequestForm = Depends()):
    user = get_user(form_data.username)
    if not user or not verify_password(form_data.password, user["hashed_password"]):
        raise HTTPException(status_code=401, detail="Incorrect username or password")
    access_token = create_access_token(data={"sub": user["username"]})
    return {"access_token": access_token, "token_type": "bearer"}

# Dependency: get current user from JWT
def get_current_user(token: str = Depends(oauth2_scheme)):
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        username: str = payload.get("sub")
        if username is None:
            raise credentials_exception
    except JWTError:
        raise credentials_exception
    user = get_user(username)
    if user is None:
        raise credentials_exception
    return user

# --- END USER AUTH SETUP ---

# API Configuration from environment variables
QLOO_API_KEY = os.getenv('QLOO_API_KEY')
OPENAI_API_KEY = os.getenv('OPENAI_API_KEY')
SEARCH_URL = os.getenv('SEARCH_URL', 'https://hackathon.api.qloo.com/search')
INSIGHT_URL = os.getenv('INSIGHT_URL', 'https://hackathon.api.qloo.com/v2/insights')
FALLBACK_CSV = os.getenv('FALLBACK_CSV', 'tags.csv')
TIMEOUT = int(os.getenv('TIMEOUT', 30))

client = OpenAI(api_key=OPENAI_API_KEY)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["https://qloo-hackathon-frontend.vercel.app"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

fallback_tags = {}
if os.path.exists(FALLBACK_CSV):
    with open(FALLBACK_CSV, newline='', encoding='utf-8') as f:
        reader = csv.DictReader(f)
        for row in reader:
            key = row['seed_word'].lower()
            fallback_tags.setdefault(key, []).append(row)

class BusinessRequest(BaseModel):
    idea: str
    country: str
    report_type: Optional[str] = "country"
    state: Optional[str] = None

def get_tag_id(query):
    headers = {"X-Api-Key": QLOO_API_KEY}
    params = {"query": query, "types": "tag"}
    try:
        res = requests.get(SEARCH_URL, headers=headers, params=params, timeout=TIMEOUT)
        data = res.json()
        if "results" in data and data["results"]:
            return data["results"][0]["id"]
    except Exception:
        pass

    if query.lower() in fallback_tags:
        return fallback_tags[query.lower()][0]['tag_id']
    for seed, entries in fallback_tags.items():
        if seed in query.lower():
            return entries[0]['tag_id']
    return None

def get_top_cities(country):
    prompt = f"List the 8 most business-friendly and culturally active cities in {country} for launching new businesses."
    try:
        res = client.chat.completions.create(
            model="gpt-3.5-turbo",
            messages=[
                {"role": "system", "content": "You are a helpful assistant that suggests great cities for business."},
                {"role": "user", "content": prompt}
            ]
        )
        content = res.choices[0].message.content
        return [c.strip("-\u2022 ").strip() for c in content.split("\n") if c.strip()][:8]
    except Exception:
        return []

def fetch_insights(city, tag_id):
    headers = {"X-Api-Key": QLOO_API_KEY}
    params = {
        "filter.location.query": city,
        "filter.location.radius": 15000,
        "signal.interests.tags": tag_id,
        "filter.type": "urn:entity:place",
        "take": 10,
        "sort_by": "affinity"
    }
    try:
        res = requests.get(INSIGHT_URL, headers=headers, params=params, timeout=TIMEOUT)
        return res.json() if res.status_code == 200 else {}
    except Exception:
        return {}

def compute_scores(entities):
    affinities = [e.get("affinity", 0) for e in entities if e.get("affinity") is not None]
    popularities = [e.get("popularity", 0) for e in entities if e.get("popularity") is not None]
    aff_avg = sum(affinities) / len(affinities) if affinities else 0
    pop_avg = sum(popularities) / len(popularities) if popularities else 0
    return aff_avg, pop_avg

def get_gpt_extras(idea, city):
    prompt = f"""
You are a helpful business assistant.

For a '{idea}' business in {city}, return exactly 4 detailed entries for each of these:

1. **Influencers**: name, niche, short bio, contact (email/link), and platform
2. **Inventory Suppliers**: name, inventory_type, location, contact (email/phone/link), and website
3. **Real Estate Agents**: name, specialization, agency, contact (email/phone/link), and website

Also include:
- A short 'subheading' summarizing the city's opportunity in 1 sentence
- A 1-paragraph 'business pitch'

Respond ONLY in this JSON format:

{{
  "subheading": "string",
  "gpt_insights": "string",
  "influencers": [{{"name": "string", "niche": "string", "bio": "string", "contact": "string", "platform": "string"}}],
  "inventory": [{{"name": "string", "inventory_type": "string", "location": "string", "contact": "string", "website": "string"}}],
  "agents": [{{"name": "string", "specialization": "string", "agency": "string", "contact": "string", "website": "string"}}]
}}

Only return valid JSON. Do not include anything else.
"""
    try:
        res = client.chat.completions.create(
            model="gpt-3.5-turbo",
            messages=[{"role": "user", "content": prompt}],
            temperature=0.7
        )
        content = res.choices[0].message.content.strip()
        json_start = content.find("{")
        json_end = content.rfind("}") + 1
        return json.loads(content[json_start:json_end])
    except Exception as e:
        return {
            "subheading": f"{city} shows business viability for a {idea} venture.",
            "gpt_insights": f"{idea} businesses can thrive in {city} given its demographics and market trends.",
            "influencers": [
                {"name": "John Doe", "niche": "Fitness", "bio": "Popular local trainer", "contact": "john@example.com", "platform": "Instagram"}
            ] * 4,
            "inventory": [
                {"name": "Supplier Co", "inventory_type": "Fitness gear", "location": "Downtown", "contact": "supplier@example.com", "website": "https://supplier.com"}
            ] * 4,
            "agents": [
                {"name": "Agent X", "specialization": "Retail", "agency": "Urban Realty", "contact": "agent@example.com", "website": "https://urbanrealty.com"}
            ] * 4
        }

@app.post("/analyze")
def analyze(data: BusinessRequest, current_user: dict = Depends(get_current_user)):
    idea = data.idea
    country = data.country
    report_type = data.report_type or "country"
    state = data.state
    print(data)
    
    # Save to history
    save_report_history(current_user["id"], idea, report_type, country, state)
    
    tag_id = get_tag_id(idea)
    if not tag_id:
        return {"error": f"Could not find a tag for '{idea}'"}

    # Use state for analysis if report_type is "state", otherwise use country
    location_for_analysis = state if report_type == "state" and state else country
    cities = get_top_cities(location_for_analysis)
    results = []

    for city in cities:
        insights = fetch_insights(city, tag_id)
        entities = insights.get("results", {}).get("entities", [])
        aff, pop = compute_scores(entities)
        score = round(((aff + pop) / 2) * 100, 1)

        enriched_places = []
        for e in entities:
            enriched_places.append({
                "name": e.get("name"),
                "address": e.get("properties", {}).get("address"),
                "phone": e.get("properties", {}).get("phone"),
                "website": e.get("properties", {}).get("website"),
                "tags": [t["name"] for t in e.get("tags", [])],
                "map_url": f"https://maps.google.com/?q={e['location'].get('lat')},{e['location'].get('lon')}"
                    if e.get("location") else None
            })

        gpt_data = get_gpt_extras(idea, city)

        results.append({
            "city": city,
            "subheading": gpt_data.get("subheading", ""),
            "gpt_insights": gpt_data.get("gpt_insights", ""),
            "influencers": gpt_data.get("influencers", []),
            "inventory": gpt_data.get("inventory", []),
            "agents": gpt_data.get("agents", []),
            "popular_places": enriched_places,
            "score": score,
            "audience_match": round(aff * 100, 1),
            "general_demand": round(pop * 100, 1)
        })

        time.sleep(1)

    return {
        "idea": idea,
        "country": country,
        "state": state,
        "report_type": report_type,
        "location_analyzed": location_for_analysis,
        "tag_id": tag_id,
        "cities": results
    }

@app.get("/me")
def read_users_me(current_user: dict = Depends(get_current_user)):
    return {"username": current_user["username"]}

@app.get("/countries")
def get_countries():
    try:
        conn = mysql.connector.connect(
            host=MYSQL_HOST,
            database=MYSQL_DB,
            user=MYSQL_USER,
            password=MYSQL_PASSWORD,
            port=MYSQL_PORT
        )
        cursor = conn.cursor()
        cursor.execute("SELECT id, name FROM countries;")
        rows = cursor.fetchall()
        countries = [{"id": row[0], "name": row[1]} for row in rows]
        cursor.close()
        conn.close()
        return {"countries": countries}
    except Exception as e:
        return {"error": str(e)}

@app.get("/states/{country_id}")
def get_states(country_id: int):
    try:
        conn = mysql.connector.connect(
            host=MYSQL_HOST,
            database=MYSQL_DB,
            user=MYSQL_USER,
            password=MYSQL_PASSWORD,
            port=MYSQL_PORT
        )
        cursor = conn.cursor()
        cursor.execute("SELECT id, name FROM states WHERE country_id = %s;", (country_id,))
        rows = cursor.fetchall()
        states = [{"id": row[0], "name": row[1]} for row in rows]
        cursor.close()
        conn.close()
        return {"states": states}
    except Exception as e:
        return {"error": str(e)}

@app.get("/history")
def get_report_history(current_user: dict = Depends(get_current_user)):
    try:
        history = get_user_history(current_user["id"])
        return {"history": history}
    except Exception as e:
        return {"error": str(e)}
