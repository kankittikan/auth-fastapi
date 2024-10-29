from fastapi import FastAPI, HTTPException, Request
import jwt
import os
from datetime import datetime, timedelta, timezone
from dotenv import load_dotenv
import uuid

load_dotenv()

app = FastAPI()
secret = os.getenv("SECRET")
refresh_secret = os.getenv("REFRESH_SECRET")
access_exp_minutes = int(os.getenv("ACCESS_MINUTES"))
refresh_exp_days = int(os.getenv("REFRESH_DAYS"))

session = {}

@app.get("/isauth")
async def is_auth(token: str = ''):
    if not token:
        raise HTTPException(status_code=400, detail="Token not found")   
    try:
        jwt.decode(token, secret, algorithms=["HS256"])
    except jwt.ExpiredSignatureError:
        raise HTTPException(status_code=400, detail="Expired token")
    except jwt.DecodeError:
        raise HTTPException(status_code=400, detail="Invalid token")
    
    return {"detail": "OK"}

@app.post('/issue')
async def issue(username: str = '', password: str = '', request: Request = None):
    # client ip address
    client_host = request.headers.get('X-Forward-For') or request.client.host

    # auth credentials
    if not (username == 'a' and password == 'b'):
        raise HTTPException(status_code=400, detail="username or password invalid")
    
    exp = datetime.now(tz=timezone.utc) + timedelta(minutes=access_exp_minutes)
    exp_refresh = datetime.now(tz=timezone.utc) + timedelta(days=refresh_exp_days)

    session_id = str(uuid.uuid4())
    payload = {"client_host": client_host,
               "session_id": session_id}
    
    access_payload = payload.copy()
    access_payload.update({"exp": exp})
    refresh_payload = payload.copy()
    refresh_payload.update({"exp": exp_refresh})

    access_token = jwt.encode(access_payload, secret)
    refresh_token = jwt.encode(refresh_payload, refresh_secret)

    session.update({client_host: session_id})

    return {"mode": "issue",
            "access_token": access_token,
            "refresh_token": refresh_token}

@app.post('/reissue')
async def issue(refresh_token: str = '', access_token: str = '', request: Request = None):
    client_host = request.headers.get('X-Forward-For') or request.client.host
    
    access_payload = None
    refresh_payload = None

    try:
        refresh_payload = jwt.decode(refresh_token, refresh_secret, algorithms=["HS256"])
    except jwt.ExpiredSignatureError:
        raise HTTPException(status_code=400, detail="Expired refresh token")
    except jwt.DecodeError:
        raise HTTPException(status_code=400, detail="Invalid refresh token")

    try:
        access_payload = jwt.decode(access_token, secret, algorithms=["HS256"], verify=False)
    except jwt.DecodeError:
        raise HTTPException(status_code=400, detail="Invalid access token")
    
    # payload validation
    if access_payload.get("client_host") != client_host or refresh_payload.get("client_host") != client_host:
        raise HTTPException(status_code=400, detail="Client host invalid")
    if access_payload.get("session_id") != refresh_payload.get("session_id"):
        raise HTTPException(status_code=400, detail="Session invalid")
    if session.get(client_host) != access_payload.get("session_id"):
        raise HTTPException(status_code=400, detail="Session not found")

    exp = datetime.now(tz=timezone.utc) + timedelta(minutes=access_exp_minutes)
    exp_refresh = datetime.now(tz=timezone.utc) + timedelta(days=refresh_exp_days)

    access_payload.update({"exp": exp})
    refresh_payload.update({"exp": exp_refresh})

    access_token = jwt.encode(access_payload, secret)
    refresh_token = jwt.encode(refresh_payload, refresh_secret)

    return {"mode": "reissue",
            "access_token": access_token,
            "refresh_token": refresh_token}