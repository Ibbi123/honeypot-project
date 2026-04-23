from fastapi import FastAPI, Request
from fastapi.responses import FileResponse
import sqlite3
from datetime import datetime
import json
import os
import csv

app = FastAPI()

DB_PATH = os.getenv("DB_PATH", "honeypot.db")
CSV_PATH = os.getenv("CSV_PATH", "request_logs.csv")

conn = sqlite3.connect(DB_PATH, check_same_thread=False)
cursor = conn.cursor()

cursor.execute("""
CREATE TABLE IF NOT EXISTS request_logs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    ip_address TEXT,
    timestamp TEXT,
    endpoint TEXT,
    method TEXT,
    status_code INTEGER,
    user_agent TEXT,
    query_params TEXT,
    headers TEXT,
    request_body TEXT
)
""")
conn.commit()


def ensure_csv_exists() -> None:
    if not os.path.exists(CSV_PATH):
        with open(CSV_PATH, "w", newline="", encoding="utf-8") as file:
            writer = csv.writer(file)
            writer.writerow([
                "ip_address",
                "timestamp",
                "endpoint",
                "method",
                "status_code",
                "user_agent",
                "query_params",
                "headers",
                "request_body",
            ])


ensure_csv_exists()


async def log_request(request: Request, status_code: int) -> None:
    ip_address = request.client.host if request.client else "unknown"
    timestamp = datetime.utcnow().isoformat()
    endpoint = request.url.path
    method = request.method
    user_agent = request.headers.get("user-agent", "unknown")
    query_params = str(request.query_params)
    headers = json.dumps(dict(request.headers))

    body_bytes = await request.body()
    request_body = body_bytes.decode("utf-8", errors="ignore") if body_bytes else ""

    cursor.execute("""
        INSERT INTO request_logs (
            ip_address,
            timestamp,
            endpoint,
            method,
            status_code,
            user_agent,
            query_params,
            headers,
            request_body
        )
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
    """, (
        ip_address,
        timestamp,
        endpoint,
        method,
        status_code,
        user_agent,
        query_params,
        headers,
        request_body
    ))
    conn.commit()

    with open(CSV_PATH, "a", newline="", encoding="utf-8") as file:
        writer = csv.writer(file)
        writer.writerow([
            ip_address,
            timestamp,
            endpoint,
            method,
            status_code,
            user_agent,
            query_params,
            headers,
            request_body,
        ])


@app.get("/")
async def home(request: Request):
    await log_request(request, 200)
    return {"message": "Welcome"}


@app.post("/login")
async def login_post(request: Request):
    await log_request(request, 401)
    return {"message": "Unauthorized"}


@app.get("/admin")
async def admin(request: Request):
    await log_request(request, 403)
    return {"message": "Forbidden"}


@app.get("/api/data")
async def api_data(request: Request):
    await log_request(request, 200)
    return {"data": "fake data"}


@app.get("/config")
async def config(request: Request):
    await log_request(request, 404)
    return {"error": "Not found"}


@app.api_route("/{path:path}", methods=["GET", "POST", "PUT", "DELETE"])
async def catch_all(request: Request, path: str):
    await log_request(request, 404)
    return {"error": "Not found"}

@app.get("/download-logs")
async def download_logs():
    return FileResponse(CSV_PATH, filename="request_logs.csv")

@app.post("/clear-logs")
async def clear_logs():
    open(CSV_PATH, "w").close()
    ensure_csv_exists()
    return {"message": "Logs cleared"}
