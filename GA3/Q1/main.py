import asyncio
import hashlib
import json
import os
import sqlite3
import uuid
import re
import httpx
from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse

app = FastAPI()

# Lock to prevent race conditions
db_lock = asyncio.Lock()

# Render provides the domain, which you will set in the dashboard
PUBLIC_BASE_URL = os.environ.get("PUBLIC_BASE_URL", "https://your-app.onrender.com/a2a")
DB_PATH = "a2a_invoice.db"

# ==========================================
# 1. DATABASE SETUP
# ==========================================
def init_db():
    with sqlite3.connect(DB_PATH) as conn:
        conn.execute("""
            CREATE TABLE IF NOT EXISTS tasks (
                task_id TEXT PRIMARY KEY,
                principal TEXT NOT NULL,
                context_id TEXT NOT NULL,
                batch_id TEXT NOT NULL,
                state TEXT NOT NULL,
                proposals_json TEXT NOT NULL,
                task_json TEXT NOT NULL,
                created_at INTEGER DEFAULT (strftime('%s', 'now'))
            )
        """)
        conn.execute("""
            CREATE TABLE IF NOT EXISTS idempotency (
                principal TEXT NOT NULL,
                message_id TEXT NOT NULL,
                msg_hash TEXT NOT NULL,
                response_json TEXT NOT NULL,
                status_code INTEGER NOT NULL,
                PRIMARY KEY (principal, message_id)
            )
        """)
        conn.execute("""
            CREATE TABLE IF NOT EXISTS package_cache (
                pkg_hash TEXT PRIMARY KEY,
                decision_json TEXT NOT NULL
            )
        """)
init_db()

def canonical_hash(obj) -> str:
    raw = json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()

def a2a_response(data: dict, status_code: int = 200) -> JSONResponse:
    return JSONResponse(content=data, status_code=status_code, media_type="application/a2a+json")

def generic_error(status_code: int, code: str, message: str) -> JSONResponse:
    return JSONResponse(
        content={"error": {"code": code, "message": message}},
        status_code=status_code,
        media_type="application/a2a+json"
    )

# ==========================================
# 2. SECURITY & AUTHENTICATION
# ==========================================
def verify_auth(request: Request):
    auth = request.headers.get("Authorization", "")
    if not auth.startswith("Bearer "):
        return None, generic_error(401, "UNAUTHORIZED", "Missing Bearer token")
    token = auth[len("Bearer "):].strip()
    
    if request.headers.get("A2A-Version") != "1.0":
        return None, generic_error(400, "UNSUPPORTED_VERSION", "A2A-Version 1.0 required")
        
    return token, None

# ==========================================
# 3. AI DECISION ENGINE (OPENAI / AIPIPE)
# ==========================================
SYSTEM_PROMPT = """You are an expert Accounts Payable Audit Engine.
Evaluate each package and return a JSON object with a single key "decisions" containing one decision per package index.

RULES FOR ACTIONS (Strict Priority):
1. "reject_duplicate": SAME commercial invoice (vendor & invoice number) is ALREADY PAID in ledger.
2. "open_exception": Material records conflict (amount mismatch, rejected goods, wrong vendor).
3. "hold_invoice": Payment must pause for verification, tax clearance, or inspection.
4. "request_approval": Valid and matched, but amount exceeds autonomous authority limit.
5. "settle_invoice": Valid, matched, not paid, no holds, AND within autonomous authority limit.

RULES FOR OUTPUT:
- facts.amountMinor MUST be an integer of the minor currency unit.
- evidenceRefs MUST be EXACTLY 3 bracketed references (e.g., "[DOC-12]") from the decisive operational paragraph.
- rationale MUST be 60-1500 chars, explicitly name the action, and cite at least two evidenceRefs.
"""

async def decide_batch_packages(policy_revision: str, packages: list) -> list:
    proposals = []
    uncached_items = []

    with sqlite3.connect(DB_PATH) as conn:
        for pkg in packages:
            pkg_id = pkg["packageId"]
            content_only = {k: v for k, v in pkg.items() if k != "packageId"}
            pkg_hash = canonical_hash({"policyRevision": policy_revision, "content": content_only})

            row = conn.execute("SELECT decision_json FROM package_cache WHERE pkg_hash = ?", (pkg_hash,)).fetchone()
            if row:
                cached_decision = json.loads(row[0])
                proposals.append({"packageId": pkg_id, "actionId": f"act_{uuid.uuid4().hex[:16]}", **cached_decision})
            else:
                uncached_items.append((pkg_id, pkg_hash, content_only))

    if uncached_items:
        batch_input = {
            "policyRevision": policy_revision,
            "packages": [{"index": idx, "content": c} for idx, (_, _, c) in enumerate(uncached_items)]
        }
        
        api_key = os.environ.get("OPENAI_API_KEY")
        base_url = os.environ.get("OPENAI_BASE_URL", "https://api.openai.com/v1").rstrip("/")
        
        if not api_key:
            raise RuntimeError("OPENAI_API_KEY environment variable is not set.")

        url = f"{base_url}/chat/completions"
        payload = {
            "model": "gpt-4o-mini",
            "temperature": 0.0,
            "response_format": {"type": "json_object"},
            "messages": [
                {"role": "system", "content": SYSTEM_PROMPT},
                {"role": "user", "content": json.dumps(batch_input)}
            ]
        }
        headers = {
            "Authorization": f"Bearer {api_key}",
            "Content-Type": "application/json"
        }

        async with httpx.AsyncClient(timeout=45.0) as client:
            resp = await client.post(url, json=payload, headers=headers)
            resp.raise_for_status()
            raw_json = resp.json()["choices"][0]["message"]["content"]

        parsed = json.loads(raw_json)
        decisions_list = {item["index"]: item for item in parsed.get("decisions", [])}

        with sqlite3.connect(DB_PATH) as conn:
            for idx, (pkg_id, pkg_hash, content) in enumerate(uncached_items):
                decision = decisions_list[idx]
                
                raw_text = json.dumps(content)
                doc_tags = {t[1:-1]: t for t in set(re.findall(r"\[[A-Za-z0-9_.:/-]+\]", raw_text))}
                decision["evidenceRefs"] = [doc_tags.get(str(r).strip(), str(r).strip()) for r in decision.get("evidenceRefs", [])][:3]
                
                conn.execute("INSERT OR REPLACE INTO package_cache (pkg_hash, decision_json) VALUES (?, ?)", (pkg_hash, json.dumps(decision)))
                proposals.append({"packageId": pkg_id, "actionId": f"act_{uuid.uuid4().hex[:16]}", **decision})

    order_map = {p["packageId"]: i for i, p in enumerate(packages)}
    proposals.sort(key=lambda x: order_map[x["packageId"]])
    return proposals

# ==========================================
# 4. API ROUTES
# ==========================================
@app.get("/.well-known/agent-card.json")
async def get_agent_card():
    return a2a_response({
        "name": "Invoice Action Agent", "description": "Processes invoices safely.", "version": "1.0.0",
        "capabilities": {"streaming": False, "pushNotifications": False, "stateTransitionHistory": True},
        "supportedInterfaces": [{"url": PUBLIC_BASE_URL, "protocolBinding": "HTTP+JSON", "protocolVersion": "1.0"}],
        "defaultInputModes": ["application/vnd.ga5.invoice-claim-batch+json", "application/vnd.ga5.invoice-action-results+json"],
        "defaultOutputModes": ["application/vnd.ga5.invoice-action-proposals+json", "application/vnd.ga5.invoice-action-receipts+json"],
        "skills": [{"id": "invoice_action_agent", "name": "Invoice Agent", "description": "Agent", "tags": ["invoice"]}]
    })

@app.post("/a2a/message:send")
async def message_send(request: Request):
    principal, err = verify_auth(request)
    if err: return err

    body = await request.json()
    msg = body.get("message", {})
    message_id = msg.get("messageId")
    msg_hash = canonical_hash(msg)

    async with db_lock:
        with sqlite3.connect(DB_PATH) as conn:
            row = conn.execute("SELECT msg_hash, response_json, status_code FROM idempotency WHERE principal=? AND message_id=?", (principal, message_id)).fetchone()
            if row:
                if row[0] != msg_hash: return generic_error(409, "CONFLICT", "ID reused with different content")
                return a2a_response(json.loads(row[1]), row[2])

        media_type = msg.get("parts", [{}])[0].get("mediaType")
        data = msg.get("parts", [{}])[0].get("data", {})

        if media_type == "application/vnd.ga5.invoice-claim-batch+json":
            task_id = msg.get("taskId") or f"task_{uuid.uuid4().hex}"
            context_id = msg.get("contextId") or f"ctx_{uuid.uuid4().hex}"
            
            proposals = await decide_batch_packages(data.get("policyRevision"), data.get("packages", []))
            
            task_obj = {
                "id": task_id, "contextId": context_id, "status": {"state": "TASK_STATE_INPUT_REQUIRED"}, "history": [msg],
                "artifacts": [{
                    "artifactId": f"art_{uuid.uuid4().hex}", "name": "proposals",
                    "parts": [{"mediaType": "application/vnd.ga5.invoice-action-proposals+json", "data": {"batchId": data.get("batchId"), "proposals": proposals}}]
                }]
            }
            with sqlite3.connect(DB_PATH) as conn:
                conn.execute("INSERT INTO tasks VALUES (?, ?, ?, ?, ?, ?, ?, ?)", 
                             (task_id, principal, context_id, data.get("batchId"), "TASK_STATE_INPUT_REQUIRED", json.dumps(proposals), json.dumps(task_obj), 0))
                conn.execute("INSERT INTO idempotency VALUES (?, ?, ?, ?, ?)", (principal, message_id, msg_hash, json.dumps({"task": task_obj}), 200))
            return a2a_response({"task": task_obj})

        elif media_type == "application/vnd.ga5.invoice-action-results+json":
            task_id, batch_id = msg.get("taskId"), data.get("batchId")
            with sqlite3.connect(DB_PATH) as conn:
                row = conn.execute("SELECT principal, state, proposals_json, task_json FROM tasks WHERE task_id=?", (task_id,)).fetchone()
                if not row or row[0] != principal: return generic_error(404, "NOT_FOUND", "Task not found")
                if row[1] != "TASK_STATE_INPUT_REQUIRED": return generic_error(409, "TERMINAL", "Task already terminal")
                
                stored_props = {p["packageId"]: p for p in json.loads(row[2])}
                executions = []
                
                for res in data.get("results", []):
                    pid = res.get("packageId")
                    orig = stored_props.get(pid)
                    if not orig or res.get("actionId") != orig["actionId"] or res.get("action") != orig["action"]:
                        return generic_error(409, "MISMATCH", "Results don't match proposals")
                    if res.get("outcome") == "ACCEPTED":
                        executions.append({**orig, "receiptNonce": res.get("receiptNonce")})

                task_obj = json.loads(row[3])
                task_obj["history"].append(msg)
                task_obj["status"] = {"state": "TASK_STATE_COMPLETED"}
                task_obj["artifacts"].append({
                    "artifactId": f"art_{uuid.uuid4().hex}", "name": "receipts",
                    "parts": [{"mediaType": "application/vnd.ga5.invoice-action-receipts+json", "data": {"batchId": batch_id, "executions": executions}}]
                })
                
                conn.execute("UPDATE tasks SET state=?, task_json=? WHERE task_id=?", ("TASK_STATE_COMPLETED", json.dumps(task_obj), task_id))
                conn.execute("INSERT INTO idempotency VALUES (?, ?, ?, ?, ?)", (principal, message_id, msg_hash, json.dumps({"task": task_obj}), 200))
            return a2a_response({"task": task_obj})

@app.get("/a2a/tasks")
async def list_tasks(request: Request):
    principal, err = verify_auth(request)
    if err: return err
    with sqlite3.connect(DB_PATH) as conn:
        tasks = [json.loads(r[0]) for r in conn.execute("SELECT task_json FROM tasks WHERE principal=?", (principal,)).fetchall()]
        return a2a_response({"tasks": tasks})

@app.get("/a2a/tasks/{task_id}")
async def get_task(task_id: str, request: Request):
    principal, err = verify_auth(request)
    if err: return err
    with sqlite3.connect(DB_PATH) as conn:
        row = conn.execute("SELECT principal, task_json FROM tasks WHERE task_id=?", (task_id,)).fetchone()
        if not row or row[0] != principal: return generic_error(404, "NOT_FOUND", "Task not found")
        return a2a_response(json.loads(row[1]))

@app.post("/a2a/tasks/{task_id}:cancel")
async def cancel_task(task_id: str, request: Request):
    principal, err = verify_auth(request)
    if err: return err
    async with db_lock:
        with sqlite3.connect(DB_PATH) as conn:
            row = conn.execute("SELECT principal, state, task_json FROM tasks WHERE task_id=?", (task_id,)).fetchone()
            if not row or row[0] != principal: return generic_error(404, "NOT_FOUND", "Task not found")
            if row[1] != "TASK_STATE_INPUT_REQUIRED": return generic_error(409, "TERMINAL", "Already terminal")
            
            task_obj = json.loads(row[2])
            task_obj["status"] = {"state": "TASK_STATE_CANCELED"}
            conn.execute("UPDATE tasks SET state=?, task_json=? WHERE task_id=?", ("TASK_STATE_CANCELED", json.dumps(task_obj), task_id))
            return a2a_response(task_obj)
