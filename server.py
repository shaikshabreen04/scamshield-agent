"""
Scam Buster — Local AI Agent API Bridge Server & SQLite Persistence
Connects the frontend UI to the OpenRouter AI Agent in agent.py
Provides SQLite persistence for scan history and serves the frontend dashboard.
"""

import sys
import json
import os
import sqlite3
import uuid
import datetime
from http.server import HTTPServer, SimpleHTTPRequestHandler

# Ensure UTF-8 output encoding for emojis on Windows
if sys.platform == "win32":
    import codecs
    try:
        sys.stdout = codecs.getwriter("utf-8")(sys.stdout.detach())
    except Exception:
        pass

# Import the Real AI Agent and structured analysis functions
try:
    from agent import agent, scam_agent, analyze_scam_structured, extract_deterministic_signals
    print("✓ Successfully connected to Real AI Agent Architecture from agent.py")
except Exception as e:
    agent = None
    scam_agent = None
    analyze_scam_structured = None
    extract_deterministic_signals = None
    print(f"⚠️ Warning: Could not import from agent.py: {e}")

PORT = 5000
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
FRONTEND_DIR = os.path.join(BASE_DIR, "frontend")
DB_PATH = os.path.join(BASE_DIR, "scam_history.db")

# ==============================================================================
# Database Initialization & Helpers
# ==============================================================================
def init_db():
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS scan_records (
        id TEXT PRIMARY KEY,
        created_at TEXT NOT NULL,
        message TEXT NOT NULL,
        snippet TEXT NOT NULL,
        risk_level TEXT NOT NULL,
        risk_score INTEGER NOT NULL,
        confidence TEXT NOT NULL,
        message_intent TEXT NOT NULL,
        summary TEXT NOT NULL,
        warning_signs_json TEXT NOT NULL,
        positive_indicators_json TEXT NOT NULL,
        limitations_json TEXT NOT NULL,
        actions_json TEXT NOT NULL,
        checklist_json TEXT NOT NULL,
        source TEXT NOT NULL
    )
    """)
    conn.commit()

    # Check if empty, seed with initial realistic records if so
    cursor.execute("SELECT COUNT(*) FROM scan_records")
    count = cursor.fetchone()[0]
    if count == 0:
        seed_records = [
            {
                "id": "SB-C77B529B",
                "created_at": (datetime.datetime.now(datetime.timezone.utc) - datetime.timedelta(minutes=4)).isoformat(),
                "message": "Dear customer, congratulations! Your mobile number has won a cash prize of Rs 25,00,000 from KBC WhatsApp Lucky Draw. To claim your prize money, send your bank account details and pay Rs 1,500 government processing fee to WhatsApp number +91-9876543210.",
                "snippet": "Dear customer, congratulations! Your mobile number has won a cash prize of Rs 25,00,000...",
                "risk_level": "high",
                "risk_score": 95,
                "confidence": "high",
                "message_intent": "Lottery Scam / Advance-Fee Fraud",
                "summary": "This is an advance-fee lottery fraud claiming unverified prize winnings to solicit an upfront processing fee and extract sensitive banking credentials.",
                "warning_signs_json": json.dumps([
                    {"title": "False Lottery Claim", "desc": "Unsolicited prize notification with zero prior ticket entry.", "severity": "high", "evidence": "won a cash prize of Rs 25,00,000 from KBC WhatsApp Lucky Draw"},
                    {"title": "Upfront Payment Demand", "desc": "Demands government processing fee to unlock funds.", "severity": "high", "evidence": "pay Rs 1,500 government processing fee"}
                ]),
                "positive_indicators_json": json.dumps(["None detected"]),
                "limitations_json": json.dumps(["External WhatsApp chat not verified"]),
                "actions_json": json.dumps(["Never pay upfront fees to claim prizes", "Block and report the sender"]),
                "checklist_json": json.dumps(["Legitimate lotteries do not ask for transfer fees"]),
                "source": "seed_data"
            },
            {
                "id": "SB-BFBDE7EA",
                "created_at": (datetime.datetime.now(datetime.timezone.utc) - datetime.timedelta(minutes=18)).isoformat(),
                "message": "URGENT: Your State Bank account 4921 has been restricted due to incomplete PAN / KYC records. Tap http://bit.ly/sbi-verify-kyc within 24 hours to prevent permanent account suspension.",
                "snippet": "URGENT: Your State Bank account 4921 has been restricted due to incomplete PAN / KYC records...",
                "risk_level": "high",
                "risk_score": 92,
                "confidence": "high",
                "message_intent": "Credential Phishing / Account Suspension Scam",
                "summary": "Coercive credential harvesting attack impersonating a bank with false urgency and deceptive link shorteners to steal netbanking logins.",
                "warning_signs_json": json.dumps([
                    {"title": "URL Shortener Obfuscation", "desc": "Deceptive bit.ly link hiding destination server.", "evidence": "http://bit.ly/sbi-verify-kyc"},
                    {"title": "False Urgency and Account Threat", "desc": "Threatens permanent account restriction within 24 hours.", "evidence": "within 24 hours to prevent permanent account suspension"}
                ]),
                "positive_indicators_json": json.dumps(["None detected"]),
                "limitations_json": json.dumps(["Cannot query live bank account status"]),
                "actions_json": json.dumps(["Do not tap the bit.ly link", "Verify via official bank portal"]),
                "checklist_json": json.dumps(["Banks never send shortened links for KYC updates"]),
                "source": "seed_data"
            },
            {
                "id": "SB-8E31A7F2",
                "created_at": (datetime.datetime.now(datetime.timezone.utc) - datetime.timedelta(minutes=45)).isoformat(),
                "message": "Earn 3000 to 5000 INR daily working 30 minutes from home! Simple online task: like YouTube videos and rate hotel listings on Google Maps. No experience required. Daily instant payouts. Contact HR Manager on Telegram: @JobOfferOfficial2026.",
                "snippet": "Earn 3000 to 5000 INR daily working 30 minutes from home! Contact HR on Telegram...",
                "risk_level": "medium",
                "risk_score": 58,
                "confidence": "medium",
                "message_intent": "Telegram Task & Part-Time Job Offer",
                "summary": "Suspicious remote employment solicitation offering unusually high pay for trivial actions, redirecting to an anonymous Telegram handle typical of task deposit schemes.",
                "warning_signs_json": json.dumps([
                    {"title": "Unrealistic Daily Earnings", "desc": "Offers 3000-5000 INR daily for video liking.", "evidence": "Earn 3000 to 5000 INR daily working 30 minutes"},
                    {"title": "Anonymous Telegram Recruiter", "desc": "Recruitment handled via anonymous Telegram account.", "evidence": "Contact HR Manager on Telegram: @JobOfferOfficial2026"}
                ]),
                "positive_indicators_json": json.dumps(["No executable attachment detected"]),
                "limitations_json": json.dumps(["External Telegram profile uninspected"]),
                "actions_json": json.dumps(["Do not transfer deposits to unlock tasks", "Verify jobs on official company careers page"]),
                "checklist_json": json.dumps(["Never pay money to receive job tasks"]),
                "source": "seed_data"
            },
            {
                "id": "SB-49C1682B",
                "created_at": (datetime.datetime.now(datetime.timezone.utc) - datetime.timedelta(hours=2)).isoformat(),
                "message": "DHL Express: We were unable to deliver parcel #DH9812403 due to an incomplete street address. Please update your delivery address and pay $1.49 redelivery fee at http://dhl-express-redelivery-center.online/update within 12 hours.",
                "snippet": "DHL Express: We were unable to deliver parcel #DH9812403. Pay $1.49 redelivery fee...",
                "risk_level": "medium",
                "risk_score": 52,
                "confidence": "medium",
                "message_intent": "Courier Package Redelivery Fee Notice",
                "summary": "Unverified parcel notification directing to a non-standard domain requesting a micro-fee. Scammers use this to capture credit card credentials.",
                "warning_signs_json": json.dumps([
                    {"title": "Unverified External Domain", "desc": "Uses .online domain instead of official dhl.com.", "evidence": "http://dhl-express-redelivery-center.online/update"},
                    {"title": "Micro-Fee Payment Request", "desc": "Solicits small fee to capture payment details.", "evidence": "pay $1.49 redelivery fee"}
                ]),
                "positive_indicators_json": json.dumps(["References standard tracking ID structure"]),
                "limitations_json": json.dumps(["Cannot query courier dispatch database"]),
                "actions_json": json.dumps(["Track shipment only on official courier website", "Do not enter payment cards on unverified domains"]),
                "checklist_json": json.dumps(["Official couriers do not suspend deliveries over small link fees"]),
                "source": "seed_data"
            },
            {
                "id": "SB-55797ED0",
                "created_at": (datetime.datetime.now(datetime.timezone.utc) - datetime.timedelta(hours=4)).isoformat(),
                "message": "Your mobile recharge of Rs. 299 was successful. Your plan benefits are now active. Thank you for using our service.",
                "snippet": "Your mobile recharge of Rs. 299 was successful. Your plan benefits are now active...",
                "risk_level": "low",
                "risk_score": 8,
                "confidence": "high",
                "message_intent": "Legitimate Transaction Alert",
                "summary": "Standard transactional confirmation receipt for mobile plan benefits with no hyperlinks, no fee demands, and no requests for banking passwords or OTPs.",
                "warning_signs_json": json.dumps([]),
                "positive_indicators_json": json.dumps([
                    "No links or URL shorteners present",
                    "No requests for sensitive credentials, PINs, or OTPs",
                    "Matches standard carrier billing confirmation format"
                ]),
                "limitations_json": json.dumps(["If you did not initiate this recharge, verify with your mobile carrier."]),
                "actions_json": json.dumps(["No action required if you initiated this recharge."]),
                "checklist_json": json.dumps(["Safe legitimate service notification"]),
                "source": "seed_data"
            }
        ]
        for r in seed_records:
            cursor.execute("""
            INSERT INTO scan_records (
                id, created_at, message, snippet, risk_level, risk_score, confidence,
                message_intent, summary, warning_signs_json, positive_indicators_json,
                limitations_json, actions_json, checklist_json, source
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                r["id"], r["created_at"], r["message"], r["snippet"], r["risk_level"],
                r["risk_score"], r["confidence"], r["message_intent"], r["summary"],
                r["warning_signs_json"], r["positive_indicators_json"], r["limitations_json"],
                r["actions_json"], r["checklist_json"], r["source"]
            ))
        conn.commit()
    conn.close()

def save_scan_to_db(scan_data: dict, raw_message: str) -> str:
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    scan_id = "SB-" + str(uuid.uuid4())[:8].upper()
    created_at = datetime.datetime.now(datetime.timezone.utc).isoformat()
    
    snippet = raw_message[:90] + "..." if len(raw_message) > 90 else raw_message
    risk_level = scan_data.get("risk_level", "medium").lower()
    risk_score = int(scan_data.get("risk_score", 50))
    confidence = scan_data.get("confidence", "high").lower()
    intent = scan_data.get("message_intent", "Unknown Intent")
    summary = scan_data.get("summary", "")
    
    warning_signs_json = json.dumps(scan_data.get("warning_signs", []))
    positive_indicators_json = json.dumps(scan_data.get("positive_indicators", []))
    limitations_json = json.dumps(scan_data.get("limitations", []))
    actions_json = json.dumps(scan_data.get("recommended_actions", []))
    checklist_json = json.dumps(scan_data.get("safety_checklist", []))
    source = scan_data.get("source", "openrouter_agent")

    cursor.execute("""
    INSERT INTO scan_records (
        id, created_at, message, snippet, risk_level, risk_score, confidence,
        message_intent, summary, warning_signs_json, positive_indicators_json,
        limitations_json, actions_json, checklist_json, source
    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    """, (
        scan_id, created_at, raw_message, snippet, risk_level, risk_score, confidence,
        intent, summary, warning_signs_json, positive_indicators_json, limitations_json,
        actions_json, checklist_json, source
    ))
    conn.commit()
    conn.close()
    return scan_id

def get_scan_history(limit=50):
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM scan_records ORDER BY created_at DESC LIMIT ?", (limit,))
    rows = cursor.fetchall()
    results = []
    for r in rows:
        results.append({
            "id": r["id"],
            "created_at": r["created_at"],
            "message": r["message"],
            "snippet": r["snippet"],
            "risk_level": r["risk_level"],
            "risk_score": r["risk_score"],
            "confidence": r["confidence"],
            "message_intent": r["message_intent"],
            "summary": r["summary"],
            "warning_signs": json.loads(r["warning_signs_json"]),
            "positive_indicators": json.loads(r["positive_indicators_json"]),
            "limitations": json.loads(r["limitations_json"]),
            "recommended_actions": json.loads(r["actions_json"]),
            "safety_checklist": json.loads(r["checklist_json"]),
            "source": r["source"]
        })
    conn.close()
    return results

def get_stats():
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute("SELECT COUNT(*) FROM scan_records")
    total = cursor.fetchone()[0]
    cursor.execute("SELECT COUNT(*) FROM scan_records WHERE risk_level = 'high'")
    high = cursor.fetchone()[0]
    cursor.execute("SELECT COUNT(*) FROM scan_records WHERE risk_level = 'medium'")
    medium = cursor.fetchone()[0]
    cursor.execute("SELECT COUNT(*) FROM scan_records WHERE risk_level = 'low'")
    low = cursor.fetchone()[0]
    cursor.execute("SELECT AVG(risk_score) FROM scan_records")
    avg_score = cursor.fetchone()[0]
    conn.close()
    return {
        "total": total,
        "high": high,
        "medium": medium,
        "low": low,
        "avg_score": round(avg_score or 0, 1)
    }

# ==============================================================================
# HTTP Request Handler
# ==============================================================================
class ScamBusterAPIHandler(SimpleHTTPRequestHandler):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, directory=FRONTEND_DIR, **kwargs)

    def _send_cors_headers(self):
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Methods", "GET, POST, DELETE, OPTIONS")
        self.send_header("Access-Control-Allow-Headers", "Content-Type, Authorization")

    def do_OPTIONS(self):
        self.send_response(200)
        self._send_cors_headers()
        self.end_headers()

    def do_GET(self):
        if self.path == "/api/status":
            self.send_response(200)
            self._send_cors_headers()
            self.send_header("Content-Type", "application/json; charset=utf-8")
            self.end_headers()
            stats = get_stats()
            status_data = {
                "status": "online",
                "agent_available": (scam_agent is not None) or (agent is not None),
                "model": "openrouter/free",
                "architecture": "Real AI Agent Architecture (Think -> Plan -> Act -> Observe -> Learn)",
                "backend": "Scam Buster Autonomous Agent Loop + SQLite",
                "stats": stats,
                "message": "Scam Buster Autonomous Real AI Agent is fully operational"
            }
            self.wfile.write(json.dumps(status_data).encode("utf-8"))
            return

        if self.path.startswith("/api/history"):
            self.send_response(200)
            self._send_cors_headers()
            self.send_header("Content-Type", "application/json; charset=utf-8")
            self.end_headers()
            history = get_scan_history()
            self.wfile.write(json.dumps({"success": True, "history": history}, ensure_ascii=False).encode("utf-8"))
            return

        if self.path == "/api/stats":
            self.send_response(200)
            self._send_cors_headers()
            self.send_header("Content-Type", "application/json; charset=utf-8")
            self.end_headers()
            stats = get_stats()
            self.wfile.write(json.dumps({"success": True, "stats": stats}).encode("utf-8"))
            return

        # Serve static files from FRONTEND_DIR
        return super().do_GET()

    def do_POST(self):
        if self.path == "/api/analyze":
            content_length = int(self.headers.get("Content-Length", 0))
            post_data = self.rfile.read(content_length).decode("utf-8")

            try:
                data = json.loads(post_data)
                message = data.get("message", "").strip()
                user_id = data.get("user_id", "default_user")

                if not message:
                    self.send_response(400)
                    self._send_cors_headers()
                    self.send_header("Content-Type", "application/json; charset=utf-8")
                    self.end_headers()
                    self.wfile.write(json.dumps({"error": "Empty message supplied"}).encode("utf-8"))
                    return

                print(f"\n[Scam Buster] Real AI Agent analysis requested for user '{user_id}': {message[:60]}...")
                
                # Run structured scam analysis via Real AI Agent
                if analyze_scam_structured:
                    analysis = analyze_scam_structured(message, user_id=user_id)
                else:
                    raise RuntimeError("analyze_scam_structured is not available")

                # Save record to SQLite
                scan_id = save_scan_to_db(analysis, message)
                analysis["id"] = scan_id

                print(f"[Scam Buster] Analysis complete. Risk: {analysis.get('risk_level')}, Score: {analysis.get('risk_score')}, ID: {scan_id}")

                try:
                    self.send_response(200)
                    self._send_cors_headers()
                    self.send_header("Content-Type", "application/json; charset=utf-8")
                    self.end_headers()

                    response_payload = {
                        "success": True,
                        "data": analysis
                    }
                    self.wfile.write(json.dumps(response_payload, ensure_ascii=False).encode("utf-8"))
                except (ConnectionResetError, ConnectionAbortedError, BrokenPipeError):
                    print("[Scam Buster] Client closed connection before response write completed.")

            except (ConnectionResetError, ConnectionAbortedError, BrokenPipeError):
                pass
            except Exception as e:
                print(f"[Scam Buster] Error during analysis: {e}")
                try:
                    self.send_response(500)
                    self._send_cors_headers()
                    self.send_header("Content-Type", "application/json; charset=utf-8")
                    self.end_headers()
                    self.wfile.write(json.dumps({"error": str(e)}).encode("utf-8"))
                except Exception:
                    pass
            return

        if self.path == "/api/feedback":
            content_length = int(self.headers.get("Content-Length", 0))
            post_data = self.rfile.read(content_length).decode("utf-8")
            try:
                data = json.loads(post_data)
                scan_id = data.get("scan_id", "")
                user_id = data.get("user_id", "default_user")
                original_risk_level = data.get("original_risk_level", "medium")
                corrected_risk_level = data.get("corrected_risk_level", "low")
                feedback_type = data.get("feedback_type", "false_positive")
                message_text = data.get("message", "")
                reasoning = data.get("reasoning", "")

                print(f"[Scam Buster] Processing user feedback for scan {scan_id} (correction: {original_risk_level} -> {corrected_risk_level})")
                if scam_agent:
                    fb_res = scam_agent.process_feedback(
                        scan_id=scan_id,
                        user_id=user_id,
                        original_risk_level=original_risk_level,
                        corrected_risk_level=corrected_risk_level,
                        feedback_type=feedback_type,
                        message_text=message_text,
                        reasoning=reasoning
                    )
                else:
                    fb_res = {"success": True, "message": "Feedback noted"}

                self.send_response(200)
                self._send_cors_headers()
                self.send_header("Content-Type", "application/json; charset=utf-8")
                self.end_headers()
                self.wfile.write(json.dumps(fb_res).encode("utf-8"))
            except Exception as e:
                print(f"[Scam Buster] Error processing feedback: {e}")
                self.send_response(500)
                self._send_cors_headers()
                self.send_header("Content-Type", "application/json; charset=utf-8")
                self.end_headers()
                self.wfile.write(json.dumps({"error": str(e)}).encode("utf-8"))
            return

        if self.path == "/api/history/clear":
            conn = sqlite3.connect(DB_PATH)
            cursor = conn.cursor()
            cursor.execute("DELETE FROM scan_records")
            conn.commit()
            conn.close()
            # Re-seed default demo records
            init_db()

            self.send_response(200)
            self._send_cors_headers()
            self.send_header("Content-Type", "application/json; charset=utf-8")
            self.end_headers()
            self.wfile.write(json.dumps({"success": True, "message": "History reset to defaults"}).encode("utf-8"))
            return

        self.send_response(404)
        self.end_headers()

    def do_DELETE(self):
        if self.path.startswith("/api/history"):
            conn = sqlite3.connect(DB_PATH)
            cursor = conn.cursor()
            cursor.execute("DELETE FROM scan_records")
            conn.commit()
            conn.close()
            init_db()

            self.send_response(200)
            self._send_cors_headers()
            self.send_header("Content-Type", "application/json; charset=utf-8")
            self.end_headers()
            self.wfile.write(json.dumps({"success": True, "message": "History cleared"}).encode("utf-8"))
            return

        self.send_response(404)
        self.end_headers()


if __name__ == "__main__":
    init_db()
    server = HTTPServer(("0.0.0.0", PORT), ScamBusterAPIHandler)
    print("=" * 65)
    print(f"🛡️  Scam Buster AI Server running at: http://localhost:{PORT}")
    print(f"📊  SQLite Database: {DB_PATH}")
    print(f"🚀  API Endpoints: /api/analyze, /api/history, /api/status")
    print(f"🌐  Frontend Dashboard: http://localhost:{PORT}/index.html")
    print("=" * 65)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nShutting down server.")
        server.server_close()
