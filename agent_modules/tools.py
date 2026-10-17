"""
Dynamic Tool Registry for ScamShield AI Agent
Provides modular, composable, and observable forensic detection tools.
"""

import re
import time
from typing import Dict, Any, List, Callable, Optional
from dataclasses import dataclass, field

@dataclass
class ToolDefinition:
    name: str
    description: str
    func: Callable
    category: str = "core_detection"
    timeout_ms: int = 2000

class ToolRegistry:
    def __init__(self):
        self.tools: Dict[str, ToolDefinition] = {}
        self._register_default_tools()

    def register_tool(self, tool_def: ToolDefinition):
        self.tools[tool_def.name] = tool_def

    def get_tool(self, name: str) -> Optional[ToolDefinition]:
        return self.tools.get(name)

    def list_tools(self) -> List[Dict[str, str]]:
        return [{"name": t.name, "description": t.description, "category": t.category} for t in self.tools.values()]

    def execute_tool(self, name: str, **kwargs) -> Dict[str, Any]:
        """Executes a tool by name with execution latency tracking and error handling."""
        tool = self.get_tool(name)
        if not tool:
            return {"success": False, "tool_name": name, "error": f"Tool '{name}' not found", "duration_ms": 0}

        start = time.perf_counter()
        try:
            result = tool.func(**kwargs)
            duration_ms = int((time.perf_counter() - start) * 1000)
            return {
                "success": True,
                "tool_name": name,
                "duration_ms": duration_ms,
                "result": result
            }
        except Exception as e:
            duration_ms = int((time.perf_counter() - start) * 1000)
            return {
                "success": False,
                "tool_name": name,
                "duration_ms": duration_ms,
                "error": str(e)
            }

    def _register_default_tools(self):
        # 1. extract_urls
        def _extract_urls(message: str) -> Dict[str, Any]:
            urls = re.findall(r'https?://[^\s]+', message)
            suspicious_tlds = ['.online', '.top', '.xyz', '.site', '.club', '.info', '.click', '.live', '.buzz']
            flagged_urls = []
            for u in urls:
                u_lower = u.lower()
                is_suspicious_tld = any(tld in u_lower for tld in suspicious_tlds)
                is_raw_ip = bool(re.search(r'https?://\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}', u))
                if is_suspicious_tld or is_raw_ip:
                    flagged_urls.append({"url": u, "reason": "Suspicious TLD or raw IP host"})
            return {
                "urls": urls,
                "url_count": len(urls),
                "suspicious_domains": flagged_urls
            }

        self.register_tool(ToolDefinition(
            name="extract_urls",
            description="Extracts hyperlinks and inspects domain extensions for non-standard TLDs and raw IP hosts.",
            func=_extract_urls,
            category="core_detection"
        ))

        # 2. check_url_shorteners
        def _check_url_shorteners(message: str) -> Dict[str, Any]:
            known_shorteners = ['bit.ly', 'tinyurl.com', 't.co', 'cutt.ly', 'is.gd', 'rb.gy', 'shorturl.at', 'ow.ly']
            found_shorteners = []
            for s in known_shorteners:
                matches = re.findall(r'https?://(?:www\.)?' + re.escape(s) + r'/[^\s]+', message, re.IGNORECASE)
                for m in matches:
                    found_shorteners.append({"shortener": s, "url": m})
            return {
                "has_shorteners": len(found_shorteners) > 0,
                "shortener_count": len(found_shorteners),
                "items": found_shorteners
            }

        self.register_tool(ToolDefinition(
            name="check_url_shorteners",
            description="Detects URL shortening services commonly used to obscure phishing destinations.",
            func=_check_url_shorteners,
            category="core_detection"
        ))

        # 3. analyze_urgency_cues
        def _analyze_urgency_cues(message: str) -> Dict[str, Any]:
            urgency_patterns = [
                (r'within\s+\d+\s+(?:hours|hrs|minutes|mins)', "Strict artificial deadline"),
                (r'urgent|immediately|action required|critical alert', "High-pressure prompt"),
                (r'account\s+(?:suspended|restricted|blocked|frozen|deactivated)', "Coercive service threat"),
                (r'permanent(?:ly)?\s+(?:block|loss|closure)', "Threat of permanent consequence"),
                (r'police|arrest|lawsuit|legal penalty|jail', "Legal intimidation tactic")
            ]
            cues = []
            msg_lower = message.lower()
            for pattern, desc in urgency_patterns:
                matches = re.findall(pattern, msg_lower)
                if matches:
                    cues.append({"evidence": matches[0], "tactic": desc})
            return {
                "urgency_detected": len(cues) > 0,
                "urgency_score": min(100, len(cues) * 35),
                "cues": cues
            }

        self.register_tool(ToolDefinition(
            name="analyze_urgency_cues",
            description="Identifies psychological manipulation, manufactured urgency, and coercive threat language.",
            func=_analyze_urgency_cues,
            category="core_detection"
        ))

        # 4. detect_financial_requests
        def _detect_financial_requests(message: str) -> Dict[str, Any]:
            financial_terms = ['inr', 'usd', '$', '€', '₹', 'rs', 'rupees', 'payout', 'daily earnings', 'deposit', 'processing fee', 'redelivery fee', 'upi', 'crypto', 'wallet address', 'processing tax', 'gift card']
            msg_lower = message.lower()
            found_terms = [t for t in financial_terms if t in msg_lower]
            
            # Check for advance fee trap
            is_advance_fee = bool(re.search(r'(?:pay|transfer|send|deposit).*(?:fee|tax|charge|\$|₹|rs|\d+)', msg_lower))
            is_lottery_win = bool(re.search(r'(?:won|winner|cash prize|lucky draw).*(?:lakh|crore|\$|₹|rs|\d+)', msg_lower))

            return {
                "has_financial_terms": len(found_terms) > 0,
                "terms": found_terms,
                "is_advance_fee_trap": is_advance_fee,
                "is_lottery_claim": is_lottery_win
            }

        self.register_tool(ToolDefinition(
            name="detect_financial_requests",
            description="Detects advance-fee traps, money transfer requests, and prize payout demands.",
            func=_detect_financial_requests,
            category="core_detection"
        ))

        # 5. identify_impersonation
        def _identify_impersonation(message: str) -> Dict[str, Any]:
            brands = [
                ('State Bank|SBI|HDFC|ICICI|Axis|Chase|Wells Fargo', 'Banking Institution Impersonation'),
                ('DHL|FedEx|UPS|India Post|Postal|Courier|Parcel', 'Courier / Delivery Service Impersonation'),
                ('WhatsApp Lucky Draw|KBC|Kaun Banega', 'Lottery / Television Brand Impersonation'),
                ('Netflix|Amazon|Apple|PayPal|Google Support', 'Big Tech / Subscription Service Impersonation'),
                ('Telegram HR|Part-Time Job|YouTube Likes|Google Maps Rating', 'Work-From-Home Task Recruitment')
            ]
            impersonations = []
            for pattern, brand_type in brands:
                if re.search(pattern, message, re.IGNORECASE):
                    impersonations.append(brand_type)
            return {
                "impersonation_suspected": len(impersonations) > 0,
                "categories": impersonations
            }

        self.register_tool(ToolDefinition(
            name="identify_impersonation",
            description="Detects brand spoofing and impersonation of financial institutions, couriers, and recruiters.",
            func=_identify_impersonation,
            category="validation"
        ))

        # 6. extract_contact_identifiers
        def _extract_contact_identifiers(message: str) -> Dict[str, Any]:
            telegram_handles = re.findall(r'@[A-Za-z0-9_]{3,}', message)
            phones = re.findall(r'(?:\+?\d{1,3}[-.\s]?)?\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4}', message)
            upi_ids = re.findall(r'[a-zA-Z0-9.\-_]{2,49}@[a-zA-Z]{2,}', message)
            
            return {
                "telegram_handles": telegram_handles,
                "phone_numbers": phones,
                "upi_ids": upi_ids,
                "has_anonymous_contact": len(telegram_handles) > 0
            }

        self.register_tool(ToolDefinition(
            name="extract_contact_identifiers",
            description="Extracts phone numbers, Telegram handles, and UPI IDs for anonymous communication channels.",
            func=_extract_contact_identifiers,
            category="enrichment"
        ))

        # 7. cross_reference_learned_patterns
        def _cross_reference_learned_patterns(message: str, user_context: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
            if not user_context:
                return {"matches_found": False, "patterns": []}

            learned = user_context.get("learned_patterns", [])
            matches = []
            msg_lower = message.lower()

            for p in learned:
                p_data = p.get("data", {})
                keywords = p_data.get("keywords", [])
                p_type = p.get("type", "custom")
                if keywords and any(k.lower() in msg_lower for k in keywords):
                    matches.append({
                        "pattern_id": p.get("id"),
                        "pattern_type": p_type,
                        "confidence": p.get("confidence", 0.8),
                        "matched_keywords": [k for k in keywords if k.lower() in msg_lower]
                    })

            return {
                "matches_found": len(matches) > 0,
                "matched_patterns": matches
            }

        self.register_tool(ToolDefinition(
            name="cross_reference_learned_patterns",
            description="Cross-references the message against user-specific learned patterns and safe sender rules.",
            func=_cross_reference_learned_patterns,
            category="user_context"
        ))

        # 8. create_safety_checklist
        def _create_safety_checklist(signals: Dict[str, Any]) -> List[str]:
            checklist = []
            if signals.get("urls"):
                checklist.append("Never tap links sent via SMS or messaging apps; navigate directly to the verified official website.")
            if signals.get("is_advance_fee"):
                checklist.append("Never pay upfront taxes, processing fees, or release charges to receive prize money or courier deliveries.")
            if signals.get("urgency"):
                checklist.append("Pause and verify threats independently; legitimate banks do not suspend accounts within hours via text.")
            if not checklist:
                checklist.append("Verify unfamiliar transaction notices through your official banking or telecommunications provider app.")
            return checklist

        self.register_tool(ToolDefinition(
            name="create_safety_checklist",
            description="Generates actionable verification steps based on flagged technical signals.",
            func=_create_safety_checklist,
            category="reporting"
        ))
