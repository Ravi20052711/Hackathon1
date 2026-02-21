"""
LLM ANALYZER - Multi-AI Support (Groq FREE, Claude, Gemini)
Priority: Groq → Claude → Gemini → Template
"""

import aiohttp
import json
import logging
from app.core.config import settings

logger = logging.getLogger(__name__)


class LLMAnalyzer:

    def __init__(self):
        self.anthropic_key = getattr(settings, 'ANTHROPIC_API_KEY', '')
        self.gemini_key = getattr(settings, 'GEMINI_API_KEY', '')
        self.groq_key = getattr(settings, 'GROQ_API_KEY', '')

        self.has_claude = bool(self.anthropic_key and self.anthropic_key.startswith('sk-ant'))
        self.has_groq = bool(self.groq_key and self.groq_key.startswith('gsk_'))
        self.has_gemini = bool(self.gemini_key and len(self.gemini_key) > 10)

        if self.has_claude:
            logger.info("✅ Claude AI (Anthropic) configured")
        elif self.has_groq:
            logger.info("✅ Groq AI configured — FREE (llama-3.3-70b)")
        elif self.has_gemini:
            logger.info("✅ Gemini AI (Google) configured")
        else:
            logger.info("ℹ️ No AI key — add GROQ_API_KEY for free AI (console.groq.com)")

    def _active_provider(self):
        if self.has_claude: return "claude"
        if self.has_groq: return "groq"
        if self.has_gemini: return "gemini"
        return "template"

    def _build_prompt(self, raw_log, iocs, matches, techniques) -> str:
        context = []

        if matches:
            context.append(f"CONFIRMED THREAT MATCHES IN DATABASE: {json.dumps([{'value': m['value'], 'type': m['ioc_type'], 'risk': m['risk_score'], 'source': m['source']} for m in matches])}")
        else:
            context.append("NO matches found in threat database.")

        if iocs.get('ips'): context.append(f"IPs extracted: {', '.join(iocs['ips'][:5])}")
        if iocs.get('domains'): context.append(f"Domains extracted: {', '.join(iocs['domains'][:5])}")
        if iocs.get('hashes'): context.append(f"Hashes extracted: {', '.join(iocs['hashes'][:3])}")
        if iocs.get('urls'): context.append(f"URLs extracted: {', '.join(iocs['urls'][:3])}")

        if techniques:
            context.append(f"MITRE ATT&CK matched: {', '.join(techniques)}")
        else:
            context.append("No MITRE techniques matched.")

        if not matches and not techniques:
            threat_hint = "This log has NO threat matches and NO suspicious keywords. It is likely LEGITIMATE or informational. Do NOT assume it is malicious or reconnaissance."
        elif matches:
            threat_hint = f"This log has {len(matches)} CONFIRMED threat match(es). This is likely malicious."
        else:
            threat_hint = "This log has suspicious keywords but no confirmed IOC matches. Treat as suspicious but unconfirmed."

        return f"""You are a senior threat intelligence analyst. Analyze ONLY what is in this log.

RAW LOG:
{raw_log[:600]}

ENRICHMENT RESULTS:
{chr(10).join(context)}

IMPORTANT: {threat_hint}

Based ONLY on actual evidence above, provide:
1. THREAT ASSESSMENT — is this malicious, suspicious, or legitimate? Be honest.
2. SEVERITY JUSTIFICATION — based on specific evidence found or lack thereof
3. ATTACK STAGE — if malicious only, otherwise say "Not applicable"
4. RECOMMENDED ACTIONS — specific to this log

Do NOT assume malicious intent without evidence. If the log looks benign, say so."""

    async def analyze_threat(self, raw_log, iocs, matches, techniques) -> str:
        provider = self._active_provider()
        prompt = self._build_prompt(raw_log, iocs, matches, techniques)
        try:
            if provider == "claude":
                return await self._call_claude(prompt, "🤖 Claude AI Analysis")
            elif provider == "groq":
                return await self._call_groq(prompt, "🤖 Groq AI Analysis (Llama 3.3)")
            elif provider == "gemini":
                return await self._call_gemini(prompt, "🤖 Gemini AI Analysis")
        except Exception as e:
            logger.error(f"{provider} error: {e}")
        return self._template_summary(iocs, matches, techniques)

    async def summarize_campaign(self, iocs: list) -> str:
        ioc_summary = "\n".join([
            f"- {i.get('ioc_type','?').upper()}: {i.get('value','?')[:50]} (Risk: {i.get('risk_score',0)}, Source: {i.get('source','?')})"
            for i in iocs[:10]
        ])
        prompt = f"""Analyze this IOC cluster as a threat intelligence analyst:

{ioc_summary}

Identify: threat actor, campaign purpose, targeted sectors, confidence level. Max 6 sentences."""
        provider = self._active_provider()
        try:
            if provider == "claude":
                return await self._call_claude(prompt, "🤖 Claude Campaign Analysis")
            elif provider == "groq":
                return await self._call_groq(prompt, "🤖 Groq Campaign Analysis")
            elif provider == "gemini":
                return await self._call_gemini(prompt, "🤖 Gemini Campaign Analysis")
        except Exception as e:
            logger.error(f"Campaign error: {e}")
        return self._template_campaign(iocs)

    async def generate_hunt_query(self, ioc_value: str, ioc_type: str) -> str:
        prompt = f"Generate a Splunk SPL query to hunt for this IOC:\nType: {ioc_type}\nValue: {ioc_value}\nReturn ONLY the SPL query, no explanation."
        provider = self._active_provider()
        try:
            if provider == "claude":
                return await self._call_claude(prompt, "")
            elif provider == "groq":
                return await self._call_groq(prompt, "")
            elif provider == "gemini":
                return await self._call_gemini(prompt, "")
        except Exception as e:
            logger.error(f"Hunt query error: {e}")
        return ""

    async def _call_groq(self, prompt: str, label: str) -> str:
        async with aiohttp.ClientSession() as session:
            async with session.post(
                "https://api.groq.com/openai/v1/chat/completions",
                headers={
                    "Authorization": f"Bearer {self.groq_key}",
                    "Content-Type": "application/json",
                },
                json={
                    "model": "llama-3.3-70b-versatile",
                    "messages": [
                        {"role": "system", "content": "You are a senior threat intelligence analyst. Be precise and base your analysis only on the evidence provided."},
                        {"role": "user", "content": prompt}
                    ],
                    "max_tokens": 400,
                    "temperature": 0.2,
                },
                timeout=aiohttp.ClientTimeout(total=30)
            ) as resp:
                if resp.status != 200:
                    raise Exception(f"Groq API {resp.status}: {await resp.text()}")
                data = await resp.json()
                text = data["choices"][0]["message"]["content"]
                return f"{label}:\n\n{text}" if label else text

    async def _call_claude(self, prompt: str, label: str) -> str:
        async with aiohttp.ClientSession() as session:
            async with session.post(
                "https://api.anthropic.com/v1/messages",
                headers={
                    "x-api-key": self.anthropic_key,
                    "anthropic-version": "2023-06-01",
                    "content-type": "application/json",
                },
                json={
                    "model": "claude-haiku-4-5-20251001",
                    "max_tokens": 400,
                    "messages": [{"role": "user", "content": prompt}]
                },
                timeout=aiohttp.ClientTimeout(total=30)
            ) as resp:
                if resp.status != 200:
                    raise Exception(f"Claude API {resp.status}: {await resp.text()}")
                data = await resp.json()
                text = data["content"][0]["text"]
                return f"{label}:\n\n{text}" if label else text

    async def _call_gemini(self, prompt: str, label: str) -> str:
        url = f"https://generativelanguage.googleapis.com/v1beta/models/gemini-1.5-flash-8b:generateContent?key={self.gemini_key}"
        async with aiohttp.ClientSession() as session:
            async with session.post(
                url,
                headers={"Content-Type": "application/json"},
                json={
                    "contents": [{"parts": [{"text": prompt}]}],
                    "generationConfig": {"maxOutputTokens": 400, "temperature": 0.2}
                },
                timeout=aiohttp.ClientTimeout(total=30)
            ) as resp:
                if resp.status != 200:
                    raise Exception(f"Gemini API {resp.status}: {await resp.text()}")
                data = await resp.json()
                text = data["candidates"][0]["content"]["parts"][0]["text"]
                return f"{label}:\n\n{text}" if label else text

    def _template_summary(self, iocs, matches, techniques) -> str:
        lines = []
        if matches:
            lines.append(f"⚠️ {len(matches)} known threat(s) matched in database:")
            for m in matches[:3]:
                lines.append(f"  • {m['ioc_type'].upper()} {m['value']} — Risk {m['risk_score']}/100 ({m['source']})")
        elif not techniques:
            lines.append("✅ No threat indicators matched. This log appears legitimate or informational.")
        if iocs.get('ips'): lines.append(f"\n🌐 IPs: {', '.join(iocs['ips'][:5])}")
        if iocs.get('domains'): lines.append(f"🔗 Domains: {', '.join(iocs['domains'][:5])}")
        if techniques: lines.append(f"\n🎯 MITRE: {', '.join(techniques[:3])}")
        lines.append("\n💡 Add GROQ_API_KEY to .env for free AI analysis (console.groq.com)")
        return '\n'.join(lines)

    def _template_campaign(self, iocs) -> str:
        sources = list(set(i.get('source', '') for i in iocs))
        types = list(set(i.get('ioc_type', '') for i in iocs))
        avg_risk = sum(i.get('risk_score', 0) for i in iocs) // max(len(iocs), 1)
        return f"Campaign: {len(iocs)} IOCs | Sources: {', '.join(sources[:3])} | Types: {', '.join(types)} | Avg risk: {avg_risk}/100"