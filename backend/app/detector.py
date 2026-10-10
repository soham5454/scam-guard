"""Rule-based scam detection (no ML needed for the MVP).

How it works:
1. The message is normalised (Unicode folded, "do not share your OTP" style
   warnings removed so genuine bank OTP messages are not flagged).
2. Each scam category has weighted regex rules (English + Hinglish + Hindi + Bengali).
3. Links are scored with simple heuristics (shorteners, odd TLDs, brand
   look-alikes, IP hosts...) and optionally checked on VirusTotal.
4. category score + urgency bonus + link score >= THRESHOLD  ->  scam.
"""
from __future__ import annotations

import re
import unicodedata
from dataclasses import dataclass, field
from typing import Callable, Optional
from urllib.parse import urlparse

THRESHOLD = 3


# --------------------------------------------------------------------------- #
# Scam categories
# --------------------------------------------------------------------------- #
@dataclass(frozen=True)
class Category:
    name: str
    explanation: str
    rules: tuple  # of (compiled regex, weight, label)


def _rule(pattern: str, weight: int, label: str):
    return (re.compile(pattern, re.IGNORECASE), weight, label)


CATEGORIES: tuple[Category, ...] = (
    Category(
        "Bank / KYC Fraud",
        "Banks never ask you to update KYC, PAN or Aadhaar through a link or phone "
        "call, and they do not block accounts over SMS. Do not click the link or call "
        "the number. Visit your bank branch or use the official app to check.",
        (
            _rule(r"\bkyc\b.{0,40}\b(expir\w*|pending|incomplete|suspend\w*|block\w*|deactivat\w*|"
                  r"(update|verify|complete)\w*\s+(now|immediately|today|urgently|within|karo|kare))", 3,
                  "KYC deadline threat"),
            _rule(r"\b(account|a/c|acct)\b.{0,40}\b(block\w*|suspend\w*|clos\w*|frozen|freez\w*|"
                  r"deactivat\w*|restrict\w*)\b", 2, "Account blocking threat"),
            _rule(r"\b(pan|aadhaar|aadhar)\b.{0,40}\b(update|verify|link|expire|block|suspend)\w*", 2,
                  "PAN/Aadhaar update request"),
            _rule(r"\b(net\s?banking|mobile\s+banking|debit\s+card|credit\s+card)\b.{0,40}"
                  r"\b(block\w*|suspend\w*|expir\w*|deactivat\w*)", 2, "Card/banking suspension threat"),
            _rule(r"(खाता|अकाउंट).{0,20}(बंद|ब्लॉक)|केवाईसी|account\s+band|kyc\s+(update|verify)\s+kar", 3,
                  "Hindi/Hinglish KYC or account threat"),
            _rule(r"(অ্যাকাউন্ট|একাউন্ট).{0,20}বন্ধ|কেওয়াইসি", 3, "Bengali KYC or account threat"),
        ),
    ),
    Category(
        "OTP / PIN Theft",
        "Nobody genuine - not your bank, UPI app or any officer - will ask for your OTP, "
        "PIN, CVV or password. Anyone who asks is trying to take money from your account. "
        "Do not share it, hang up and block the sender.",
        (
            _rule(r"\b(share|send|tell|give|provide|forward|read\s+out|batao|bataiye|bataye)\b.{0,25}"
                  r"\b(otp|pin|cvv|password|passcode)\b", 4, "Asks you to share OTP/PIN/CVV"),
            _rule(r"(ओटीपी|ओ\.टी\.पी).{0,20}(बताएं|बताओ|शेयर|भेजें)|ওটিপি.{0,20}(বলুন|শেয়ার|পাঠান)", 4,
                  "Hindi/Bengali OTP request"),
        ),
    ),
    Category(
        "UPI / Payment Request Scam",
        "You never need to enter your UPI PIN or approve a request to RECEIVE money. "
        "Approving a 'collect request' or scanning a QR code sends money out of your account. "
        "Decline the request and report it in your UPI app.",
        (
            _rule(r"\benter\b.{0,15}\bupi\s?pin\b.{0,40}\b(receive|refund|credit|get)", 4,
                  "Asks for UPI PIN to receive money"),
            _rule(r"\b(approve|accept)\b.{0,25}\b(request|collect)\b.{0,40}\b(receive|refund|get)", 3,
                  "Asks you to approve a collect request"),
            _rule(r"\bcollect\s+request\b", 2, "Mentions a collect request"),
            _rule(r"\b(scan|click)\b.{0,30}\b(qr|link)\b.{0,40}\b(receive|refund|get\s+(?:your\s+)?money|"
                  r"cashback|reward)", 3, "QR/link to 'receive' money"),
            _rule(r"\brefund\b.{0,40}\b(link|click|upi|gpay|phonepe|paytm)\b", 2, "Refund via link/UPI"),
            _rule(r"\b(cashback|reward\s*points?)\b.{0,40}\b(expir\w*|redeem|claim)\b.{0,30}"
                  r"(link|click|now|today)", 2, "Expiring cashback/rewards"),
        ),
    ),
    Category(
        "Lottery / Prize Scam",
        "You cannot win a lottery or prize you never entered. These messages ask for a "
        "'processing fee' or your bank details to release the prize. Ignore and delete.",
        (
            _rule(r"\b(won|winner|selected|lucky|congratulations?)\b.{0,50}\b(prize|lottery|lakh|crore|"
                  r"reward|gift|iphone|car|kbc|jackpot|rs\.?|inr)|₹", 3, "Says you won a prize"),
            _rule(r"\b(claim|collect)\b.{0,20}\b(prize|reward|gift|lottery|winning)", 3, "Asks you to claim a prize"),
            _rule(r"\blucky\s*draw\b|\bkbc\b|\bjackpot\b", 3, "Lucky draw / KBC / jackpot"),
            _rule(r"(लॉटरी|इनाम).{0,30}(जीत|मिला)|লটারি|পুরস্কার.{0,20}(জিত|পেয়েছেন)", 3,
                  "Hindi/Bengali lottery claim"),
        ),
    ),
    Category(
        "Fake Job / Task Scam",
        "Real employers do not ask for registration or training fees, and they do not pay "
        "for liking videos or completing 'tasks' on Telegram/WhatsApp. These jobs start "
        "with small payouts and end with you paying a large 'deposit'.",
        (
            _rule(r"\b(part[- ]?time|work\s*from\s*home|wfh|online\s+job|home\s+based)\b.{0,60}"
                  r"\b(earn|income|salary|rs\.?|per\s+(day|hour)|daily|commission)|₹", 3,
                  "Work-from-home / part-time earning offer"),
            _rule(r"\b(earn|make)\b.{0,15}(rs\.?|inr)?\s*\d[\d,]{2,}.{0,20}\b(per\s+day|daily|a\s+day|per\s+hour|weekly)\b",
                  3, "Promises daily income"),
            _rule(r"\b(like|subscribe|rate|review|task)s?\b.{0,40}\b(earn|paid|commission|reward)\b", 2,
                  "Paid for likes/tasks"),
            _rule(r"\b(whatsapp|telegram)\b.{0,40}\b(job|task|hr|recruit\w*|vacancy)\b|"
                  r"\b(job|task|hr|recruit\w*)\b.{0,40}\b(whatsapp|telegram)\b", 2, "Job offered via WhatsApp/Telegram"),
            _rule(r"\b(registration|security|training|activation)\s+(fee|deposit|charges?)\b", 3,
                  "Asks for an upfront fee/deposit"),
        ),
    ),
    Category(
        "Courier / Customs Scam",
        "Couriers and customs do not demand payment or personal details through SMS links, "
        "and no agency 'seizes' a parcel you never sent. Track parcels only on the "
        "courier's official website or app.",
        (
            _rule(r"\b(parcel|courier|package|shipment|consignment)\b.{0,60}\b(seiz\w*|illegal|drugs?|"
                  r"contraband|narcotics?|customs\s+(?:duty|fee|clearance))", 4, "Parcel seized / customs fee"),
            _rule(r"\b(parcel|courier|package|shipment)\b.{0,60}\b(held|on\s+hold|undelivered|"
                  r"address\s+(?:incomplete|invalid)|pay\w*\s+(?:a\s+)?(?:small\s+)?(?:fee|charge))", 2,
                  "Parcel on hold / delivery fee"),
            _rule(r"\b(fedex|dhl|india\s?post|blue\s?dart|dtdc|delhivery)\b.{0,60}\b(update|verify|confirm|pay|"
                  r"reschedule|fee)\b.{0,30}\b(address|delivery|link|click|fee)", 2, "Courier brand + action link"),
        ),
    ),
    Category(
        "Electricity / Utility Bill Scam",
        "Electricity boards do not disconnect supply through a same-night SMS or ask you to "
        "call a mobile number. Check your bill on the official board website or app.",
        (
            _rule(r"\b(electricity|power|gas|water|broadband)\b.{0,50}\b(disconnect\w*|cut|terminat\w*|suspend\w*)\b"
                  r".{0,40}\b(tonight|today|\d+\s*(?:hours?|hrs?)|9\s?(?:pm|:30)|immediately|unpaid|pending)", 4,
                  "Disconnection tonight threat"),
            _rule(r"\bbill\b.{0,30}\b(unpaid|not\s+paid|pending|overdue)\b.{0,50}\b(disconnect\w*|cut|terminat\w*)\b",
                  3, "Unpaid bill disconnection threat"),
        ),
    ),
    Category(
        "Impersonation / Digital Arrest",
        "Police, CBI, customs, TRAI or the RBI never arrest or interrogate anyone over a "
        "video call, and never ask for money to 'clear' a case. 'Digital arrest' does not "
        "exist in law. Hang up and call 1930 (cyber crime helpline).",
        (
            _rule(r"\bdigital\s+arrest\b", 5, "Mentions 'digital arrest'"),
            _rule(r"\b(cbi|police|customs|narcotics|ncb|trai|enforcement\s+directorate|cyber\s*crime|"
                  r"income\s+tax\s+department|rbi)\b.{0,80}\b(arrest\w*|warrant|fir|legal\s+action|money\s+laundering|"
                  r"case\s+(?:has\s+been\s+)?registered|illegal\s+activit\w+)", 4, "Officer + arrest/legal threat"),
            _rule(r"\b(video\s+call|skype|whatsapp\s+call)\b.{0,60}\b(police|cbi|officer|statement|verification)\b", 3,
                  "Official 'verification' over video call"),
            _rule(r"\byour\s+(aadhaar|aadhar|sim|number|mobile)\b.{0,50}\b(used|linked|involved)\b.{0,50}"
                  r"\b(illegal|crime|fraud|money\s+laundering|drugs?)\b", 4, "Claims your ID/SIM is linked to a crime"),
        ),
    ),
    Category(
        "Investment / Crypto Scam",
        "No genuine investment can guarantee returns or double your money. Tip groups on "
        "WhatsApp/Telegram show fake profits to push you into depositing more. Invest only "
        "through SEBI-registered platforms.",
        (
            _rule(r"\bguaranteed\s+(returns?|profits?|income)\b|\bdouble\s+your\s+(money|investment)\b|"
                  r"\brisk[- ]free\s+(returns?|profits?)\b", 4, "Guaranteed / doubled returns"),
            _rule(r"\b\d{2,3}\s?%\s*(daily|weekly|monthly|per\s+(?:day|week|month))", 3, "Unrealistic % returns"),
            _rule(r"\b(stock|share\s+market|trading|crypto|bitcoin|forex|ipo)\b.{0,60}\b(tips?|signals?|group|vip|"
                  r"premium|guaranteed|allotment)\b", 2, "Trading/crypto tips group"),
            _rule(r"\b(join|add)\b.{0,40}\b(whatsapp|telegram)\b.{0,30}\b(group|channel)\b", 2,
                  "Invitation to a WhatsApp/Telegram group"),
        ),
    ),
    Category(
        "Loan App Threat",
        "Illegal loan apps lure you with 'no documents' loans and then harass you and your "
        "contacts. Borrow only from RBI-registered banks and NBFCs, and never allow apps "
        "access to your contacts or photos.",
        (
            _rule(r"\b(instant|pre[- ]?approved|urgent)\s+loan\b.{0,60}\b(no\s+(?:cibil|documents?|collateral)|"
                  r"approved|click|apply|link)", 3, "Instant / pre-approved loan offer"),
            _rule(r"\bno\s+(cibil|credit\s+check|documents?\s+required)\b", 2, "'No CIBIL / no documents' loan"),
            _rule(r"\b(repay|pay)\b.{0,40}\b(or\s+we\s+will|otherwise|else)\b.{0,50}\b(contacts?|family|photos?|"
                  r"relatives|friends)\b|\binform\s+your\s+contacts\b", 5, "Threatens to contact your family/contacts"),
        ),
    ),
    Category(
        "SIM / Telecom Scam",
        "Telecom companies do not block your SIM through an SMS asking you to call or click a "
        "link. Check your connection status in your operator's official app.",
        (
            _rule(r"\b(sim|mobile\s+number|phone\s+number)\b.{0,40}\b(block\w*|deactivat\w*|disconnect\w*|suspend\w*)\b"
                  r".{0,50}\b(\d+\s*(?:hours?|hrs?)|today|tonight|immediately|kyc|verify)", 4, "SIM blocking threat"),
            _rule(r"\b(5g|4g)\s+(sim\s+)?(upgrade|activation)\b.{0,40}\b(click|link|otp)", 3, "Fake 5G/4G SIM upgrade"),
            _rule(r"\btrai\b.{0,40}\b(notice|block\w*|disconnect\w*)", 3, "Fake TRAI notice"),
        ),
    ),
)

SUSPICIOUS_LINK = Category(
    "Suspicious Link",
    "This message contains a link that shows several warning signs of phishing. Do not open "
    "it. If it claims to be from a company, go to that company's official website or app "
    "directly instead.",
    (),
)

URGENCY_RE = re.compile(
    r"\b(immediately|urgent(?:ly)?|within\s+\d+\s*(?:hours?|hrs?|minutes?|mins?)|today\s+only|"
    r"last\s+(?:chance|day|warning)|expires?\s+(?:today|soon|tonight)|act\s+now|final\s+(?:notice|warning)|"
    r"right\s+now|asap|turant|abhi)\b",
    re.IGNORECASE,
)

# "Do not share your OTP with anyone" is a genuine warning in real bank SMS - strip it.
_NEGATED_SHARE = re.compile(
    r"\b(?:do\s*not|don'?t|dont|never|not\s+to)\s+(?:ever\s+)?(?:share|disclose|reveal|give|send|tell)\b[^.!?\n]{0,40}",
    re.IGNORECASE,
)


def normalize(text: str) -> str:
    text = unicodedata.normalize("NFKC", text)
    text = _NEGATED_SHARE.sub(" ", text)
    return re.sub(r"\s+", " ", text).strip()


# --------------------------------------------------------------------------- #
# Link analysis
# --------------------------------------------------------------------------- #
_URL_RE = re.compile(
    r"(?i)\b((?:https?://|www\.)[^\s<>\"']+|"
    r"(?:[a-z0-9-]+\.)+(?:com|in|net|org|xyz|top|click|link|info|online|site|live|co|me|cc|tk|ml|ga|cf|gq|"
    r"icu|vip|club|shop|buzz|cyou|rest|bond)\b(?:/[^\s<>\"']*)?)"
)
_TWO_PART_SUFFIXES = {"co.in", "org.in", "gov.in", "nic.in", "ac.in", "net.in", "bank.in",
                      "com.au", "co.uk", "gov.uk"}
_SHORTENERS = {"bit.ly", "tinyurl.com", "t.co", "goo.gl", "is.gd", "cutt.ly", "rb.gy", "shorturl.at",
               "tiny.cc", "ow.ly", "buff.ly", "rebrand.ly", "bl.ink", "s.id", "v.gd", "t.ly"}
_SUSPICIOUS_TLDS = {"xyz", "top", "click", "link", "icu", "vip", "club", "buzz", "cyou", "rest", "bond",
                    "tk", "ml", "ga", "cf", "gq", "live", "online", "site", "shop", "info"}
_RISKY_WORDS = ("verify", "update", "login", "kyc", "claim", "refund", "secure", "reward", "bonus", "gift")

_BRANDS = {
    "sbi": {"sbi.co.in", "onlinesbi.sbi", "sbi.bank.in", "sbicard.com", "sbilife.co.in", "sbimf.com"},
    "hdfc": {"hdfcbank.com", "hdfc.com", "hdfclife.com", "hdfcsec.com"},
    "icici": {"icicibank.com", "icicibank.co.in", "icicidirect.com", "icicilombard.com", "iciciprulife.com"},
    "axisbank": {"axisbank.com"},
    "kotak": {"kotak.com", "kotak.bank.in"},
    "paytm": {"paytm.com", "paytmbank.com"},
    "phonepe": {"phonepe.com"},
    "amazon": {"amazon.in", "amazon.com", "amazon.co.uk", "amazonaws.com"},
    "flipkart": {"flipkart.com"},
    "npci": {"npci.org.in"},
    "uidai": {"uidai.gov.in"},
    "incometax": {"incometax.gov.in"},
    "irctc": {"irctc.co.in"},
    "airtel": {"airtel.in", "airtel.com"},
    "jio": {"jio.com", "jiomart.com"},
    "indiapost": {"indiapost.gov.in"},
    "fedex": {"fedex.com"},
}


def registered_domain(host: str) -> str:
    parts = host.split(".")
    if len(parts) >= 3 and ".".join(parts[-2:]) in _TWO_PART_SUFFIXES:
        return ".".join(parts[-3:])
    return ".".join(parts[-2:]) if len(parts) >= 2 else host


def extract_urls(message: str) -> list[str]:
    seen: list[str] = []
    for match in _URL_RE.finditer(message):
        url = match.group(1).rstrip(".,;:!?)]}'\"")
        if url and url not in seen:
            seen.append(url)
    return seen


def score_url(url: str) -> tuple[int, list[str]]:
    explicit_http = url.lower().startswith("http://")
    parsed = urlparse(url if "://" in url else "http://" + url)
    host = (parsed.hostname or "").lower()
    if not host:
        return 0, []
    reg = registered_domain(host)
    tld = host.rsplit(".", 1)[-1]
    score, signals = 0, []

    if reg in _SHORTENERS:
        score += 2
        signals.append(f"Shortened link ({reg}) hides the real destination")
    if re.fullmatch(r"\d{1,3}(\.\d{1,3}){3}", host):
        score += 2
        signals.append("Link uses a raw IP address instead of a website name")
    if "@" in (parsed.netloc or ""):
        score += 2
        signals.append("Link contains '@' (disguised destination)")
    if "xn--" in host:
        score += 2
        signals.append("Link uses look-alike (punycode) characters")
    if tld in _SUSPICIOUS_TLDS:
        score += 1
        signals.append(f"Link ends in '.{tld}', often used for throwaway scam sites")
    if host.count("-") >= 2:
        score += 1
        signals.append("Link has many hyphens, typical of fake sites")
    if explicit_http:
        score += 1
        signals.append("Link is not encrypted (http, not https)")
    for brand, official in _BRANDS.items():
        if brand in host and reg not in official:
            score += 3
            signals.append(f"Link imitates '{brand}' but is not its official website")
            break
    if any(word in host + parsed.path.lower() for word in _RISKY_WORDS):
        score += 1
        signals.append("Link asks you to verify/update/claim something")
    return score, signals


# --------------------------------------------------------------------------- #
# Main entry point
# --------------------------------------------------------------------------- #
@dataclass
class Verdict:
    is_scam: bool
    category: Optional[str]
    explanation: str
    score: int
    confidence: float
    risk_level: str
    signals: list[str] = field(default_factory=list)
    urls: list[str] = field(default_factory=list)


def analyze(message: str, url_checker: Optional[Callable[[str], Optional[int]]] = None) -> Verdict:
    text = normalize(message)

    best: Optional[Category] = None
    best_score, best_signals = 0, []
    for category in CATEGORIES:
        score, signals = 0, []
        for pattern, weight, label in category.rules:
            if pattern.search(text):
                score += weight
                signals.append(label)
        if score > best_score:
            best, best_score, best_signals = category, score, signals

    urls = extract_urls(message)
    url_score, url_signals = 0, []
    for url in urls:
        s, sig = score_url(url)
        url_score += s
        url_signals += sig
    url_score = min(url_score, 6)

    if url_checker:
        for url in urls[:3]:
            malicious = url_checker(url)
            if malicious is not None and malicious >= 2:
                url_score += 5
                url_signals.append(f"{malicious} security engines on VirusTotal flag this link as malicious")
                break

    urgency = best_score > 0 and bool(URGENCY_RE.search(text))
    signals = best_signals + (["Creates false urgency"] if urgency else []) + url_signals
    total = best_score + (1 if urgency else 0) + url_score
    is_scam = total >= THRESHOLD

    category = best if best_score > 0 else (SUSPICIOUS_LINK if url_score >= THRESHOLD else None)
    risk = "high" if total >= 6 else "medium" if total >= THRESHOLD else "low"
    confidence = round(min(0.99, 0.35 + total * 0.08), 2) if is_scam else round(max(0.5, 0.95 - total * 0.15), 2)

    return Verdict(
        is_scam=is_scam,
        category=category.name if (is_scam and category) else None,
        explanation=category.explanation if (is_scam and category) else "",
        score=total,
        confidence=confidence,
        risk_level=risk,
        signals=signals if is_scam else [],
        urls=urls,
    )
