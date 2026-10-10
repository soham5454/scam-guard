"""Pre-written spoken/visible warnings (the app reads these aloud with TTS)."""

SUPPORTED = ("en", "hi", "bn")

_WARNINGS = {
    "en": {
        "scam": "Warning! This message looks like a scam. Do not click any links, "
                "and never share your OTP, PIN or password with anyone.",
        "safe": "This message looks safe, but always stay careful with unknown senders.",
    },
    "hi": {
        "scam": "सावधान! यह संदेश धोखाधड़ी जैसा लगता है। किसी भी लिंक पर क्लिक न करें "
                "और अपना OTP, पिन या पासवर्ड किसी को न बताएं।",
        "safe": "यह संदेश सुरक्षित लगता है, फिर भी अनजान लोगों से सावधान रहें।",
    },
    "bn": {
        "scam": "সতর্ক থাকুন! এই বার্তাটি প্রতারণা বলে মনে হচ্ছে। কোনো লিঙ্কে ক্লিক করবেন না "
                "এবং আপনার OTP, পিন বা পাসওয়ার্ড কাউকে বলবেন না।",
        "safe": "বার্তাটি নিরাপদ মনে হচ্ছে, তবুও অচেনা প্রেরকদের থেকে সতর্ক থাকুন।",
    },
}


def normalize_lang(lang: str) -> str:
    return lang if lang in SUPPORTED else "en"


def warning_for(lang: str, is_scam: bool) -> str:
    return _WARNINGS[normalize_lang(lang)]["scam" if is_scam else "safe"]
