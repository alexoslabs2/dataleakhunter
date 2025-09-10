
import json, hashlib

def load_patterns(path="patterns.json"):
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)

def redact(text: str, matches):
    out = text
    for m in set(matches):
        if m:
            out = out.replace(m, "****")
    return out

def sha256(s: str) -> str:
    return hashlib.sha256(s.encode("utf-8")).hexdigest()
