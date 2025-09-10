
#!/usr/bin/env python3
from datetime import datetime, timezone, timedelta
from pymongo import MongoClient
import os, random, hashlib
MONGO_URI = os.getenv("MONGO_URI", "mongodb://localhost:27017")
DB = os.getenv("MONGO_DB", "leakhunter")
client = MongoClient(MONGO_URI)
mdb = client[DB]
events = mdb.events
labels = ["Credit Card", "API Token1", "Password2"]
plats = ["slack", "jira", "confluence", "trello"]
now = datetime.now(tz=timezone.utc)
docs = []
for i in range(10):
    text = f"sample secret {i} 4111-1111-1111-{1000+i} token-XYZ"
    det = [{"label": random.choice(labels), "match": "sample"}]
    fp = hashlib.sha1(f"{text}{i}".encode()).hexdigest()
    docs.append({
        "fingerprint": fp,
        "platform": random.choice(plats),
        "container": {"type": "channel", "id": f"C{i:03d}", "name": f"chan-{i}", "url": "https://example.com"},
        "found_at": now - timedelta(minutes=10-i),
        "severity": random.choice(["Low","Medium","High"]),
        "detections": det,
        "snippet_redacted": text.replace("4111-1111-1111", "4111-****-****"),
        "source_meta": {"author_name": "seed", "author_id": "seed"},
    })
for d in docs:
    events.update_one({"fingerprint": d["fingerprint"]}, {"$setOnInsert": d}, upsert=True)
print(f"Inserted/kept {len(docs)} sample events. DB={DB}")
