# dashboard.py
from flask import Flask, render_template, jsonify
import os
import json

EVENT_FILE = os.path.join(os.getcwd(), "ids_events.jsonl")
STATS_FILE = os.path.join(os.getcwd(), "ids_stats.json")

app = Flask(__name__)

def tail_last_events(n=50):
    """Read last n JSONL events from EVENT_FILE (fast-ish)."""
    if not os.path.exists(EVENT_FILE):
        return []
    lines = []
    # read file backwards safely for reasonably sized file
    with open(EVENT_FILE, "r", encoding="utf-8") as f:
        all_lines = f.readlines()
    for line in all_lines[-n:]:
        try:
            lines.append(json.loads(line))
        except:
            continue
    # newest last
    return lines

def read_stats():
    if not os.path.exists(STATS_FILE):
        return {}
    try:
        with open(STATS_FILE, "r", encoding="utf-8") as f:
            return json.load(f)
    except:
        return {}

@app.route("/")
def index():
    return render_template("index.html")

@app.route("/api/logs")
def api_logs():
    events = tail_last_events(100)
    return jsonify({"events": events})

@app.route("/api/stats")
def api_stats():
    s = read_stats()
    return jsonify(s)

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=True)
