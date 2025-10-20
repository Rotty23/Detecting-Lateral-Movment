import os
import time
import socket
import json
import shutil
import wmi
import sqlite3
import threading
import pythoncom
from datetime import datetime, timedelta
from confluent_kafka import Producer
import csv
from urllib.parse import urlparse

# === CONFIG ===
EXECUTABLE_EXTENSIONS = [".exe", ".bat", ".ps1"]
CHROME_HISTORY_PATH = os.path.join(
    os.environ["LOCALAPPDATA"],
    "Google",
    "Chrome",
    "User Data",
    "Default",
    "History"
)
TEMP_HISTORY_COPY = "temp_chrome_history"
MALICIOUS_DOMAINS = set()  # Will be populated from CSV

# Kafka configuration
KAFKA_BROKER = "192.168.6.62:9092"  # Change if your Kafka broker is elsewhere
KAFKA_TOPIC = "agent-events"
kafka_producer = Producer({'bootstrap.servers': KAFKA_BROKER})

# === MALICIOUS DOMAIN FETCHER (CSV) ===
def fetch_malicious_domains():
    domains = set()
    try:
        with open("csv.txt", "r", encoding="utf-8") as f:
            reader = csv.reader(f)
            for row in reader:
                if not row or row[0].startswith("#") or row[0].startswith('"id"'):
                    continue  # Skip comments and header
                if len(row) > 2:
                    url = row[2].strip('"')
                    parsed = urlparse(url)
                    if parsed.hostname:
                        domains.add(parsed.hostname)
        print(f"[CSV] Loaded {len(domains)} domains from CSV.")
    except Exception as e:
        print(f"[CSV] Error loading domains: {e}")
    return domains

def refresh_domains_periodically():
    global MALICIOUS_DOMAINS
    while True:
        MALICIOUS_DOMAINS = fetch_malicious_domains()
        time.sleep(86400)  # 24 hours

# === COMMON EVENT LOGGER ===
def log_event(event_type, data):
    event = {
        "event_type": event_type,
        "data": data,
        "timestamp": time.time(),
        "hostname": socket.gethostname()
    }
    json_event = json.dumps(event)

    print(json_event)  # Log locally

    # Send event to Kafka
    try:
        kafka_producer.produce(KAFKA_TOPIC, json_event.encode('utf-8'))
        kafka_producer.poll(0)  # Trigger delivery callbacks
    except Exception as e:
        print(f"[Kafka] Failed to send event: {e}")

# === PROCESS MONITORING (FILE EXECUTION) ===
def is_suspicious_exec(command_line):
    if command_line:
        return any(command_line.lower().endswith(ext) for ext in EXECUTABLE_EXTENSIONS)
    return False

def monitor_process_execution():
    pythoncom.CoInitialize()  # Initialize COM in this thread
    c = wmi.WMI()
    watcher = c.Win32_Process.watch_for("creation")
    print("[Process Monitor] Monitoring for executable launches...")

    while True:
        try:
            new_proc = watcher()
            command = new_proc.CommandLine or new_proc.Name
            if is_suspicious_exec(command):
                log_event("file_executed", {"command": command})
        except Exception as e:
            print(f"[Process Monitor] Error: {e}")
            time.sleep(2)

# === BROWSER HISTORY MONITORING (SUSPICIOUS URLS) ===
def scan_browser_history():
    print("[URL Scanner] Started scanning Chrome history every 5 minutes...")
    last_scan_time = datetime.now() - timedelta(minutes=5)
    while True:
        try:
            if not os.path.exists(CHROME_HISTORY_PATH):
                print(f"[URL Scanner] Chrome history not found at {CHROME_HISTORY_PATH}")
                time.sleep(300)
                continue

            shutil.copy2(CHROME_HISTORY_PATH, TEMP_HISTORY_COPY)
            conn = sqlite3.connect(TEMP_HISTORY_COPY)
            cursor = conn.cursor()

            # Only get history since last scan
            chrome_time_cutoff = last_scan_time.timestamp() * 1_000_000
            cursor.execute("SELECT url FROM urls WHERE last_visit_time > ?", (int(chrome_time_cutoff),))

            for (url,) in cursor.fetchall():
                domain = url.split("://", 1)[-1].split("/", 1)[0]
                if domain in MALICIOUS_DOMAINS:
                    log_event("suspicious_url", {"url": url})

            conn.close()
            os.remove(TEMP_HISTORY_COPY)
            last_scan_time = datetime.now()
        except Exception as e:
            print(f"[URL Scanner] Error: {e}")

        time.sleep(300)  # 5 minutes

# === MAIN ===
if __name__ == "__main__":
    print("[Agent] Starting combined agent...")

    # Start domain refresh thread
    domain_thread = threading.Thread(target=refresh_domains_periodically, daemon=True)
    domain_thread.start()

    # Thread 1: Monitor file execution
    process_thread = threading.Thread(target=monitor_process_execution, daemon=True)
    process_thread.start()

    # Thread 2: Monitor browser history
    browser_thread = threading.Thread(target=scan_browser_history, daemon=True)
    browser_thread.start()

    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        print("[Agent] Shutting down.")