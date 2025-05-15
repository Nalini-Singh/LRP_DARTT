
import sqlite3
import datetime

DB_PATH = 'data/pentest.db'

def init_db():
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS sessions(
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            session_name TEXT,
            target_ip TEXT,
            ports TEXT,
            vulnerabilities TEXT,
            exploits_used TEXT,
            timestamp TEXT
        )
    ''')
    conn.commit()
    conn.close()

def save_session(session_name, target_ip, ports, vulnerabilities, exploits):
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute('''
        INSERT INTO sessions(session_name, target_ip, ports, vulnerabilities, exploits_used, timestamp)
        VALUES (?, ?, ?, ?, ?, ?)
    ''', (session_name, target_ip, ports, vulnerabilities, exploits, datetime.datetime.now()))
    conn.commit()
    conn.close()
