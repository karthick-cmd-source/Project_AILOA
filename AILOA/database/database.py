import sqlite3
from datetime import datetime
from pathlib import Path


DATABASE = str(
    Path(__file__).resolve().parent.parent / "cybercopilot.db"
)


def get_connection():
    return sqlite3.connect(DATABASE)


def initialize_database():

    connection = get_connection()
    cursor = connection.cursor()

    # Command history
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS command_history (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            request TEXT NOT NULL,
            command TEXT NOT NULL,
            safety TEXT NOT NULL,
            result TEXT,
            timestamp TEXT NOT NULL
        )
    """)

    # Monitoring history
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS monitoring_history (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            monitor_type TEXT NOT NULL,
            value TEXT,
            status TEXT,
            timestamp TEXT NOT NULL
        )
    """)

    # Question / AI answer history
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS question_history (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            question TEXT NOT NULL,
            answer TEXT,
            timestamp TEXT NOT NULL
        )
    """)

    # Security check history
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS security_history (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            security_type TEXT NOT NULL,
            request TEXT,
            result TEXT,
            risk_level TEXT,
            timestamp TEXT NOT NULL
        )
    """)

    connection.commit()
    connection.close()


def save_command(request, command, safety, result):

    connection = get_connection()
    cursor = connection.cursor()

    cursor.execute("""
        INSERT INTO command_history
        (request, command, safety, result, timestamp)
        VALUES (?, ?, ?, ?, ?)
    """, (
        request,
        command,
        safety,
        result,
        datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    ))

    connection.commit()
    connection.close()


def save_monitoring(monitor_type, value, status):

    connection = get_connection()
    cursor = connection.cursor()

    cursor.execute("""
        INSERT INTO monitoring_history
        (monitor_type, value, status, timestamp)
        VALUES (?, ?, ?, ?)
    """, (
        monitor_type,
        str(value),
        status,
        datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    ))

    connection.commit()
    connection.close()


def save_question(question, answer):

    connection = get_connection()
    cursor = connection.cursor()

    cursor.execute("""
        INSERT INTO question_history
        (question, answer, timestamp)
        VALUES (?, ?, ?)
    """, (
        question,
        answer,
        datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    ))

    connection.commit()
    connection.close()


def save_security(security_type, request, result, risk_level):

    connection = get_connection()
    cursor = connection.cursor()

    cursor.execute("""
        INSERT INTO security_history
        (security_type, request, result, risk_level, timestamp)
        VALUES (?, ?, ?, ?, ?)
    """, (
        security_type,
        request,
        result,
        risk_level,
        datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    ))

    connection.commit()
    connection.close()
