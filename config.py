"""
Centralized configuration, data signatures, wordlists, and default settings for the Security Headers & Exposure Auditor.
"""

from typing import Dict, List

# Request settings
DEFAULT_TIMEOUT: float = 10.0
MAX_CONCURRENCY: int = 50
USER_AGENT: str = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) SecurityHeadersAuditor/1.0"
DEFAULT_RATE_LIMIT_DELAY: float = 0.05  # Delay between requests in seconds to avoid overwhelming targets

# Severity Levels
SEVERITY_HIGH: str = "High"
SEVERITY_MEDIUM: str = "Medium"
SEVERITY_LOW: str = "Low"
SEVERITY_INFO: str = "Info"

# Exposure Wordlists and Verification Signatures
# Each entry specifies the path to probe and optional signature verification patterns / keywords
EXPOSURE_PATHS: List[Dict[str, any]] = [
    # Environment & Configuration Files
    {
        "path": ".env",
        "category": "Configuration",
        "severity": SEVERITY_HIGH,
        "description": "Exposed environment variable file containing potential credentials and secrets.",
        "signatures": ["=", "DB_", "API_KEY", "SECRET", "PASSWORD", "APP_ENV"],
        "min_length": 10,
    },
    {
        "path": ".env.local",
        "category": "Configuration",
        "severity": SEVERITY_HIGH,
        "description": "Exposed local environment variable file.",
        "signatures": ["=", "DB_", "API_KEY", "SECRET", "PASSWORD"],
        "min_length": 10,
    },
    {
        "path": ".env.production",
        "category": "Configuration",
        "severity": SEVERITY_HIGH,
        "description": "Exposed production environment variable file.",
        "signatures": ["=", "DB_", "API_KEY", "SECRET"],
        "min_length": 10,
    },
    {
        "path": "docker-compose.yml",
        "category": "Configuration",
        "severity": SEVERITY_MEDIUM,
        "description": "Exposed Docker Compose configuration file.",
        "signatures": ["version:", "services:", "image:", "environment:"],
        "min_length": 15,
    },
    {
        "path": "Dockerfile",
        "category": "Configuration",
        "severity": SEVERITY_LOW,
        "description": "Exposed Dockerfile blueprint.",
        "signatures": ["FROM ", "RUN ", "COPY ", "WORKDIR "],
        "min_length": 10,
    },
    {
        "path": "wp-config.php.bak",
        "category": "Configuration",
        "severity": SEVERITY_HIGH,
        "description": "Exposed WordPress configuration backup file.",
        "signatures": ["DB_NAME", "DB_USER", "DB_PASSWORD", "auth_key"],
        "min_length": 20,
    },
    {
        "path": "config.json",
        "category": "Configuration",
        "severity": SEVERITY_MEDIUM,
        "description": "Exposed JSON configuration file.",
        "signatures": ["{", "}"],
        "min_length": 5,
    },
    {
        "path": "settings.py",
        "category": "Configuration",
        "severity": SEVERITY_MEDIUM,
        "description": "Exposed Python settings file.",
        "signatures": ["DATABASES", "SECRET_KEY", "DEBUG ="],
        "min_length": 10,
    },

    # Version Control & Debug Artifacts
    {
        "path": ".git/HEAD",
        "category": "Version Control",
        "severity": SEVERITY_HIGH,
        "description": "Exposed Git repository HEAD file.",
        "signatures": ["ref: refs/"],
        "min_length": 5,
    },
    {
        "path": ".git/config",
        "category": "Version Control",
        "severity": SEVERITY_HIGH,
        "description": "Exposed Git configuration file.",
        "signatures": ["[core]", "[remote", "url ="],
        "min_length": 10,
    },
    {
        "path": "phpinfo.php",
        "category": "Debug",
        "severity": SEVERITY_MEDIUM,
        "description": "Exposed PHP information disclosure page.",
        "signatures": ["PHP Version", "<title>phpinfo()</title>", "System "],
        "min_length": 50,
    },
    {
        "path": ".DS_Store",
        "category": "Metadata",
        "severity": SEVERITY_LOW,
        "description": "Exposed macOS Finder metadata file.",
        "signatures": ["Budm", "File"],
        "min_length": 4,
    },

    # Archive & Database Dumps
    {
        "path": "backup.zip",
        "category": "Backup & Database",
        "severity": SEVERITY_HIGH,
        "description": "Exposed archive backup file.",
        "signatures": ["PK"],  # ZIP magic bytes (checked via bytes prefix)
        "is_binary": True,
        "min_length": 10,
    },
    {
        "path": "backup.tar.gz",
        "category": "Backup & Database",
        "severity": SEVERITY_HIGH,
        "description": "Exposed TAR GZ archive backup.",
        "signatures": ["\\x1f\\x8b"],  # Gzip magic bytes
        "is_binary": True,
        "min_length": 10,
    },
    {
        "path": "backup.sql",
        "category": "Backup & Database",
        "severity": SEVERITY_HIGH,
        "description": "Exposed SQL database backup dump.",
        "signatures": ["CREATE TABLE", "INSERT INTO", "-- MySQL dump", "DROP TABLE"],
        "min_length": 15,
    },
    {
        "path": "dump.sql",
        "Category": "Backup & Database",
        "severity": SEVERITY_HIGH,
        "description": "Exposed SQL database dump file.",
        "signatures": ["CREATE TABLE", "INSERT INTO", "-- MySQL dump"],
        "min_length": 15,
    },
    {
        "path": "database.sqlite",
        "category": "Backup & Database",
        "severity": SEVERITY_HIGH,
        "description": "Exposed SQLite database file.",
        "signatures": ["SQLite format 3"],
        "is_binary": True,
        "min_length": 16,
    }
]
