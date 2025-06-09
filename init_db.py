import os
import sqlite3
from app import app

def init_db_manually():
    """Initialize the database manually without relying on app.init_db"""
    # Get database path from app config
    db_path = app.config.get('DATABASE', 'image_portal.db')
    
    # Remove existing database if it exists
    if os.path.exists(db_path):
        os.remove(db_path)
        print(f"Removed existing database: {db_path}")
    
    # Create new database
    conn = sqlite3.connect(db_path)
    
    # Disable foreign keys temporarily
    conn.execute('PRAGMA foreign_keys = OFF')
    
    # Create tables
    conn.executescript('''
    DROP TABLE IF EXISTS images;
    DROP TABLE IF EXISTS users;
    
    CREATE TABLE users (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      email TEXT UNIQUE NOT NULL,
      name TEXT NOT NULL,
      profile_pic TEXT
    );
    
    CREATE TABLE images (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      filename TEXT NOT NULL,
      caption TEXT,
      user_id INTEGER NOT NULL,
      upload_date TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
      FOREIGN KEY (user_id) REFERENCES users (id)
    );
    ''')
    
    # Re-enable foreign keys
    conn.execute('PRAGMA foreign_keys = ON')
    
    # Commit changes and close connection
    conn.commit()
    conn.close()
    
    print(f"Database initialized successfully: {db_path}")

if __name__ == "__main__":
    init_db_manually()


