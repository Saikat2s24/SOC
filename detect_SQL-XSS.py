import sqlite3
import html
def login_user(username, password):
    conn = sqlite3.connect(':memory:')
    cursor = conn.cursor()
    
    query = "SELECT id FROM users WHERE username = ? AND password = ?"
    try:
        cursor.execute(query, (username, password))
        user = cursor.fetchone()
        return user is not None
    except sqlite3.Error as e:
        print(f"Database error: {e}")
        return False
    finally:
        conn.close()
def sanitize_user_input(user_bio):
    safe_output = html.escape(user_bio)
    return safe_output
