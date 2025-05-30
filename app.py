"""
TAS-Final-Exam - Vulnerable Web Application

This application intentionally contains multiple vulnerabilities:
1. Information Disclosure - Exposed backup file with MD5 hashed passwords
2. SQL Injection - Vulnerable search functionality
3. Broken Access Control (IDOR) - Vulnerable email update feature
4. SSRF - Vulnerable URL fetcher in admin panel
"""

from flask import Flask, render_template, request, redirect, url_for, session, g, abort, jsonify, flash, send_file
import os
import sqlite3
import hashlib
import time
import uuid
import requests
from urllib.parse import urlparse
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime
import json

# Create app
app = Flask(__name__)
app.config.update(
    SECRET_KEY='TAS-Final-Exam-Secret-Key',
    DATABASE=os.path.join(app.root_path, 'database.db'),
    INTERNAL_API_URL='http://localhost:3333/flag',
    MAX_CONTENT_LENGTH=16 * 1024 * 1024  # 16MB max upload
)

# Make sure static directories exist
os.makedirs(os.path.join(app.root_path, 'static', 'uploads'), exist_ok=True)
os.makedirs(os.path.join(app.root_path, 'static', 'images'), exist_ok=True)

# Database helper functions
def get_db():
    if 'db' not in g:
        g.db = sqlite3.connect(app.config['DATABASE'])
        g.db.row_factory = sqlite3.Row
    return g.db

@app.teardown_appcontext
def close_db(e=None):
    db = g.pop('db', None)
    if db is not None:
        db.close()

def init_db():
    db = get_db()
    
    # Create tables
    with app.open_resource('schema.sql', mode='r') as f:
        db.executescript(f.read())
    
    # Create flags table
    db.execute('CREATE TABLE IF NOT EXISTS flags (id INTEGER PRIMARY KEY, name TEXT, value TEXT)')
    
    # Insert flags if they don't exist
    flags = [
        ('FLAG2', 'TAS{SQL_1nj3ct10n_vuln3r4b1l1ty_3xpl01t3d}')
    ]
    
    for flag_name, flag_value in flags:
        db.execute('INSERT OR IGNORE INTO flags (name, value) VALUES (?, ?)', (flag_name, flag_value))
    
    # Create test users with flag
    users = [
        ('flag', 'flag@tas.com', generate_hash_md5('qwerty123'), 'user', 'Flag User', 'Flag Owner', '0123456789', 'Flag Street', 'Flag City', 'Vietnam', 'This user has the first flag: TAS{1nf0rm4t10n_d1scl0sur3_l34ds_t0_4cc0unt_t4k30v3r}')
    ]
    
    # Create 19 test users first (admin will be 20th)
    for i in range(1, 20):
        users.append((
            f'user{i}', 
            f'user{i}@tas.com', 
            generate_hash_md5(f'password{i}'), 
            'user',
            f'User {i}',
            f'Regular User {i}',
            f'123456789{i}',
            f'Street {i}',
            f'City {i}',
            'Vietnam',
            f'This is the bio for user {i}'
        ))
    
    # Add admin as the 20th user to make ID = 20
    users.append((
        'admin', 
        'admin@tas.com', 
        generate_hash_md5('TAS{IDOR_vuln3r4b1l1ty_l34ds_t0_pr1v1l3g3_3sc4l4t10n}'), 
        'admin', 
        'Admin', 
        'Administrator', 
        '0987654321', 
        'Admin Office', 
        'Admin City', 
        'Vietnam', 
        'Admin bio with FLAG3 also is admin password: TAS{IDOR_vuln3r4b1l1ty_l34ds_t0_pr1v1l3g3_3sc4l4t10n}'
    ))
    
    # Add the 21st user (user20)
    users.append((
        'user20', 
        f'user20@tas.com', 
        generate_hash_md5(f'password20'), 
        'user',
        f'User 20',
        f'Regular User 20',
        f'1234567890',
        f'Street 20',
        f'City 20',
        'Vietnam',
        f'This is the bio for user 20'
    ))
    
    for username, email, password, role, full_name, company, phone, address, city, country, bio in users:
        # Check if user exists
        cursor = db.execute('SELECT id FROM users WHERE username = ?', (username,))
        if cursor.fetchone() is None:
            db.execute('''
                INSERT INTO users (username, email, password, role, full_name, company, phone, address, city, country, bio, created_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ''', (username, email, password, role, full_name, company, phone, address, city, country, bio, datetime.now()))
    
    # Create blog posts
    posts = [
        ('Web Application Security Best Practices', 'Learn about the most important security practices for your web applications.', 'In today\'s digital landscape, web application security is more important than ever. This article covers essential security practices that every developer should know.<br><br>Cross-Site Scripting (XSS) attacks are a type of injection, in which malicious scripts are injected into otherwise benign and trusted websites. XSS attacks occur when an attacker uses a web application to send malicious code, generally in the form of a browser side script, to a different end user.<br><br>SQL Injection is a code injection technique, used to attack data-driven applications, in which malicious SQL statements are inserted into an entry field for execution.<br><br>Cross-Site Request Forgery (CSRF) is an attack that forces an end user to execute unwanted actions on a web application in which they\'re currently authenticated.', 'security', 20, 'images/img1.jpg'),
        ('Understanding OWASP Top 10', 'An overview of the most critical web application security risks.', 'The OWASP Top 10 is a standard awareness document for developers and web application security. It represents a broad consensus about the most critical security risks to web applications.<br><br>1. Injection<br>2. Broken Authentication<br>3. Sensitive Data Exposure<br>4. XML External Entities (XXE)<br>5. Broken Access Control<br>6. Security Misconfiguration<br>7. Cross-Site Scripting (XSS)<br>8. Insecure Deserialization<br>9. Using Components with Known Vulnerabilities<br>10. Insufficient Logging & Monitoring', 'security', 20, 'images/img1.jpg'),
        ('Introduction to Penetration Testing', 'Learn the basics of penetration testing and ethical hacking.', 'Penetration testing, also called pen testing or ethical hacking, is the practice of testing a computer system, network or web application to find security vulnerabilities that an attacker could exploit.<br><br>Penetration testing can be automated with software applications or performed manually. Either way, the process involves gathering information about the target before the test, identifying possible entry points, attempting to break in — either virtually or for real — and reporting back the findings.<br><br>The main objective of penetration testing is to identify security weaknesses. Penetration testing can also be used to test an organization\'s security policy, its adherence to compliance requirements, its employees\' security awareness and the organization\'s ability to identify and respond to security incidents.', 'security', 20, 'images/img1.jpg'),
        ('Secure Coding Guidelines', 'Essential guidelines for writing secure code.', 'Secure coding is the practice of developing computer software in a way that guards against the accidental introduction of security vulnerabilities. Defects, bugs and logic flaws are consistently the primary cause of commonly exploited software vulnerabilities.<br><br>1. Input Validation: All input is evil until proven otherwise.<br>2. Output Encoding: Encode all output to prevent injection attacks.<br>3. Authentication and Password Management: Implement secure authentication mechanisms.<br>4. Session Management: Implement secure session handling.<br>5. Access Control: Implement proper authorization checks.<br>6. Cryptographic Practices: Use strong, standard algorithms and secure key management.<br>7. Error Handling and Logging: Implement proper error handling and logging.<br>8. Data Protection: Protect sensitive data in storage and in transit.<br>9. Communication Security: Implement secure communication channels.<br>10. System Configuration: Secure the underlying platform configuration.', 'development', 20, 'images/img1.jpg'),
        ('Cloud Security Challenges', 'Understanding the security challenges in cloud environments.', 'Cloud computing presents many unique security issues and challenges. In the cloud, data is stored with a third-party provider and accessed over the internet. This means visibility and control over that data is limited.<br><br>The main challenges in cloud security include:<br><br>1. Data Breaches<br>2. Misconfiguration and Inadequate Change Control<br>3. Lack of Cloud Security Architecture and Strategy<br>4. Insufficient Identity, Credential, Access and Key Management<br>5. Account Hijacking<br>6. Insider Threat<br>7. Insecure Interfaces and APIs<br>8. Weak Control Plane<br>9. Metastructure and Applistructure Failures<br>10. Limited Cloud Usage Visibility<br>11. Abuse and Nefarious Use of Cloud Services', 'cloud', 20, 'images/img1.jpg')
    ]
    
    for title, summary, content, category, author_id, image_path in posts:
        cursor = db.execute('SELECT id FROM posts WHERE title = ?', (title,))
        if cursor.fetchone() is None:
            db.execute('''
                INSERT INTO posts (title, summary, content, category, author_id, image_path, created_at)
                VALUES (?, ?, ?, ?, ?, ?, ?)
            ''', (title, summary, content, category, author_id, image_path, datetime.now()))
    
    # Commit changes
    db.commit()
    
    # Create backup file with MD5 hashes (vulnerable)
    create_backup_file()

def generate_hash_md5(password):
    """Generate MD5 hash for password (vulnerable by design)"""
    return hashlib.md5(password.encode()).hexdigest()

def create_backup_file():
    """Create backup file with user data including MD5 hashed passwords"""
    db = get_db()
    users = db.execute('SELECT username, email, password, role FROM users').fetchall()
    
    backup_data = []
    for user in users:
        backup_data.append({
            'username': user['username'],
            'email': user['email'],
            'password_hash': user['password'],  # MD5 hash (vulnerable)
            'role': user['role']
        })
    
    # Move to root static directory for easier discovery
    backup_path = os.path.join(app.root_path, 'static', 'backup.bak')
    with open(backup_path, 'w') as f:
        f.write(json.dumps(backup_data, indent=4))
    
    # Print backup URL for verification
    print(f"\n[INFO] Backup file created at: {backup_path}")
    print(f"[INFO] Accessible via URL: http://localhost:1111/static/backup.bak\n")

# Internal API server setup (for SSRF)
def setup_internal_server():
    """Setup internal server for SSRF vulnerability demo"""
    from threading import Thread
    from http.server import HTTPServer, BaseHTTPRequestHandler
    
    class InternalAPIHandler(BaseHTTPRequestHandler):
        def do_GET(self):
            print(f"[Internal Server] Received request for: {self.path}")
            
            if self.path == '/flag' or self.path == '/flag/':
                self.send_response(200)
                self.send_header('Content-Type', 'application/json')
                self.end_headers()
                response = {
                    'flag': 'TAS{SSRF_vuln3r4b1l1ty_3xpl01t3d_succ3ssfully}',
                    'message': 'Congratulations! You have successfully exploited the SSRF vulnerability.'
                }
                response_json = json.dumps(response)
                self.wfile.write(response_json.encode('utf-8'))
                print(f"[Internal Server] Sent flag response: {response_json}")
            else:
                self.send_response(404)
                self.send_header('Content-Type', 'text/plain')
                self.end_headers()
                error_message = f"Path not found: {self.path}. Try accessing /flag instead."
                self.wfile.write(error_message.encode('utf-8'))
                print(f"[Internal Server] Path not found: {self.path}")
        
        def log_message(self, format, *args):
            # Simple logging
            print(f"[Internal Server] {format % args}")
    
    def run_server():
        try:
            server = HTTPServer(('127.0.0.1', 3333), InternalAPIHandler)
            print("\n[INFO] Internal flag server started at http://127.0.0.1:3333")
            print("[INFO] Flag endpoint available at http://127.0.0.1:3333/flag")
            print("[INFO] This server is only accessible locally (SSRF target)\n")
            server.serve_forever()
        except Exception as e:
            print(f"[ERROR] Failed to start internal server: {str(e)}")
    
    thread = Thread(target=run_server, daemon=True)
    thread.start()

# User loader
@app.before_request
def load_logged_in_user():
    g.user = None
    user_id = session.get('user_id')
    
    if user_id is not None:
        db = get_db()
        g.user = db.execute('SELECT * FROM users WHERE id = ?', (user_id,)).fetchone()

# Routes
@app.route('/')
def index():
    db = get_db()
    posts = db.execute('''
        SELECT p.id, p.title, p.summary, p.category, p.image_path, p.created_at, u.username 
        FROM posts p JOIN users u ON p.author_id = u.id 
        ORDER BY p.created_at DESC LIMIT 5
    ''').fetchall()
    
    return render_template('index.html', posts=posts)

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        
        db = get_db()
        error = None
        
        user = db.execute('SELECT * FROM users WHERE username = ?', (username,)).fetchone()
        
        if user is None:
            error = 'Invalid username or password'
        elif user['password'] != generate_hash_md5(password):
            error = 'Invalid username or password'
        
        if error is None:
            session.clear()
            session['user_id'] = user['id']
            session['role'] = user['role']
            flash('You have successfully logged in!', 'success')
            return redirect(url_for('index'))
        
        flash(error, 'danger')
    
    return render_template('login.html')

@app.route('/logout')
def logout():
    session.clear()
    flash('You have been logged out.', 'info')
    return redirect(url_for('index'))

@app.route('/profile')
def profile():
    if g.user is None:
        flash('You need to log in first.', 'warning')
        return redirect(url_for('login'))
    
    return render_template('profile.html')

@app.route('/posts')
def posts():
    db = get_db()
    posts = db.execute('''
        SELECT p.id, p.title, p.summary, p.category, p.image_path, p.created_at, u.username 
        FROM posts p JOIN users u ON p.author_id = u.id 
        ORDER BY p.created_at DESC
    ''').fetchall()
    
    return render_template('posts.html', posts=posts)

@app.route('/post/<int:post_id>')
def post(post_id):
    db = get_db()
    post = db.execute('''
        SELECT p.*, u.username 
        FROM posts p JOIN users u ON p.author_id = u.id 
        WHERE p.id = ?
    ''', (post_id,)).fetchone()
    
    if post is None:
        abort(404)
    
    comments = db.execute('''
        SELECT c.*, u.username 
        FROM comments c JOIN users u ON c.user_id = u.id 
        WHERE c.post_id = ? 
        ORDER BY c.created_at
    ''', (post_id,)).fetchall()
    
    return render_template('post.html', post=post, comments=comments)

@app.route('/post/<int:post_id>/comment', methods=['POST'])
def add_comment(post_id):
    if g.user is None:
        flash('You need to log in to comment.', 'warning')
        return redirect(url_for('login'))
    
    content = request.form.get('content')
    
    if not content:
        flash('Comment cannot be empty.', 'danger')
        return redirect(url_for('post', post_id=post_id))
    
    db = get_db()
    db.execute(
        'INSERT INTO comments (post_id, user_id, content, created_at) VALUES (?, ?, ?, ?)',
        (post_id, g.user['id'], content, datetime.now())
    )
    db.commit()
    
    flash('Your comment has been added.', 'success')
    return redirect(url_for('post', post_id=post_id))

@app.route('/search')
def search():
    """Vulnerable to SQL Injection"""
    # Require login to access search
    if g.user is None:
        flash('You need to log in first.', 'warning')
        return redirect(url_for('login'))
    
    query = request.args.get('q', '')
    
    if not query:
        return render_template('search.html', posts=[], query='')
    
    db = get_db()
    # Vulnerable to SQL Injection - Much simpler and easier to exploit
    sql = "SELECT id, title, summary, content FROM posts WHERE title LIKE '%" + query + "%'"
    
    try:
        posts = db.execute(sql).fetchall()
        return render_template('search.html', posts=posts, query=query)
    except Exception as e:
        # Show the raw SQL error to make SQL injection easier to debug
        error_msg = f"SQL Error: {str(e)}\nQuery: {sql}"
        flash(error_msg, 'danger')
        return render_template('search.html', posts=[], query=query, error=error_msg)

@app.route('/profile/update_email', methods=['POST'])
def update_email():
    """Vulnerable to IDOR - No proper authorization check"""
    if g.user is None:
        return jsonify({'error': 'Authentication required'}), 401
    
    data = request.get_json()
    if not data or 'user_id' not in data or 'email' not in data:
        return jsonify({'error': 'Missing required fields'}), 400
    
    user_id = data['user_id']
    email = data['email']
    
    # Vulnerable to IDOR - No check if the user_id belongs to the logged-in user
    db = get_db()
    
    # Check if email already exists for another user
    existing_user = db.execute('SELECT id FROM users WHERE email = ? AND id != ?', (email, user_id)).fetchone()
    if existing_user:
        return jsonify({'error': 'Email address already in use by another user'}), 400
    
    try:
        db.execute('UPDATE users SET email = ? WHERE id = ?', (email, user_id))
        db.commit()
        
        # Return full user details (including sensitive information)
        user = db.execute('SELECT * FROM users WHERE id = ?', (user_id,)).fetchone()
        
        return jsonify({
            'id': user['id'],
            'username': user['username'],
            'email': user['email'],
            'role': user['role'],
            'full_name': user['full_name'],
            'company': user['company'],
            'phone': user['phone'],
            'address': user['address'],
            'city': user['city'],
            'country': user['country'],
            'bio': user['bio']
        })
    except Exception as e:
        # Rollback in case of any error
        db.rollback()
        return jsonify({'error': f'Failed to update email: {str(e)}'}), 500

@app.route('/admin')
def admin():
    if g.user is None or g.user['role'] != 'admin':
        flash('You do not have permission to access this page.', 'danger')
        return redirect(url_for('index'))
    
    return render_template('admin.html')

@app.route('/admin/fetch', methods=['POST'])
def admin_fetch():
    """Vulnerable to SSRF"""
    if g.user is None or g.user['role'] != 'admin':
        return jsonify({'error': 'Unauthorized'}), 403
    
    url = request.form.get('url')
    if not url:
        return jsonify({'error': 'URL is required'}), 400
    
    # Log the request for debugging
    print(f"[INFO] Admin fetch request to URL: {url}")
    
    # Vulnerable to SSRF - No validation of URL
    try:
        # Make the request to the specified URL
        response = requests.get(url, timeout=5)
        print(f"[INFO] Received response from {url} - Status: {response.status_code}")
        print(f"[INFO] Response headers: {response.headers}")
        
        # Display some debug info
        try:
            print(f"[INFO] Response content (first 200 chars): {response.text[:200]}")
        except:
            pass
        
        # Get content type and status
        content_type = response.headers.get('Content-Type', '').lower()
        status_code = response.status_code
        
        # Special handling for JSON responses
        if 'application/json' in content_type:
            try:
                json_data = response.json()
                print(f"[INFO] Parsed JSON response: {json_data}")
                return jsonify({
                    'success': True,
                    'content': json_data,
                    'content_type': content_type,
                    'status': status_code
                })
            except Exception as e:
                print(f"[ERROR] Failed to parse JSON: {str(e)}")
        
        # Handle text responses
        if 'text/' in content_type or content_type == '' or 'application/json' in content_type:
            print(f"[INFO] Returning text response: {response.text[:50]}...")
            return jsonify({
                'success': True,
                'content': response.text,
                'content_type': content_type,
                'status': status_code
            })
        
        # Handle binary content as a last resort
        file_name = os.path.basename(urlparse(url).path) or 'fetched_content'
        if not file_name:
            file_name = 'fetched_content'
            
        file_path = os.path.join(app.root_path, 'static', 'uploads', file_name)
        with open(file_path, 'wb') as f:
            f.write(response.content)
        
        return jsonify({
            'success': True,
            'file_url': url_for('static', filename=f'uploads/{file_name}'),
            'content_type': content_type,
            'status': status_code
        })
    
    except Exception as e:
        print(f"[ERROR] Failed to fetch {url}: {str(e)}")
        return jsonify({
            'error': str(e), 
            'url': url,
            'message': 'Failed to fetch the URL. Please check the URL and try again.'
        }), 500

# Error handlers
@app.errorhandler(404)
def page_not_found(e):
    return render_template('404.html'), 404

@app.errorhandler(500)
def internal_server_error(e):
    return render_template('500.html'), 500

# Added route to make /static discoverable
@app.route('/static')
def static_dir():
    """Return a directory listing for /static to expose all files"""
    static_path = os.path.join(app.root_path, 'static')
    files = os.listdir(static_path)
    
    # Build HTML for directory listing
    html = '<!DOCTYPE html><html><head><title>Index of /static</title></head><body>'
    html += '<h1>Index of /static</h1><hr><pre>'
    
    # Add parent directory link
    html += '<a href="/">../</a>\n'
    
    # List all files with links
    for file in sorted(files):
        file_path = os.path.join(static_path, file)
        if os.path.isdir(file_path):
            html += f'<a href="/static/{file}/">{file}/</a>\n'
        else:
            # Get file size
            size = os.path.getsize(file_path)
            size_str = f'{size} bytes'
            html += f'<a href="/static/{file}">{file}</a> {size_str}\n'
    
    html += '</pre><hr></body></html>'
    return html

# Initialize the app
if __name__ == '__main__':
    with app.app_context():
        init_db()
        setup_internal_server()
    app.run(host='0.0.0.0', port=1111, debug=True)
