from flask import Flask, g, render_template, flash, redirect, url_for, request, session
import os
import sqlite3
from werkzeug.utils import secure_filename
import secrets
from flask_login import LoginManager, login_user, logout_user, login_required, current_user
from datetime import datetime
from authlib.integrations.flask_client import OAuth

# Configuration
UPLOAD_FOLDER = 'static/uploads'
ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif'}
DATABASE = os.environ.get('DATABASE_PATH', 'image_portal.db')

# Create Flask app
app = Flask(__name__)
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
app.config['MAX_CONTENT_LENGTH'] = 5 * 1024 * 1024  # 5MB max upload
app.secret_key = os.environ.get('SECRET_KEY', secrets.token_hex(32))

# Google OAuth config


app.config['GOOGLE_CLIENT_ID'] = os.environ.get('GOOGLE_CLIENT_ID')
app.config['GOOGLE_CLIENT_SECRET'] = os.environ.get('GOOGLE_CLIENT_SECRET')


# Initialize OAuth
oauth = OAuth(app)
google = oauth.register(
    name='google',
    client_id=app.config['GOOGLE_CLIENT_ID'],
    client_secret=app.config['GOOGLE_CLIENT_SECRET'],
    server_metadata_url='https://accounts.google.com/.well-known/openid-configuration',
    client_kwargs={'scope': 'openid email profile'},
)

@app.route('/login')
def login():
    if current_user.is_authenticated:
        return redirect(url_for('index'))
    
    # Store the next parameter for redirection after login
    session['next'] = request.args.get('next')
    
    # Redirect to Google OAuth - ensure _external=True to get full URL
    redirect_uri = url_for('authorize', _external=True)
    return google.authorize_redirect(redirect_uri)

@app.route('/authorize')
def authorize():
    try:
        token = google.authorize_access_token()
        resp = google.get('https://www.googleapis.com/oauth2/v3/userinfo')
        user_info = resp.json()
        
        # Check if user exists in database
        db = get_db()
        user = db.execute('SELECT * FROM users WHERE email = ?', (user_info['email'],)).fetchone()
        
        if user is None:
            # Create new user
            db.execute(
                'INSERT INTO users (email, name, profile_pic) VALUES (?, ?, ?)',
                (user_info['email'], user_info.get('name', user_info['email']), user_info.get('picture'))
            )
            db.commit()
            user = db.execute('SELECT * FROM users WHERE email = ?', (user_info['email'],)).fetchone()
        
        # Login user
        user_obj = User(user['id'], user['email'], user['name'], user['profile_pic'])
        login_user(user_obj)
        
        # Redirect to next page or index
        next_page = session.pop('next', None)
        if not next_page or not next_page.startswith('/'):
            next_page = url_for('index')
        
        flash('You have been logged in successfully!')
        return redirect(next_page)
    except Exception as e:
        app.logger.error(f"OAuth error: {str(e)}")
        flash(f"Authentication error: {str(e)}")
        return redirect(url_for('index'))

# Security settings
app.config.update(
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE='Lax',
    SESSION_COOKIE_SECURE=False  # Set to True in production with HTTPS
)

# Ensure upload folder exists
os.makedirs(UPLOAD_FOLDER, exist_ok=True)

# Initialize Flask-Login
login_manager = LoginManager()
login_manager.login_view = 'login'
login_manager.init_app(app)

# Add template filter for formatting dates
@app.template_filter('format_datetime')
def format_datetime(value):
    if isinstance(value, str):
        try:
            value = datetime.strptime(value, '%Y-%m-%d %H:%M:%S')
        except ValueError:
            return value
    return value.strftime('%b %d, %Y at %I:%M %p')

# Database functions
def get_db():
    db = getattr(g, '_database', None)
    if db is None:
        db = g._database = sqlite3.connect(
            DATABASE,
            detect_types=sqlite3.PARSE_DECLTYPES
        )
        db.row_factory = sqlite3.Row
        # Enable foreign key constraints
        db.execute('PRAGMA foreign_keys = ON')
    return db

@app.teardown_appcontext
def close_connection(exception):
    db = getattr(g, '_database', None)
    if db is not None:
        db.close()

def init_db():
    with app.app_context():
        db = get_db()
        # Disable foreign keys temporarily for initialization
        db.execute('PRAGMA foreign_keys = OFF')
        with app.open_resource('schema.sql', mode='r') as f:
            db.cursor().executescript(f.read())
        # Re-enable foreign keys after initialization
        db.execute('PRAGMA foreign_keys = ON')
        db.commit()

# File upload helper
def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

# User class for Flask-Login
class User:
    def __init__(self, id, email, name, profile_pic=None):
        self.id = id
        self.email = email
        self.name = name
        self.profile_pic = profile_pic
        
    def is_authenticated(self):
        return True
        
    def is_active(self):
        return True
        
    def is_anonymous(self):
        return False
        
    def get_id(self):
        return str(self.id)

# User loader for Flask-Login
@login_manager.user_loader
def load_user(user_id):
    db = get_db()
    user = db.execute('SELECT * FROM users WHERE id = ?', (user_id,)).fetchone()
    if user is None:
        return None
    return User(user['id'], user['email'], user['name'], user['profile_pic'])

# Routes for Google authentication
# Comment out or remove this duplicate route
# @app.route('/authorize')
# def authorize():
#     token = google.authorize_access_token()
#     user_info = google.get('userinfo').json()
#     
#     # Check if user exists in database
#     db = get_db()
#     user = db.execute('SELECT * FROM users WHERE email = ?', (user_info['email'],)).fetchone()
#     
#     if user is None:
#         # Create new user
#         db.execute(
#             'INSERT INTO users (email, name, profile_pic) VALUES (?, ?, ?)',
#             (user_info['email'], user_info['name'], user_info.get('picture'))
#         )
#         db.commit()
#         user = db.execute('SELECT * FROM users WHERE email = ?', (user_info['email'],)).fetchone()
#     
#     # Login user
#     user_obj = User(user['id'], user['email'], user['name'], user['profile_pic'])
#     login_user(user_obj)
#     
#     # Redirect to next page or index
#     next_page = session.pop('next', None)
#     if not next_page or not next_page.startswith('/'):
#         next_page = url_for('index')
#     
#     flash('You have been logged in successfully!')
#     return redirect(next_page)

@app.route('/logout')
@login_required
def logout():
    logout_user()
    flash('You have been logged out')
    return redirect(url_for('index'))

@app.route('/upload', methods=['GET', 'POST'])
@login_required
def upload_image():
    if request.method == 'POST':
        # Check if the post request has the file part
        if 'image' not in request.files:
            flash('No file part')
            return redirect(request.url)
            
        file = request.files['image']
        
        # If user does not select file, browser also
        # submit an empty part without filename
        if file.filename == '':
            flash('No selected file')
            return redirect(request.url)
            
        if file and allowed_file(file.filename):
            # Secure the filename to prevent directory traversal attacks
            filename = secure_filename(file.filename)
            
            # Add a timestamp to make filename unique
            filename = f"{datetime.now().strftime('%Y%m%d%H%M%S')}_{filename}"
            
            # Save the file
            file.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))
            
            # Save file info to database
            caption = request.form.get('caption', '')
            db = get_db()
            db.execute(
                'INSERT INTO images (filename, caption, user_id) VALUES (?, ?, ?)',
                (filename, caption, current_user.id)
            )
            db.commit()
            
            flash('Image uploaded successfully!')
            return redirect(url_for('index'))
            
    return render_template('upload.html')

@app.route('/users')
def users():
    db = get_db()
    try:
        users = db.execute('SELECT id, name, profile_pic FROM users ORDER BY name').fetchall()
        return render_template('users.html', users=users)
    except sqlite3.OperationalError as e:
        # Handle case where table doesn't exist yet
        flash(f"Database error: {str(e)}. Try initializing the database.")
        return redirect(url_for('index'))

@app.route('/user/<int:user_id>')
def user_profile(user_id):
    db = get_db()
    user = db.execute('SELECT id, name, email, profile_pic FROM users WHERE id = ?', (user_id,)).fetchone()
    if user is None:
        flash('User not found')
        return redirect(url_for('index'))
    
    images = db.execute('''
        SELECT id, filename, caption, upload_date
        FROM images
        WHERE user_id = ?
        ORDER BY upload_date DESC
    ''', (user_id,)).fetchall()
    
    return render_template('user_profile.html', user=user, images=images)

@app.route('/')
def index():
    db = get_db()
    try:
        images = db.execute('''
            SELECT i.id, i.filename, i.caption, i.upload_date, i.user_id, u.name as username
            FROM images i JOIN users u ON i.user_id = u.id
            ORDER BY i.upload_date DESC
        ''').fetchall()
    except sqlite3.Error:
        # Handle case where tables don't exist yet
        images = []
    return render_template('index.html', images=images)

# Simple error handler
@app.errorhandler(404)
def page_not_found(e):
    return render_template('404.html'), 404

@app.errorhandler(500)
def internal_server_error(e):
    return render_template('500.html'), 500

# Health check endpoint
@app.route('/health')
def health_check():
    return "OK", 200

@app.route('/oauth-debug')
def oauth_debug():
    if not app.debug:
        return "Debug information not available in production", 403
        
    client_id = app.config.get('GOOGLE_CLIENT_ID', 'Not set')
    # Only show first few characters of client secret for security
    client_secret = app.config.get('GOOGLE_CLIENT_SECRET', 'Not set')
    if client_secret and len(client_secret) > 8:
        client_secret = client_secret[:4] + '...' + client_secret[-4:]
    
    debug_info = {
        'client_id': client_id,
        'client_secret_preview': client_secret,
        'redirect_uri': url_for('authorize', _external=True),
        'server_metadata_url': 'https://accounts.google.com/.well-known/openid-configuration',
        'userinfo_endpoint': 'https://www.googleapis.com/oauth2/v3/userinfo'
    }
    
    return render_template('debug.html', debug_info=debug_info) if app.debug else "Debug information not available in production", 403

# TEMPORARY: Development-only direct login (REMOVE IN PRODUCTION)
@app.route('/dev-login')
def dev_login():
    if not app.debug:
        return "Not available in production", 403
        
    try:
        # Initialize database if needed
        db = get_db()
        try:
            db.execute('SELECT 1 FROM users LIMIT 1')
        except sqlite3.OperationalError:
            # Table doesn't exist, initialize database
            init_db()
            flash("Database initialized")
            
        # Create or get test user
        email = "test@example.com"
        user = db.execute('SELECT * FROM users WHERE email = ?', (email,)).fetchone()
        
        if user is None:
            db.execute(
                'INSERT INTO users (email, name, profile_pic) VALUES (?, ?, ?)',
                (email, "Test User", None)
            )
            db.commit()
            user = db.execute('SELECT * FROM users WHERE email = ?', (email,)).fetchone()
        
        # Login user
        user_obj = User(user['id'], user['email'], user['name'], user['profile_pic'])
        login_user(user_obj)
        
        flash('Development login successful!')
        return redirect(url_for('index'))
    except Exception as e:
        return f"Error: {str(e)}", 500

if __name__ == '__main__':
    app.run(debug=True)



















