from flask import Flask, render_template, request, redirect, url_for, flash
import os
import openai
from dotenv import load_dotenv
from datetime import date, datetime, timedelta
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, BooleanField, SubmitField
from wtforms.validators import DataRequired, Length, EqualTo, ValidationError

load_dotenv() # Load environment variables from .env file

app = Flask(__name__)

# --- Configuration ---
# Get the absolute path of the directory where this script resides
basedir = os.path.abspath(os.path.dirname(__file__))

# SECRET_KEY is needed for session management and flash messages
# IMPORTANT: Generate a strong, random key and store it in .env for production!
secret_key = os.getenv('SECRET_KEY')
if not secret_key:
    raise RuntimeError("SECRET_KEY environment variable must be set for production")
app.config['SECRET_KEY'] = secret_key
# Use SQLite in /tmp for demo deployments (Vercel readonly FS) by default
app.config['SQLALCHEMY_DATABASE_URI'] = os.getenv('DATABASE_URL',
    'sqlite:////tmp/promptski.db')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['PROMPTS_PER_DAY'] = 5 # Max prompts per user per day
# -------------------

# --- Extensions Initialization ---
# Enable SQLite file in /tmp with check_same_thread for demo
db = SQLAlchemy(app, engine_options={"connect_args": {"check_same_thread": False}})
login_manager = LoginManager(app)
login_manager.login_view = 'login' # Redirect to 'login' view if user tries to access protected page
# -------------------------------

# Load OpenAI API key from environment variable
openai.api_key = os.getenv("OPENAI_API_KEY")
if not openai.api_key:
    raise ValueError("OPENAI_API_KEY environment variable not set.")

# --- Configuration ---
SYSTEM_PROMPT = """You are a prompt consultant named Promptski. Improve the user's prompt to make it more effective for a language model, based on clarity, specificity, and intended task.
 
**IMPORTANT:** Your response MUST follow this exact format:
1.  The improved prompt.
2.  The separator '---EXPLANATION---' on its own line.
3.  A short explanation of what you changed and why.

Example:
<Improved Prompt Content>
---EXPLANATION---
<Explanation Content>"""
MODEL_NAME = 'gpt-4.1-nano-2025-04-14' # As specified by the user
# ---------------------

@app.route('/', methods=['GET', 'POST'])
@login_required
def index():
    polished_prompt = ""
    explanation = ""
    error_message = None # Initialize error message
    raw_prompt_input = "" # Initialize to empty for GET requests
    selected_use_case = "general" # Default use case
    if request.method == 'POST':
        now = datetime.utcnow()
        limit_window_start = now - timedelta(days=1) # Check prompts in the last 24 hours
        prompt_count_today = PromptHistory.query.filter(
            PromptHistory.user_id == current_user.id,
            PromptHistory.timestamp >= limit_window_start
        ).count()

        if prompt_count_today >= app.config['PROMPTS_PER_DAY']:
            flash(f"You have reached your limit of {app.config['PROMPTS_PER_DAY']} prompts per day.", 'warning')
            # Return the template render directly, preserving user input but not making API call
            return render_template('index.html',
                                   polished_prompt="",
                                   explanation="",
                                   raw_prompt=request.form.get('raw_prompt', ''), # Preserve input
                                   selected_use_case=request.form.get('use_case', 'general'), # Preserve selection
                                   error=None) # No direct error, flash is used
        else:
            raw_prompt = request.form['raw_prompt']
            raw_prompt_input = raw_prompt # Store for passing back to template
            selected_use_case = request.form.get('use_case', 'general') # Get selected use case

            try:
                response = openai.chat.completions.create(
                    model=MODEL_NAME,
                    messages=[
                        {"role": "system", "content": SYSTEM_PROMPT},
                        {"role": "user", "content": raw_prompt} # Send the raw prompt directly
                    ],
                    temperature=0.7, # Adjust temperature as needed
                    max_tokens=500 # Adjust max tokens as needed
                )
                full_response = response.choices[0].message.content
                print(f"--- OpenAI Raw Response ---\n{full_response}\n---------------------------") # Log the raw response

                # Split the response into polished prompt and explanation
                parts = full_response.split('---EXPLANATION---', 1)
                if len(parts) == 2:
                    polished_prompt = parts[0].strip()
                    explanation = parts[1].strip()
                else:
                    polished_prompt = full_response.strip()
                    explanation = "(Promptski didn't provide a separate explanation this time.)"

                # Save successful prompt interaction
                history_entry = PromptHistory(
                    user_id=current_user.id,
                    raw_prompt=raw_prompt,
                    use_case=selected_use_case,
                    polished_prompt=polished_prompt,
                    explanation=explanation
                )
                db.session.add(history_entry)
                db.session.commit()

            except Exception as e:
                api_error_message = str(e)
                print(f"Error calling OpenAI: {api_error_message}")
                flash(f"API Error: {api_error_message}", 'danger') # Use flash for API errors too
                explanation = "" # Clear explanation on error
                polished_prompt = "" # Clear polished prompt on error
                # Save failed prompt interaction
                history_entry = PromptHistory(
                    user_id=current_user.id,
                    raw_prompt=raw_prompt,
                    use_case=selected_use_case,
                    api_error=api_error_message
                )
                db.session.add(history_entry)
                db.session.commit()

    return render_template('index.html',
                           polished_prompt=polished_prompt,
                           explanation=explanation,
                           raw_prompt=raw_prompt_input,
                           selected_use_case=selected_use_case,
                           error=None) # Errors handled by flash messages

# --- User Model ---
class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password_hash = db.Column(db.String(128), nullable=False)

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

    def __repr__(self):
        return f'<User {self.username}>'
# ------------------

# --- Prompt History Model ---
class PromptHistory(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    timestamp = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    raw_prompt = db.Column(db.Text, nullable=False)
    use_case = db.Column(db.String(50), nullable=True)
    polished_prompt = db.Column(db.Text, nullable=True)
    explanation = db.Column(db.Text, nullable=True)
    api_error = db.Column(db.Text, nullable=True) # Store API errors if any

    user = db.relationship('User', backref=db.backref('prompts', lazy=True))

    def __repr__(self):
        return f'<PromptHistory {self.id} by User {self.user_id}>'
# --------------------------

# Create database tables if they don't exist (for /tmp SQLite on Vercel)
with app.app_context():
    db.create_all()

# --- Flask-Login Setup ---
@login_manager.user_loader
def load_user(user_id):
    return db.session.get(User, int(user_id)) # Use db.session.get for SQLAlchemy >= 2.0
# ------------------------

# --- Prompt History Route ---
@app.route('/history')
@login_required
def history():
    # Query prompt history for the current user, order by most recent first
    user_history = PromptHistory.query.filter_by(user_id=current_user.id)\
                                      .order_by(PromptHistory.timestamp.desc())\
                                      .all()
    return render_template('history.html', title='Prompt History', history=user_history)
# --------------------------

# --- Forms ---
class RegistrationForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired(), Length(min=4, max=80)])
    password = PasswordField('Password', validators=[DataRequired(), Length(min=6)])
    confirm_password = PasswordField('Confirm Password', validators=[DataRequired(), EqualTo('password')])
    submit = SubmitField('Register')

    # Custom validator to check if username already exists
    def validate_username(self, username):
        user = User.query.filter_by(username=username.data).first()
        if user:
            raise ValidationError('That username is already taken. Please choose a different one.')

class LoginForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired()])
    password = PasswordField('Password', validators=[DataRequired()])
    remember = BooleanField('Remember Me')
    submit = SubmitField('Login')
# ----------

# --- Routes ---
# (Keep the existing index route)
# ... @app.route('/', methods=['GET', 'POST']) ...

@app.route('/register', methods=['GET', 'POST'])
def register():
    if current_user.is_authenticated: # If already logged in, redirect to home
        return redirect(url_for('index'))
    form = RegistrationForm()
    if form.validate_on_submit():
        hashed_password = generate_password_hash(form.password.data)
        user = User(username=form.username.data, password_hash=hashed_password)
        db.session.add(user)
        db.session.commit()
        flash('Your account has been created! You can now log in.', 'success')
        return redirect(url_for('login'))
    return render_template('register.html', title='Register', form=form)

@app.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('index'))
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(username=form.username.data).first()
        if user and user.check_password(form.password.data):
            login_user(user, remember=form.remember.data)
            flash('Login successful!', 'success')
            # Redirect to the page the user was trying to access, or index if none
            next_page = request.args.get('next')
            return redirect(next_page) if next_page else redirect(url_for('index'))
        else:
            flash('Login Unsuccessful. Please check username and password.', 'danger')
    return render_template('login.html', title='Login', form=form)

@app.route('/logout')
@login_required # User must be logged in to log out
def logout():
    logout_user()
    flash('You have been logged out.', 'info')
    return redirect(url_for('login'))

# TODO: Update templates (base.html, navbar, flash messages)
# TODO: Refactor rate limiting for logged-in users
# ----------

# --- Context Processors ---
@app.context_processor
def inject_now():
    """Inject current year into templates for footer."""
    return {'now': datetime.utcnow()}

# --- CLI Command for DB Init ---
@app.cli.command('init-db')
def init_db_command():
    """Clear existing data and create new tables."""
    # Consider uncommenting drop_all() for a truly clean start if needed
    # db.drop_all() 
    db.create_all()
    print('Initialized the database.')
# -----------------------------
