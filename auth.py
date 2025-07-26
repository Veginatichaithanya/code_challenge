from flask import Blueprint, render_template, request, redirect, url_for, flash, session
from flask_login import LoginManager, login_user, logout_user, login_required, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from models import User, Achievement
from app import db
import uuid

# Initialize Flask-Login
login_manager = LoginManager()

def init_login_manager(app):
    login_manager.init_app(app)
    login_manager.login_view = 'auth.login'
    login_manager.login_message = 'Please log in to access this page.'
    login_manager.login_message_category = 'info'

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(user_id)

# Create auth blueprint
auth_bp = Blueprint('auth', __name__, url_prefix='/auth')

@auth_bp.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form.get('username')
        email = request.form.get('email')
        password = request.form.get('password')
        confirm_password = request.form.get('confirm_password')
        
        # Validation
        if not username or not email or not password:
            flash('All fields are required.', 'error')
            return render_template('auth/register.html')
        
        if password != confirm_password:
            flash('Passwords do not match.', 'error')
            return render_template('auth/register.html')
        
        # Check if user already exists
        if User.query.filter_by(username=username).first():
            flash('Username already exists.', 'error')
            return render_template('auth/register.html')
        
        if User.query.filter_by(email=email).first():
            flash('Email already registered.', 'error')
            return render_template('auth/register.html')
        
        # Create new user
        user = User(
            id=str(uuid.uuid4()),
            username=username,
            email=email
        )
        
        db.session.add(user)
        db.session.commit()
        
        # Initialize default achievements
        init_default_achievements()
        
        login_user(user)
        flash('Registration successful! Welcome to the Cybersecurity Challenge Platform.', 'success')
        return redirect(url_for('dashboard'))
    
    return render_template('auth/register.html')

@auth_bp.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        
        if not username:
            flash('Username is required.', 'error')
            return render_template('auth/login.html')
        
        user = User.query.filter_by(username=username).first()
        
        if user:
            login_user(user)
            flash('Login successful!', 'success')
            next_page = request.args.get('next')
            return redirect(next_page) if next_page else redirect(url_for('dashboard'))
        else:
            flash('Invalid username. Please try again.', 'error')
    
    return render_template('auth/login.html')

@auth_bp.route('/logout')
@login_required
def logout():
    logout_user()
    flash('You have been logged out.', 'info')
    return redirect(url_for('index'))

def init_default_achievements():
    """Initialize default achievements if they don't exist"""
    achievements_data = [
        {
            'id': 'first_steps',
            'name': 'First Steps',
            'description': 'Complete your first challenge',
            'icon': 'fas fa-baby',
            'badge_color': 'bronze',
            'category': 'beginner',
            'difficulty': 'easy',
            'points': 50,
            'requirement_type': 'challenges_completed',
            'requirement_value': 1
        },
        {
            'id': 'crypto_novice',
            'name': 'Crypto Novice',
            'description': 'Complete 3 cryptography challenges',
            'icon': 'fas fa-key',
            'badge_color': 'silver',
            'category': 'cryptography',
            'difficulty': 'medium',
            'points': 150,
            'requirement_type': 'challenges_completed',
            'requirement_value': 3
        },
        {
            'id': 'security_expert',
            'name': 'Security Expert',
            'description': 'Complete 7 challenges',
            'icon': 'fas fa-shield-alt',
            'badge_color': 'gold',
            'category': 'general',
            'difficulty': 'hard',
            'points': 300,
            'requirement_type': 'challenges_completed',
            'requirement_value': 7
        },
        {
            'id': 'perfectionist',
            'name': 'Perfectionist',
            'description': 'Complete a challenge with 100% test cases passed',
            'icon': 'fas fa-star',
            'badge_color': 'platinum',
            'category': 'excellence',
            'difficulty': 'medium',
            'points': 200,
            'requirement_type': 'perfect_score',
            'requirement_value': 100
        },
        {
            'id': 'streak_master',
            'name': 'Streak Master',
            'description': 'Complete challenges for 5 consecutive days',
            'icon': 'fas fa-fire',
            'badge_color': 'red',
            'category': 'consistency',
            'difficulty': 'hard',
            'points': 250,
            'requirement_type': 'streak',
            'requirement_value': 5
        },
        {
            'id': 'champion',
            'name': 'Cybersecurity Champion',
            'description': 'Complete all 14 challenges',
            'icon': 'fas fa-crown',
            'badge_color': 'diamond',
            'category': 'mastery',
            'difficulty': 'legendary',
            'points': 500,
            'requirement_type': 'challenges_completed',
            'requirement_value': 14
        }
    ]
    
    for achievement_data in achievements_data:
        if not Achievement.query.get(achievement_data['id']):
            achievement = Achievement(**achievement_data)
            db.session.add(achievement)
    
    try:
        db.session.commit()
    except Exception as e:
        db.session.rollback()
        print(f"Error initializing achievements: {e}")