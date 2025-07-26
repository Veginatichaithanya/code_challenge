from datetime import datetime
from app import db
from flask_login import UserMixin
from sqlalchemy import UniqueConstraint

# User model for authentication and progress tracking
class User(UserMixin, db.Model):
    __tablename__ = 'users'
    id = db.Column(db.String, primary_key=True)
    email = db.Column(db.String, unique=True, nullable=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    first_name = db.Column(db.String, nullable=True)
    last_name = db.Column(db.String, nullable=True)
    profile_image_url = db.Column(db.String, nullable=True)
    total_score = db.Column(db.Integer, default=0)
    challenges_completed = db.Column(db.Integer, default=0)
    current_streak = db.Column(db.Integer, default=0)
    best_streak = db.Column(db.Integer, default=0)
    last_activity = db.Column(db.DateTime, default=datetime.now)
    created_at = db.Column(db.DateTime, default=datetime.now)
    updated_at = db.Column(db.DateTime, default=datetime.now, onupdate=datetime.now)

    # Relationships
    progress_entries = db.relationship('ChallengeProgress', backref='user', lazy=True, cascade='all, delete-orphan')
    achievements = db.relationship('UserAchievement', backref='user', lazy=True, cascade='all, delete-orphan')

# Challenge progress tracking
class ChallengeProgress(db.Model):
    __tablename__ = 'challenge_progress'
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.String, db.ForeignKey('users.id'), nullable=False)
    challenge_id = db.Column(db.String(50), nullable=False)
    challenge_name = db.Column(db.String(200), nullable=False)
    status = db.Column(db.String(20), default='not_started')  # not_started, in_progress, completed
    score = db.Column(db.Integer, default=0)
    max_score = db.Column(db.Integer, default=100)
    attempts = db.Column(db.Integer, default=0)
    test_cases_passed = db.Column(db.Integer, default=0)
    total_test_cases = db.Column(db.Integer, default=0)
    completion_time = db.Column(db.Integer, nullable=True)  # Time in seconds
    first_attempt_date = db.Column(db.DateTime, nullable=True)
    completion_date = db.Column(db.DateTime, nullable=True)
    last_attempt_date = db.Column(db.DateTime, default=datetime.now)
    
    __table_args__ = (UniqueConstraint('user_id', 'challenge_id', name='uq_user_challenge'),)

# Achievement definitions
class Achievement(db.Model):
    __tablename__ = 'achievements'
    id = db.Column(db.String(50), primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    description = db.Column(db.Text, nullable=False)
    icon = db.Column(db.String(50), default='fas fa-trophy')
    badge_color = db.Column(db.String(20), default='gold')
    category = db.Column(db.String(30), nullable=False)
    difficulty = db.Column(db.String(20), default='medium')
    points = db.Column(db.Integer, default=100)
    requirement_type = db.Column(db.String(30), nullable=False)  # challenges_completed, streak, score, etc.
    requirement_value = db.Column(db.Integer, nullable=False)
    is_active = db.Column(db.Boolean, default=True)
    created_at = db.Column(db.DateTime, default=datetime.now)

# User achievement tracking
class UserAchievement(db.Model):
    __tablename__ = 'user_achievements'
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.String, db.ForeignKey('users.id'), nullable=False)
    achievement_id = db.Column(db.String(50), db.ForeignKey('achievements.id'), nullable=False)
    earned_date = db.Column(db.DateTime, default=datetime.now)
    progress_value = db.Column(db.Integer, default=0)  # Current progress towards achievement
    
    # Relationships
    achievement = db.relationship('Achievement', backref='user_achievements')
    
    __table_args__ = (UniqueConstraint('user_id', 'achievement_id', name='uq_user_achievement'),)

# Code submission history
class CodeSubmission(db.Model):
    __tablename__ = 'code_submissions'
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.String, db.ForeignKey('users.id'), nullable=False)
    challenge_id = db.Column(db.String(50), nullable=False)
    code = db.Column(db.Text, nullable=False)
    test_results = db.Column(db.JSON, nullable=True)
    score = db.Column(db.Integer, default=0)
    execution_time = db.Column(db.Float, nullable=True)
    status = db.Column(db.String(20), default='submitted')  # submitted, passed, failed
    submitted_at = db.Column(db.DateTime, default=datetime.now)
    
    # Foreign key relationship
    user = db.relationship('User', backref='submissions')