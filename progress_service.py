from datetime import datetime, timedelta
from models import User, ChallengeProgress, Achievement, UserAchievement, CodeSubmission
from app import db
from flask_login import current_user
import json

class ProgressService:
    """Service for handling user progress and achievements"""
    
    @staticmethod
    def update_challenge_progress(user_id, challenge_id, challenge_name, test_results, code):
        """Update user progress for a specific challenge"""
        try:
            # Get or create progress entry
            progress = ChallengeProgress.query.filter_by(
                user_id=user_id, 
                challenge_id=challenge_id
            ).first()
            
            if not progress:
                progress = ChallengeProgress(
                    user_id=user_id,
                    challenge_id=challenge_id,
                    challenge_name=challenge_name,
                    first_attempt_date=datetime.now()
                )
                db.session.add(progress)
            
            # Update progress based on test results
            if test_results and test_results.get('success'):
                results = test_results.get('results', [])
                total_tests = len(results)
                passed_tests = sum(1 for r in results if r.get('passed', False))
                
                progress.test_cases_passed = max(progress.test_cases_passed, passed_tests)
                progress.total_test_cases = total_tests
                progress.attempts += 1
                progress.last_attempt_date = datetime.now()
                
                # Calculate score (percentage based)
                if total_tests > 0:
                    score = int((passed_tests / total_tests) * 100)
                    progress.score = max(progress.score, score)
                    
                    # Mark as completed if all tests pass
                    if passed_tests == total_tests and progress.status != 'completed':
                        progress.status = 'completed'
                        progress.completion_date = datetime.now()
                        ProgressService._update_user_stats(user_id)
                        ProgressService._check_achievements(user_id)
                    elif progress.status == 'not_started':
                        progress.status = 'in_progress'
            
            # Save code submission
            submission = CodeSubmission(
                user_id=user_id,
                challenge_id=challenge_id,
                code=code,
                test_results=test_results,
                score=progress.score,
                status='passed' if progress.status == 'completed' else 'submitted'
            )
            db.session.add(submission)
            
            db.session.commit()
            return progress
            
        except Exception as e:
            db.session.rollback()
            print(f"Error updating progress: {e}")
            return None
    
    @staticmethod
    def _update_user_stats(user_id):
        """Update user's overall statistics"""
        try:
            user = User.query.get(user_id)
            if not user:
                return
            
            # Count completed challenges
            completed_count = ChallengeProgress.query.filter_by(
                user_id=user_id, 
                status='completed'
            ).count()
            
            # Calculate total score
            total_score = db.session.query(db.func.sum(ChallengeProgress.score)).filter_by(
                user_id=user_id,
                status='completed'
            ).scalar() or 0
            
            # Update streak
            ProgressService._update_streak(user)
            
            user.challenges_completed = completed_count
            user.total_score = total_score
            user.last_activity = datetime.now()
            
            db.session.commit()
            
        except Exception as e:
            db.session.rollback()
            print(f"Error updating user stats: {e}")
    
    @staticmethod
    def _update_streak(user):
        """Update user's current and best streak"""
        try:
            # Get recent completion dates
            recent_completions = db.session.query(ChallengeProgress.completion_date).filter_by(
                user_id=user.id,
                status='completed'
            ).filter(
                ChallengeProgress.completion_date.isnot(None)
            ).order_by(ChallengeProgress.completion_date.desc()).all()
            
            if not recent_completions:
                user.current_streak = 0
                return
            
            # Calculate current streak
            current_streak = 0
            today = datetime.now().date()
            
            completion_dates = [comp[0].date() for comp in recent_completions]
            unique_dates = sorted(set(completion_dates), reverse=True)
            
            for i, date in enumerate(unique_dates):
                if i == 0:
                    # First date should be today or yesterday
                    if date == today or date == today - timedelta(days=1):
                        current_streak = 1
                    else:
                        break
                else:
                    # Check if consecutive
                    prev_date = unique_dates[i-1]
                    if (prev_date - date).days == 1:
                        current_streak += 1
                    else:
                        break
            
            user.current_streak = current_streak
            user.best_streak = max(user.best_streak, current_streak)
            
        except Exception as e:
            print(f"Error updating streak: {e}")
    
    @staticmethod
    def _check_achievements(user_id):
        """Check and award new achievements"""
        try:
            user = User.query.get(user_id)
            if not user:
                return
            
            achievements = Achievement.query.filter_by(is_active=True).all()
            
            for achievement in achievements:
                # Check if user already has this achievement
                existing = UserAchievement.query.filter_by(
                    user_id=user_id,
                    achievement_id=achievement.id
                ).first()
                
                if existing:
                    continue
                
                # Check if user meets requirements
                if ProgressService._meets_achievement_requirements(user, achievement):
                    # Award achievement
                    user_achievement = UserAchievement(
                        user_id=user_id,
                        achievement_id=achievement.id,
                        progress_value=achievement.requirement_value
                    )
                    db.session.add(user_achievement)
            
            db.session.commit()
            
        except Exception as e:
            db.session.rollback()
            print(f"Error checking achievements: {e}")
    
    @staticmethod
    def _meets_achievement_requirements(user, achievement):
        """Check if user meets the requirements for an achievement"""
        req_type = achievement.requirement_type
        req_value = achievement.requirement_value
        
        if req_type == 'challenges_completed':
            return user.challenges_completed >= req_value
        elif req_type == 'streak':
            return user.current_streak >= req_value or user.best_streak >= req_value
        elif req_type == 'score':
            return user.total_score >= req_value
        elif req_type == 'perfect_score':
            # Check if user has any challenge with 100% score
            perfect_score = ChallengeProgress.query.filter_by(
                user_id=user.id,
                score=100
            ).first()
            return perfect_score is not None
        
        return False
    
    @staticmethod
    def get_user_progress_summary(user_id):
        """Get comprehensive progress summary for user"""
        try:
            user = User.query.get(user_id)
            if not user:
                return None
            
            # Get challenge progress
            progress_entries = ChallengeProgress.query.filter_by(user_id=user_id).all()
            
            # Get user achievements
            user_achievements = db.session.query(UserAchievement, Achievement).join(
                Achievement, UserAchievement.achievement_id == Achievement.id
            ).filter(UserAchievement.user_id == user_id).all()
            
            # Calculate completion percentage
            total_challenges = 14  # Total number of challenges
            completion_percentage = (user.challenges_completed / total_challenges) * 100
            
            return {
                'user': {
                    'username': user.username,
                    'total_score': user.total_score,
                    'challenges_completed': user.challenges_completed,
                    'current_streak': user.current_streak,
                    'best_streak': user.best_streak,
                    'completion_percentage': round(completion_percentage, 1)
                },
                'challenges': [
                    {
                        'challenge_id': p.challenge_id,
                        'challenge_name': p.challenge_name,
                        'status': p.status,
                        'score': p.score,
                        'attempts': p.attempts,
                        'test_cases_passed': p.test_cases_passed,
                        'total_test_cases': p.total_test_cases,
                        'completion_date': p.completion_date.isoformat() if p.completion_date else None
                    } for p in progress_entries
                ],
                'achievements': [
                    {
                        'id': achievement.id,
                        'name': achievement.name,
                        'description': achievement.description,
                        'icon': achievement.icon,
                        'badge_color': achievement.badge_color,
                        'category': achievement.category,
                        'points': achievement.points,
                        'earned_date': user_achievement.earned_date.isoformat()
                    } for user_achievement, achievement in user_achievements
                ]
            }
            
        except Exception as e:
            print(f"Error getting progress summary: {e}")
            return None
    
    @staticmethod
    def get_available_achievements(user_id):
        """Get all achievements with progress indicators"""
        try:
            user = User.query.get(user_id)
            if not user:
                return []
            
            achievements = Achievement.query.filter_by(is_active=True).all()
            user_achievements = {ua.achievement_id for ua in UserAchievement.query.filter_by(user_id=user_id).all()}
            
            result = []
            for achievement in achievements:
                is_earned = achievement.id in user_achievements
                
                # Calculate progress
                progress = 0
                if not is_earned:
                    req_type = achievement.requirement_type
                    req_value = achievement.requirement_value
                    
                    if req_type == 'challenges_completed':
                        progress = min(100, (user.challenges_completed / req_value) * 100)
                    elif req_type == 'streak':
                        current_progress = max(user.current_streak, user.best_streak)
                        progress = min(100, (current_progress / req_value) * 100)
                    elif req_type == 'score':
                        progress = min(100, (user.total_score / req_value) * 100)
                    elif req_type == 'perfect_score':
                        perfect_count = ChallengeProgress.query.filter_by(
                            user_id=user_id, score=100
                        ).count()
                        progress = 100 if perfect_count > 0 else 0
                else:
                    progress = 100
                
                result.append({
                    'id': achievement.id,
                    'name': achievement.name,
                    'description': achievement.description,
                    'icon': achievement.icon,
                    'badge_color': achievement.badge_color,
                    'category': achievement.category,
                    'difficulty': achievement.difficulty,
                    'points': achievement.points,
                    'is_earned': is_earned,
                    'progress': round(progress, 1)
                })
            
            return result
            
        except Exception as e:
            print(f"Error getting available achievements: {e}")
            return []