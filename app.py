# app.py - Main Flask Application for TrainTrack

import os
import json # Import json for handling question options
from flask import Flask, render_template, redirect, url_for, flash, request, abort
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime, date, timedelta # Import date and timedelta for date comparisons
from functools import wraps # Import wraps for decorators
from sqlalchemy import inspect # Import inspect for database schema introspection
from sqlalchemy.orm import relationship # Import relationship for many-to-many

# Initialize Flask app
app = Flask(__name__)

# Configuration
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', 'a_very_secret_key_for_dev') # Use environment variable for production
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///traintrack.db' # SQLite database
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

# Initialize SQLAlchemy
db = SQLAlchemy(app)

# Initialize Flask-Login
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login' # Redirect to login page if not authenticated
login_manager.login_message_category = 'info'

# Define passcodes for admin and support roles (use environment variables in production)
ADMIN_PASSCODE = os.environ.get('ADMIN_PASSCODE', 'admincode') # Default for dev
SUPPORT_PASSCODE = os.environ.get('SUPPORT_PASSCODE', 'supportcode') # Default for dev

# Define predefined domains
PREDEFINED_DOMAINS = ['Data Collection', 'Data Cleaning', 'Data Engineering', 'Compliance', 'Marketing', 'Sales', 'Human Resources', 'Finance']

# --- Jinja2 Custom Filters ---
@app.template_filter('from_json')
def from_json_filter(value):
    """Jinja2 filter to parse a JSON string into a Python object."""
    if value:
        return json.loads(value)
    return None

# --- Role-based Access Control Decorators ---
def role_required(role):
    """
    Custom decorator to restrict access to routes based on user role.
    """
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            if not current_user.is_authenticated or current_user.role != role:
                flash('You do not have permission to access this page.', 'danger')
                return redirect(url_for('dashboard')) # Redirect to dashboard or login
            return f(*args, **kwargs)
        return decorated_function
    return decorator

# Modified to allow multiple roles
def roles_required(*roles):
    """
    Custom decorator to restrict access to routes based on multiple user roles.
    """
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            if not current_user.is_authenticated or current_user.role not in roles:
                flash('You do not have permission to access this page.', 'danger')
                return redirect(url_for('dashboard'))
            return f(*args, **kwargs)
        return decorated_function
    return decorator

def admin_required(f):
    """Decorator to restrict access to admin users only."""
    return role_required('admin')(f)

def support_required(f):
    """Decorator to restrict access to support users only."""
    return role_required('support')(f)

def trainee_required(f):
    """Decorator to restrict access to trainee users only."""
    return role_required('trainee')(f)


# --- Database Models ---

# Association table for LearningPath and Course (Many-to-Many)
learning_path_courses = db.Table('learning_path_courses',
    db.Column('learning_path_id', db.Integer, db.ForeignKey('learning_path.id'), primary_key=True),
    db.Column('course_id', db.Integer, db.ForeignKey('course.id'), primary_key=True)
)

class User(UserMixin, db.Model):
    """
    User model representing a user in the TrainTrack application.
    Includes fields for username, password hash, and role.
    """
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password_hash = db.Column(db.String(128), nullable=False)
    # Roles: 'admin', 'support', 'trainee'
    role = db.Column(db.String(20), nullable=False, default='trainee')
    domain = db.Column(db.String(50), nullable=True) # New field for trainee/admin domain

    # Relationships
    # User can be assigned many assignments (as trainee)
    assignments_as_trainee = db.relationship('Assignment', foreign_keys='Assignment.trainee_id', backref='trainee', lazy=True)
    # User (admin) can create many courses
    created_courses = db.relationship('Course', foreign_keys='Course.created_by_id', backref='creator', lazy=True)
    # User (admin) can create many assessments
    created_assessments = db.relationship('Assessment', foreign_keys='Assessment.created_by_id', backref='assessor_creator', lazy=True)
    # User (admin) can create many learning paths
    created_learning_paths = db.relationship('LearningPath', foreign_keys='LearningPath.created_by_id', backref='path_creator', lazy=True)
    # User (admin) can assign many assignments
    assigned_assignments = db.relationship('Assignment', foreign_keys='Assignment.assigned_by_id', backref='assigner', lazy=True)
    # User can receive many notifications
    notifications_received = db.relationship('Notification', foreign_keys='Notification.recipient_id', backref='recipient', lazy=True)
    # User can send many notifications
    notifications_sent = db.relationship('Notification', foreign_keys='Notification.sender_id', backref='sender', lazy=True)
    # User can grade many submissions
    graded_submissions = db.relationship('Submission', foreign_keys='Submission.graded_by_id', backref='grader', lazy=True)


    def set_password(self, password):
        """Hashes the given password and stores it."""
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        """Checks if the given password matches the stored hash."""
        return check_password_hash(self.password_hash, password)

    def __repr__(self):
        return f'<User {self.username} ({self.role})>'

class Course(db.Model):
    """
    Course model representing a training course.
    Can contain multiple assessments.
    """
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(120), nullable=False)
    description = db.Column(db.Text, nullable=True)
    course_link = db.Column(db.String(255), nullable=True) # New field for external link
    domain = db.Column(db.String(50), nullable=True) # Changed from 'category' to 'domain'
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    created_by_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False) # Admin who created it

    # Relationships
    assessments = db.relationship('Assessment', backref='course', lazy=True)
    assignments = db.relationship('Assignment', backref='course', lazy=True)
    modules = db.relationship('Module', backref='course', lazy=True) # New relationship for modules
    
    # Many-to-many relationship with LearningPath
    learning_paths = relationship('LearningPath', secondary=learning_path_courses, back_populates='courses')

    def __repr__(self):
        return f'<Course {self.name}>'

class Module(db.Model):
    """
    Module model representing a single module within a course.
    """
    id = db.Column(db.Integer, primary_key=True)
    course_id = db.Column(db.Integer, db.ForeignKey('course.id'), nullable=False)
    name = db.Column(db.String(120), nullable=False)
    description = db.Column(db.Text, nullable=True)
    module_link = db.Column(db.String(255), nullable=True) # Link to module content
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    created_by_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)

    # Relationships
    module_completions = db.relationship('TraineeModuleCompletion', backref='module', lazy=True)

    def __repr__(self):
        return f'<Module {self.name} (Course: {self.course_id})>'

class TraineeModuleCompletion(db.Model):
    """
    Model to track individual module completion for a trainee's course assignment.
    """
    id = db.Column(db.Integer, primary_key=True)
    assignment_id = db.Column(db.Integer, db.ForeignKey('assignment.id'), nullable=False)
    module_id = db.Column(db.Integer, db.ForeignKey('module.id'), nullable=False)
    completed_at = db.Column(db.DateTime, nullable=True) # Null if not completed

    __table_args__ = (db.UniqueConstraint('assignment_id', 'module_id', name='_assignment_module_uc'),)

    def __repr__(self):
        return f'<TraineeModuleCompletion Assignment:{self.assignment_id} Module:{self.module_id}>'


class Assessment(db.Model):
    """
    Assessment model representing a test or quiz.
    Can be part of a course or standalone.
    """
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(120), nullable=False)
    description = db.Column(db.Text, nullable=True)
    type = db.Column(db.String(50), nullable=False) # e.g., 'multiple_choice', 'open_ended'
    course_id = db.Column(db.Integer, db.ForeignKey('course.id'), nullable=True) # Optional: if part of a course
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    created_by_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False) # Admin who created it

    # Relationships
    questions = db.relationship('Question', backref='assessment', lazy=True)
    assignments = db.relationship('Assignment', backref='assessment', lazy=True)

    def __repr__(self):
        return f'<Assessment {self.name}>'

class Question(db.Model):
    """
    Question model for assessments.
    """
    id = db.Column(db.Integer, primary_key=True)
    assessment_id = db.Column(db.Integer, db.ForeignKey('assessment.id'), nullable=False)
    text = db.Column(db.Text, nullable=False)
    type = db.Column(db.String(50), nullable=False) # e.g., 'multiple_choice', 'open_ended', 'true_false'
    options = db.Column(db.Text, nullable=True) # JSON string for multiple choice options
    correct_answer = db.Column(db.Text, nullable=True) # For MC, TF. For open_ended, might be empty or a hint.
    points = db.Column(db.Integer, nullable=False, default=1)

    # Relationships
    submissions = db.relationship('Submission', backref='question', lazy=True)

    def __repr__(self):
        return f'<Question {self.id} for Assessment {self.assessment_id}>'

class LearningPath(db.Model):
    """
    LearningPath model representing a collection of courses.
    """
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(120), nullable=False)
    description = db.Column(db.Text, nullable=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    created_by_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)

    # Many-to-many relationship with Course
    courses = relationship('Course', secondary=learning_path_courses, back_populates='learning_paths')
    assignments = db.relationship('Assignment', backref='learning_path', lazy=True)


    def __repr__(self):
        return f'<LearningPath {self.name}>'

class Assignment(db.Model):
    """
    Assignment model to link a trainee to a course, an assessment, or a learning path.
    """
    id = db.Column(db.Integer, primary_key=True)
    trainee_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    course_id = db.Column(db.Integer, db.ForeignKey('course.id'), nullable=True) # Either course_id or assessment_id or learning_path_id must be set
    assessment_id = db.Column(db.Integer, db.ForeignKey('assessment.id'), nullable=True) # Either course_id or assessment_id or learning_path_id must be set
    learning_path_id = db.Column(db.Integer, db.ForeignKey('learning_path.id'), nullable=True) # New field for learning path assignment
    assigned_by_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False) # Admin who assigned it
    assigned_at = db.Column(db.DateTime, default=datetime.utcnow)
    due_date = db.Column(db.DateTime, nullable=True)
    status = db.Column(db.String(50), default='assigned') # e.g., 'assigned', 'in_progress', 'completed', 'graded', 'submitted_for_grading'
    completion_date = db.Column(db.DateTime, nullable=True)
    score = db.Column(db.Float, nullable=True) # Overall score for the assignment
    completion_badge_link = db.Column(db.String(255), nullable=True) # New field for course completion badge

    # Relationships
    submissions = db.relationship('Submission', backref='assignment', lazy=True)
    module_completions = db.relationship('TraineeModuleCompletion', backref='assignment', lazy=True) # New relationship for module completions

    def __repr__(self):
        return f'<Assignment {self.id} for Trainee {self.trainee_id}>'

class Submission(db.Model):
    """
    Model to store a trainee's answer to a specific question within an assignment.
    """
    id = db.Column(db.Integer, primary_key=True)
    assignment_id = db.Column(db.Integer, db.ForeignKey('assignment.id'), nullable=False)
    question_id = db.Column(db.Integer, db.ForeignKey('question.id'), nullable=False)
    answer_text = db.Column(db.Text, nullable=True) # For open-ended or text answers
    submitted_at = db.Column(db.DateTime, default=datetime.utcnow)
    is_correct = db.Column(db.Boolean, nullable=True) # For auto-graded questions
    grade = db.Column(db.Float, nullable=True) # For manually graded open-ended questions
    graded_by_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=True) # Admin who graded it
    graded_at = db.Column(db.DateTime, nullable=True)

    def __repr__(self):
        return f'<Submission {self.id} for Assignment {self.assignment_id} Question {self.question_id}>'

class Notification(db.Model):
    """
    Notification model to store alerts for users.
    """
    id = db.Column(db.Integer, primary_key=True)
    recipient_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    sender_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=True) # Optional: who triggered the notification
    message = db.Column(db.Text, nullable=False)
    # Type can be 'assignment_assigned', 'course_completed', 'assessment_submitted', 'assessment_graded', etc.
    type = db.Column(db.String(50), nullable=False)
    # Optional: ID of the related object (e.g., assignment_id, course_id, assessment_id)
    related_id = db.Column(db.Integer, nullable=True)
    is_read = db.Column(db.Boolean, default=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    def __repr__(self):
        return f'<Notification {self.id} for User {self.recipient_id} ({self.type})>'


# --- Flask-Login User Loader ---

@login_manager.user_loader
def load_user(user_id):
    """
    Loads a user from the database given their user ID.
    Required by Flask-Login.
    """
    # Fix: Use db.session.get() instead of User.query.get()
    return db.session.get(User, int(user_id))

# --- Context Processor for Unread Notifications ---
@app.context_processor
def inject_unread_notifications_count():
    """
    Injects the count of unread notifications for the current user into all templates.
    """
    if current_user.is_authenticated:
        unread_count = Notification.query.filter_by(recipient_id=current_user.id, is_read=False).count()
        return dict(unread_notifications_count=unread_count)
    return dict(unread_notifications_count=0)


# --- Routes ---

@app.route('/')
def index():
    """Renders the homepage."""
    # Pass the current year to the template
    current_year = datetime.now().year
    return render_template('index.html', title='Welcome to TrainTrack', current_year=current_year)

@app.route('/login', methods=['GET', 'POST'])
def login():
    """Handles user login."""
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))

    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        user = User.query.filter_by(username=username).first()

        if user and user.check_password(password):
            login_user(user)
            flash('Logged in successfully!', 'success')
            next_page = request.args.get('next')
            return redirect(next_page or url_for('dashboard'))
        else:
            flash('Login Unsuccessful. Please check username and password', 'danger')
    # Pass the current year to the template
    current_year = datetime.now().year
    return render_template('login.html', title='Login', current_year=current_year)

@app.route('/logout')
@login_required # User must be logged in to log out
def logout():
    """Handles user logout."""
    logout_user()
    flash('You have been logged out.', 'info')
    return redirect(url_for('index'))

@app.route('/register', methods=['GET', 'POST'])
def register():
    """Handles user registration with role-based passcodes."""
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))

    current_year = datetime.now().year # Get current year for footer
    
    # Get all unique domains for the datalist, including predefined ones
    existing_domains = db.session.query(Course.domain).distinct().all()
    existing_domains = [d[0] for d in existing_domains if d[0] is not None]
    
    # Combine existing domains with predefined ones, remove duplicates, and sort
    all_domains = sorted(list(set(PREDEFINED_DOMAINS + existing_domains)))


    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        role = request.form.get('role')
        passcode = request.form.get('passcode')
        user_domain = request.form.get('user_domain') # New: Get user domain (for trainee or admin)

        # Basic validation
        if not username or not password or not role:
            flash('Please fill in all required fields.', 'danger')
            return render_template('register.html', title='Register', current_year=current_year, domains=all_domains)

        if User.query.filter_by(username=username).first():
            flash('Username already exists. Please choose a different one.', 'danger')
            return render_template('register.html', title='Register', current_year=current_year, domains=all_domains)

        # Role-specific passcode check
        if role == 'admin':
            if passcode != ADMIN_PASSCODE:
                flash('Incorrect passcode for Admin registration.', 'danger')
                return render_template('register.html', title='Register', current_year=current_year, domains=all_domains)
            if not user_domain: # Admins now also require a domain
                flash('Please provide a domain for Admin registration.', 'danger')
                return render_template('register.html', title='Register', current_year=current_year, domains=all_domains)
        elif role == 'support':
            if passcode != SUPPORT_PASSCODE:
                flash('Incorrect passcode for Support registration.', 'danger')
                return render_template('register.html', title='Register', current_year=current_year, domains=all_domains)
        elif role == 'trainee':
            if not user_domain: # Trainees require a domain
                flash('Please provide a domain for trainee registration.', 'danger')
                return render_template('register.html', title='Register', current_year=current_year, domains=all_domains)
        elif role not in ['admin', 'support', 'trainee']:
            flash('Invalid role selected.', 'danger')
            return render_template('register.html', title='Register', current_year=current_year, domains=all_domains)
        

        # Create new user
        new_user = User(username=username, role=role)
        new_user.set_password(password)
        
        # Set domain for both trainees and admins
        if role in ['trainee', 'admin']:
            new_user.domain = user_domain 
        else:
            new_user.domain = None # Ensure domain is None for support users

        try:
            db.session.add(new_user)
            db.session.commit()
            flash(f'Account created successfully for {role} user: {username}. You can now log in.', 'success')
            return redirect(url_for('login'))
        except Exception as e:
            db.session.rollback()
            flash(f'An error occurred during registration: {e}', 'danger')
            app.logger.error(f"Registration error: {e}") # Log the error for debugging

    return render_template('register.html', title='Register', current_year=current_year, domains=all_domains)


@app.route('/dashboard')
@login_required # User must be logged in to access the dashboard
def dashboard():
    """
    Renders the dashboard, adapting content based on the current user's role.
    Includes trainee insights for admin and support roles, and leaderboard data.
    """
    current_year = datetime.now().year
    
    dashboard_data = {}
    leaderboard_data = []

    if current_user.role == 'admin':
        dashboard_data['total_trainees'] = db.session.query(User).filter_by(role='trainee').count()
        dashboard_data['assignments_awaiting_grading'] = db.session.query(Assignment).filter_by(status='submitted_for_grading').count()
        
        # Count overdue assessments for admins
        overdue_assessments = db.session.query(Assignment).filter(
            Assignment.assessment_id.isnot(None), # Ensure it's an assessment
            Assignment.due_date < datetime.utcnow(),
            Assignment.status.in_(['assigned', 'in_progress', 'submitted_for_grading'])
        ).count()
        dashboard_data['overdue_assessments'] = overdue_assessments

        # Count overdue courses for admins
        overdue_courses = db.session.query(Assignment).filter(
            Assignment.course_id.isnot(None), # Ensure it's a course
            Assignment.due_date < datetime.utcnow(),
            Assignment.status.in_(['assigned', 'in_progress']) # Courses are typically 'assigned' or 'in_progress'
        ).count()
        dashboard_data['overdue_courses'] = overdue_courses

        # Count active assessments for admins
        active_assessments = db.session.query(Assignment).filter(
            Assignment.assessment_id.isnot(None),
            Assignment.status.in_(['assigned', 'in_progress'])
        ).count()
        dashboard_data['active_assessments'] = active_assessments

        # Count active courses for admins
        active_courses = db.session.query(Assignment).filter(
            Assignment.course_id.isnot(None),
            Assignment.status.in_(['assigned', 'in_progress'])
        ).count()
        dashboard_data['active_courses'] = active_courses

        # Prepare leaderboard data for admin
        trainees = db.session.query(User).filter_by(role='trainee').all()
        for trainee in trainees:
            completed_assessments = db.session.query(Assignment).filter(
                Assignment.trainee_id == trainee.id,
                Assignment.assessment_id.isnot(None),
                Assignment.status.in_(['completed', 'graded'])
            ).all()

            total_score = 0
            num_graded_assessments = 0
            for assignment in completed_assessments:
                if assignment.score is not None:
                    total_score += assignment.score
                    num_graded_assessments += 1
            
            average_score = (total_score / num_graded_assessments) if num_graded_assessments > 0 else 0
            leaderboard_data.append({
                'trainee': trainee,
                'average_score': round(average_score, 2)
            })
        
        # Sort by average_score in descending order
        leaderboard_data.sort(key=lambda x: x['average_score'], reverse=True)


    elif current_user.role == 'support':
        dashboard_data['total_trainees'] = db.session.query(User).filter_by(role='trainee').count()
        
        # Count active assignments for support (assigned or in_progress)
        active_assignments = db.session.query(Assignment).filter(
            Assignment.status.in_(['assigned', 'in_progress'])
        ).count()
        dashboard_data['active_assignments'] = active_assignments

        # Count overdue assignments (assessments + courses) for support
        overdue_assignments_total = db.session.query(Assignment).filter(
            Assignment.due_date < datetime.utcnow(),
            Assignment.status.in_(['assigned', 'in_progress', 'submitted_for_grading'])
        ).count()
        dashboard_data['overdue_assignments'] = overdue_assignments_total

        # Prepare leaderboard data for support (same as admin)
        trainees = db.session.query(User).filter_by(role='trainee').all()
        for trainee in trainees:
            completed_assessments = db.session.query(Assignment).filter(
                Assignment.trainee_id == trainee.id,
                Assignment.assessment_id.isnot(None),
                Assignment.status.in_(['completed', 'graded'])
            ).all()

            total_score = 0
            num_graded_assessments = 0
            for assignment in completed_assessments:
                if assignment.score is not None:
                    total_score += assignment.score
                    num_graded_assessments += 1
            
            average_score = (total_score / num_graded_assessments) if num_graded_assessments > 0 else 0
            leaderboard_data.append({
                'trainee': trainee,
                'average_score': round(average_score, 2)
            })
        
        # Sort by average_score in descending order
        leaderboard_data.sort(key=lambda x: x['average_score'], reverse=True)


    elif current_user.role == 'trainee':
        # Trainee dashboard content is handled by my_assignments route
        pass # No additional data needed for trainee dashboard here, as they have a dedicated page

    return render_template('dashboard.html', 
                           title='Dashboard', 
                           user=current_user, 
                           current_year=current_year,
                           dashboard_data=dashboard_data,
                           leaderboard_data=leaderboard_data) # Pass leaderboard data


# --- Admin Routes ---

@app.route('/admin/courses')
@login_required
@admin_required
def admin_view_courses():
    """
    Allows admins to view all courses, with optional filtering by domain.
    """
    current_year = datetime.now().year
    selected_domain = request.args.get('domain') # Changed from 'category' to 'domain'
    
    if selected_domain and selected_domain != 'all':
        courses = db.session.query(Course).filter_by(domain=selected_domain).all() # Changed from 'category' to 'domain'
    else:
        courses = db.session.query(Course).all()
    
    # Get all unique domains for the filter dropdown
    domains = db.session.query(Course.domain).distinct().all() # Changed from 'category' to 'domain'
    domains = [d[0] for d in domains if d[0] is not None] # Extract strings and filter out None
    domains.sort() # Sort domains alphabetically

    return render_template('admin/view_courses.html', 
                           title='Manage Courses', 
                           courses=courses, 
                           domains=domains, # Pass domains to template (changed from categories)
                           selected_domain=selected_domain, # Pass selected domain for dropdown (changed from selected_category)
                           current_year=current_year)


@app.route('/admin/courses/new', methods=['GET', 'POST'])
@login_required
@admin_required # Only admins can access this route
def create_course():
    """
    Handles the creation of a new course by an admin.
    """
    current_year = datetime.now().year
    # Get all unique domains for the datalist, including predefined ones
    existing_domains = db.session.query(Course.domain).distinct().all()
    existing_domains = [d[0] for d in existing_domains if d[0] is not None]
    
    # Combine existing domains with predefined ones, remove duplicates, and sort
    all_domains = sorted(list(set(PREDEFINED_DOMAINS + existing_domains)))

    if request.method == 'POST':
        name = request.form.get('name')
        description = request.form.get('description')
        course_link = request.form.get('course_link')
        domain = request.form.get('domain') # Changed from 'category' to 'domain'

        if not name:
            flash('Course name is required.', 'danger')
            return render_template('admin/create_course.html', title='Create New Course', domains=all_domains, current_year=current_year)

        new_course = Course(
            name=name,
            description=description,
            course_link=course_link,
            domain=domain, # Save the new domain (changed from category)
            created_by_id=current_user.id
        )
        
        try:
            db.session.add(new_course)
            db.session.commit()
            flash(f'Course "{name}" created successfully!', 'success')
            return redirect(url_for('admin_view_courses')) # Redirect to a course list page
        except Exception as e:
            db.session.rollback()
            flash(f'An error occurred while creating the course: {e}', 'danger')
            app.logger.error(f"Course creation error: {e}")

    return render_template('admin/create_course.html', title='Create New Course', domains=all_domains, current_year=current_year)

@app.route('/admin/courses/<int:course_id>/edit', methods=['GET', 'POST'])
@login_required
@admin_required
def edit_course(course_id):
    """
    Allows an admin to edit an existing course.
    """
    current_year = datetime.now().year
    course = db.session.get(Course, course_id) # Fix: Use db.session.get()
    if course is None:
        abort(404)
    # Get all unique domains for the datalist, including predefined ones
    existing_domains = db.session.query(Course.domain).distinct().all()
    existing_domains = [d[0] for d in existing_domains if d[0] is not None]
    
    # Combine existing domains with predefined ones, remove duplicates, and sort
    all_domains = sorted(list(set(PREDEFINED_DOMAINS + existing_domains)))

    if request.method == 'POST':
        course.name = request.form.get('name')
        course.description = request.form.get('description')
        course.course_link = request.form.get('course_link')
        course.domain = request.form.get('domain') # Update domain (changed from category)

        if not course.name:
            flash('Course name is required.', 'danger')
            return render_template('admin/edit_course.html', title='Edit Course', course=course, domains=all_domains, current_year=current_year)
        
        try:
            db.session.commit()
            flash(f'Course "{course.name}" updated successfully!', 'success')
            return redirect(url_for('admin_view_courses'))
        except Exception as e:
            db.session.rollback()
            flash(f'An error occurred while updating the course: {e}', 'danger')
            app.logger.error(f"Course update error: {e}")

    return render_template('admin/edit_course.html', title='Edit Course', course=course, domains=all_domains, current_year=current_year)


@app.route('/admin/courses/<int:course_id>/modules')
@login_required
@admin_required
def admin_view_course_modules(course_id):
    """
    Allows admins to view modules for a specific course.
    """
    current_year = datetime.now().year
    course = db.session.get(Course, course_id) # Fix: Use db.session.get()
    if course is None:
        abort(404)
    modules = db.session.query(Module).filter_by(course_id=course.id).all()
    return render_template('admin/view_course_modules.html', title=f'Modules for {course.name}', course=course, modules=modules, current_year=current_year)

@app.route('/admin/courses/<int:course_id>/modules/new', methods=['GET', 'POST'])
@login_required
@admin_required
def create_module(course_id):
    """
    Handles the creation of a new module for a specific course by an admin.
    """
    current_year = datetime.now().year
    course = db.session.get(Course, course_id) # Fix: Use db.session.get()
    if course is None:
        abort(404)

    if request.method == 'POST':
        name = request.form.get('name')
        description = request.form.get('description')
        module_link = request.form.get('module_link')

        if not name:
            flash('Module name is required.', 'danger')
            return render_template('admin/create_module.html', title='Create New Module', course=course, current_year=current_year)

        new_module = Module(
            course_id=course.id,
            name=name,
            description=description,
            module_link=module_link,
            created_by_id=current_user.id
        )
        try:
            db.session.add(new_module)
            db.session.commit()
            flash(f'Module "{name}" added successfully to {course.name}!', 'success')
            return redirect(url_for('admin_view_course_modules', course_id=course.id))
        except Exception as e:
            db.session.rollback()
            flash(f'An error occurred while creating the module: {e}', 'danger')
            app.logger.error(f"Module creation error: {e}")

    return render_template('admin/create_module.html', title='Create New Module', course=course, current_year=current_year)


@app.route('/admin/assessments')
@login_required
@admin_required
def admin_view_assessments():
    """
    Allows admins to view all assessments.
    """
    current_year = datetime.now().year
    assessments = db.session.query(Assessment).all()
    return render_template('admin/view_assessments.html', title='Manage Assessments', assessments=assessments, current_year=current_year)


@app.route('/admin/assessments/new', methods=['GET', 'POST'])
@login_required
@admin_required # Only admins can access this route
def create_assessment():
    """
    Handles the creation of a new assessment by an admin.
    Allows linking to an existing course.
    """
    current_year = datetime.now().year
    courses = db.session.query(Course).all() # Get all existing courses to link an assessment

    if request.method == 'POST':
        name = request.form.get('name')
        description = request.form.get('description')
        assessment_type = request.form.get('type')
        course_id = request.form.get('course_id')

        # Basic validation
        if not name or not assessment_type:
            flash('Assessment name and type are required.', 'danger')
            return render_template('admin/create_assessment.html', title='Create New Assessment', courses=courses, current_year=current_year)

        # Convert course_id to integer if provided, otherwise set to None
        course_id = int(course_id) if course_id else None

        new_assessment = Assessment(
            name=name,
            description=description,
            type=assessment_type,
            course_id=course_id,
            created_by_id=current_user.id
        )
        
        try:
            db.session.add(new_assessment)
            db.session.commit()
            flash(f'Assessment "{name}" created successfully!', 'success')
            # Redirect to the page to add questions for this new assessment
            return redirect(url_for('create_question', assessment_id=new_assessment.id))
        except Exception as e:
            db.session.rollback()
            flash(f'An error occurred while creating the assessment: {e}', 'danger')
            app.logger.error(f"Assessment creation error: {e}")

    return render_template('admin/create_assessment.html', title='Create New Assessment', courses=courses, current_year=current_year)

@app.route('/admin/assessments/<int:assessment_id>/edit', methods=['GET', 'POST'])
@login_required
@admin_required
def edit_assessment(assessment_id):
    """
    Allows an admin to edit an existing assessment.
    """
    current_year = datetime.now().year
    assessment = db.session.get(Assessment, assessment_id) # Fix: Use db.session.get()
    if assessment is None:
        abort(404)
    courses = db.session.query(Course).all() # For dropdown to change associated course

    if request.method == 'POST':
        assessment.name = request.form.get('name')
        assessment.description = request.form.get('description')
        assessment.type = request.form.get('type')
        course_id = request.form.get('course_id')

        if not assessment.name or not assessment.type:
            flash('Assessment name and type are required.', 'danger')
            return render_template('admin/edit_assessment.html', title='Edit Assessment', assessment=assessment, courses=courses, current_year=current_year)
        
        assessment.course_id = int(course_id) if course_id else None

        try:
            db.session.commit()
            flash(f'Assessment "{assessment.name}" updated successfully!', 'success')
            return redirect(url_for('admin_view_assessments'))
        except Exception as e:
            db.session.rollback()
            flash(f'An error occurred while updating the assessment: {e}', 'danger')
            app.logger.error(f"Assessment update error: {e}")

    return render_template('admin/edit_assessment.html', title='Edit Assessment', assessment=assessment, courses=courses, current_year=current_year)


@app.route('/admin/assessments/<int:assessment_id>/questions/new', methods=['GET', 'POST'])
@login_required
@admin_required
def create_question(assessment_id):
    """
    Handles the creation of a new question for a specific assessment by an admin.
    """
    current_year = datetime.now().year
    assessment = db.session.get(Assessment, assessment_id) # Fix: Use db.session.get()
    if assessment is None:
        abort(404)

    if request.method == 'POST':
        text = request.form.get('text')
        question_type = request.form.get('type')
        points = request.form.get('points', type=int)
        options_str = request.form.get('options') # For multiple choice/true_false
        correct_answer = request.form.get('correct_answer') # For multiple choice/true_false

        if not text or not question_type or points is None:
            flash('Question text, type, and points are required.', 'danger')
            return render_template('admin/create_question.html', title='Add Question', assessment=assessment, current_year=current_year)

        options = None
        if question_type in ['multiple_choice', 'true_false']:
            if options_str:
                options = [opt.strip() for opt in options_str.split('\n') if opt.strip()]
                if not options:
                    flash('Please provide options for multiple choice/true/false questions.', 'danger')
                    return render_template('admin/create_question.html', title='Add Question', assessment=assessment, current_year=current_year)
                options = json.dumps(options) # Store as JSON string
            else:
                flash('Options are required for multiple choice/true/false questions.', 'danger')
                return render_template('admin/create_question.html', title='Add Question', assessment=assessment, current_year=current_year)
            
            if not correct_answer:
                flash('Correct answer is required for multiple choice/true/false questions.', 'danger')
                return render_template('admin/create_question.html', title='Add Question', assessment=assessment, current_year=current_year)
            
            if question_type == 'true_false' and correct_answer not in ['True', 'False']:
                flash('Correct answer for True/False must be "True" or "False".', 'danger')
                return render_template('admin/create_question.html', title='Add Question', assessment=assessment, current_year=current_year)


        new_question = Question(
            assessment_id=assessment.id,
            text=text,
            type=question_type,
            options=options,
            correct_answer=correct_answer,
            points=points
        )

        try:
            db.session.add(new_question)
            db.session.commit()
            flash('Question added successfully!', 'success')
            # Redirect back to the same page to allow adding more questions, or to assessment details
            return redirect(url_for('create_question', assessment_id=assessment.id))
        except Exception as e:
            db.session.rollback()
            flash(f'An error occurred while adding the question: {e}', 'danger')
            app.logger.error(f"Question creation error: {e}")

    return render_template('admin/create_question.html', title='Add Question', assessment=assessment, current_year=current_year)

@app.route('/admin/assign/options')
@login_required
@admin_required
def assign_training_options():
    """
    Provides options for admins to choose between assigning a course or an assessment.
    """
    current_year = datetime.now().year
    return render_template('admin/assign_training_options.html', title='Assign Training Options', current_year=current_year)


@app.route('/admin/assign/course', methods=['GET', 'POST'])
@login_required
@admin_required
def assign_course_training():
    """
    Allows admins to assign courses to trainees.
    Creates notifications for trainees upon assignment.
    """
    current_year = datetime.now().year
    trainees = db.session.query(User).filter_by(role='trainee').all()
    courses = db.session.query(Course).all()

    # Get all unique domains for the datalist for filtering trainees
    existing_trainee_domains = db.session.query(User.domain).filter(User.role == 'trainee').distinct().all()
    existing_trainee_domains = [d[0] for d in existing_trainee_domains if d[0] is not None]
    all_trainee_domains = sorted(list(set(PREDEFINED_DOMAINS + existing_trainee_domains)))

    if request.method == 'POST':
        trainee_ids = request.form.getlist('trainee_ids') # Get a list of selected trainee IDs
        course_id = request.form.get('course_id')
        due_date_str = request.form.get('due_date')

        if not trainee_ids or not course_id:
            flash('Please select at least one trainee and a course.', 'danger')
            return render_template('admin/assign_course_training.html', title='Assign Course', trainees=trainees, courses=courses, current_year=current_year, trainee_domains=all_trainee_domains)

        try:
            course_id_int = int(course_id)
            due_date = datetime.strptime(due_date_str, '%Y-%m-%d') if due_date_str else None
        except (ValueError, TypeError):
            flash('Invalid course ID or due date format.', 'danger')
            return render_template('admin/assign_course_training.html', title='Assign Course', trainees=trainees, courses=courses, current_year=current_year, trainee_domains=all_trainee_domains)

        assigned_count = 0
        course_name = db.session.get(Course, course_id_int).name # Fix: Use db.session.get()

        for trainee_id in trainee_ids:
            try:
                trainee_id_int = int(trainee_id)
                
                # Check for existing assignment to prevent duplicates
                existing_assignment = db.session.query(Assignment).filter_by(
                    trainee_id=trainee_id_int,
                    course_id=course_id_int
                ).first()

                if existing_assignment:
                    flash(f'Course "{course_name}" already assigned to trainee ID {trainee_id}. Skipping.', 'info')
                    continue # Skip to the next trainee

                new_assignment = Assignment(
                    trainee_id=trainee_id_int,
                    course_id=course_id_int,
                    assigned_by_id=current_user.id,
                    due_date=due_date
                )

                db.session.add(new_assignment)
                db.session.flush() # Flush to get new_assignment.id for notification

                # Create notification for the trainee
                notification = Notification(
                    recipient_id=trainee_id_int,
                    sender_id=current_user.id,
                    message=f'You have been assigned a new course: "{course_name}".',
                    type='assignment_assigned',
                    related_id=new_assignment.id
                )
                db.session.add(notification)
                assigned_count += 1

            except ValueError:
                flash(f'Invalid trainee ID: {trainee_id}. Skipping.', 'danger')
                continue

        if assigned_count > 0:
            db.session.commit()
            flash(f'{assigned_count} course assignments created successfully!', 'success')
            return redirect(url_for('dashboard')) # Or a page to view assignments
        else:
            db.session.rollback()
            flash('No new course assignments were created.', 'info')

    return render_template('admin/assign_course_training.html', title='Assign Course', trainees=trainees, courses=courses, current_year=current_year, trainee_domains=all_trainee_domains)


@app.route('/admin/assign/assessment', methods=['GET', 'POST'])
@login_required
@admin_required
def assign_assessment_training():
    """
    Allows admins to assign assessments to trainees.
    Creates notifications for trainees upon assignment.
    """
    current_year = datetime.now().year
    trainees = db.session.query(User).filter_by(role='trainee').all()
    assessments = db.session.query(Assessment).all()

    # Get all unique domains for the datalist for filtering trainees
    existing_trainee_domains = db.session.query(User.domain).filter(User.role == 'trainee').distinct().all()
    existing_trainee_domains = [d[0] for d in existing_trainee_domains if d[0] is not None]
    all_trainee_domains = sorted(list(set(PREDEFINED_DOMAINS + existing_trainee_domains)))

    if request.method == 'POST':
        trainee_ids = request.form.getlist('trainee_ids') # Get a list of selected trainee IDs
        assessment_id = request.form.get('assessment_id')
        due_date_str = request.form.get('due_date')

        if not trainee_ids or not assessment_id:
            flash('Please select at least one trainee and an assessment.', 'danger')
            return render_template('admin/assign_assessment_training.html', title='Assign Assessment', trainees=trainees, assessments=assessments, current_year=current_year, trainee_domains=all_trainee_domains)

        try:
            assessment_id_int = int(assessment_id)
            due_date = datetime.strptime(due_date_str, '%Y-%m-%d') if due_date_str else None
        except (ValueError, TypeError):
            flash('Invalid assessment ID or due date format.', 'danger')
            return render_template('admin/assign_assessment_training.html', title='Assign Assessment', trainees=trainees, assessments=assessments, current_year=current_year, trainee_domains=all_trainee_domains)

        assigned_count = 0
        assessment_name = db.session.get(Assessment, assessment_id_int).name # Fix: Use db.session.get()

        for trainee_id in trainee_ids:
            try:
                trainee_id_int = int(trainee_id)
                
                # Check for existing assignment to prevent duplicates
                existing_assignment = db.session.query(Assignment).filter_by(
                    trainee_id=trainee_id_int,
                    assessment_id=assessment_id_int
                ).first()

                if existing_assignment:
                    flash(f'Assessment "{assessment_name}" already assigned to trainee ID {trainee_id}. Skipping.', 'info')
                    continue # Skip to the next trainee

                new_assignment = Assignment(
                    trainee_id=trainee_id_int,
                    assessment_id=assessment_id_int,
                    assigned_by_id=current_user.id,
                    due_date=due_date
                )

                db.session.add(new_assignment)
                db.session.flush() # Flush to get new_assignment.id for notification

                # Create notification for the trainee
                notification = Notification(
                    recipient_id=trainee_id_int,
                    sender_id=current_user.id,
                    message=f'You have been assigned a new assessment: "{assessment_name}".',
                    type='assignment_assigned',
                    related_id=new_assignment.id
                )
                db.session.add(notification)
                assigned_count += 1

            except ValueError:
                flash(f'Invalid trainee ID: {trainee_id}. Skipping.', 'danger')
                continue

        if assigned_count > 0:
            db.session.commit()
            flash(f'{assigned_count} assessment assignments created successfully!', 'success')
            return redirect(url_for('dashboard')) # Or a page to view assignments
        else:
            db.session.rollback()
            flash('No new assessment assignments were created.', 'info')

    return render_template('admin/assign_assessment_training.html', title='Assign Assessment', trainees=trainees, assessments=assessments, current_year=current_year, trainee_domains=all_trainee_domains)


@app.route('/admin/learning_paths')
@login_required
@admin_required
def admin_view_learning_paths():
    """
    Allows admins to view all learning paths.
    """
    current_year = datetime.now().year
    learning_paths = db.session.query(LearningPath).all()
    return render_template('admin/view_learning_paths.html', title='Manage Learning Paths', learning_paths=learning_paths, current_year=current_year)

@app.route('/admin/learning_paths/new', methods=['GET', 'POST'])
@login_required
@admin_required
def create_learning_path():
    """
    Handles the creation of a new learning path by an admin.
    """
    current_year = datetime.now().year
    courses = db.session.query(Course).all() # Get all courses to allow selection for the path

    if request.method == 'POST':
        name = request.form.get('name')
        description = request.form.get('description')
        selected_course_ids = request.form.getlist('courses') # Get list of selected course IDs

        if not name:
            flash('Learning Path name is required.', 'danger')
            return render_template('admin/create_learning_path.html', title='Create New Learning Path', courses=courses, current_year=current_year)

        new_path = LearningPath(
            name=name,
            description=description,
            created_by_id=current_user.id
        )

        try:
            # Add courses to the learning path
            for course_id in selected_course_ids:
                course = db.session.get(Course, int(course_id)) # Fix: Use db.session.get()
                if course:
                    new_path.courses.append(course)
            
            db.session.add(new_path)
            db.session.commit()
            flash(f'Learning Path "{name}" created successfully!', 'success')
            return redirect(url_for('admin_view_learning_paths'))
        except Exception as e:
            db.session.rollback()
            flash(f'An error occurred while creating the learning path: {e}', 'danger')
            app.logger.error(f"Learning Path creation error: {e}")

    return render_template('admin/create_learning_path.html', title='Create New Learning Path', courses=courses, current_year=current_year)

@app.route('/admin/learning_paths/<int:path_id>/edit', methods=['GET', 'POST'])
@login_required
@admin_required
def edit_learning_path(path_id):
    """
    Allows an admin to edit an existing learning path, including its associated courses.
    """
    current_year = datetime.now().year
    learning_path = db.session.get(LearningPath, path_id) # Fix: Use db.session.get()
    if learning_path is None:
        abort(404)
    all_courses = db.session.query(Course).all() # All courses available for selection

    if request.method == 'POST':
        learning_path.name = request.form.get('name')
        learning_path.description = request.form.get('description')
        selected_course_ids = request.form.getlist('courses')

        if not learning_path.name:
            flash('Learning Path name is required.', 'danger')
            return render_template('admin/edit_learning_path.html', title='Edit Learning Path', learning_path=learning_path, all_courses=all_courses, current_year=current_year)
        
        try:
            # Clear existing courses and add new ones
            learning_path.courses.clear()
            for course_id in selected_course_ids:
                course = db.session.get(Course, int(course_id)) # Fix: Use db.session.get()
                if course:
                    learning_path.courses.append(course)
            
            db.session.commit()
            flash(f'Learning Path "{learning_path.name}" updated successfully!', 'success')
            return redirect(url_for('admin_view_learning_paths'))
        except Exception as e:
            db.session.rollback()
            flash(f'An error occurred while updating the learning path: {e}', 'danger')
            app.logger.error(f"Learning Path update error: {e}")

    return render_template('admin/edit_learning_path.html', title='Edit Learning Path', learning_path=learning_path, all_courses=all_courses, current_year=current_year)


@app.route('/admin/assign/learning_path', methods=['GET', 'POST'])
@login_required
@admin_required
def assign_learning_path_training():
    """
    Allows admins to assign learning paths to trainees.
    Creates notifications for trainees upon assignment.
    """
    current_year = datetime.now().year
    trainees = db.session.query(User).filter_by(role='trainee').all()
    learning_paths = db.session.query(LearningPath).all()

    # Get all unique domains for the datalist for filtering trainees
    existing_trainee_domains = db.session.query(User.domain).filter(User.role == 'trainee').distinct().all()
    existing_trainee_domains = [d[0] for d in existing_trainee_domains if d[0] is not None]
    all_trainee_domains = sorted(list(set(PREDEFINED_DOMAINS + existing_trainee_domains)))

    if request.method == 'POST':
        trainee_ids = request.form.getlist('trainee_ids')
        learning_path_id = request.form.get('learning_path_id')
        due_date_str = request.form.get('due_date')

        if not trainee_ids or not learning_path_id:
            flash('Please select at least one trainee and a learning path.', 'danger')
            return render_template('admin/assign_learning_path_training.html', title='Assign Learning Path', trainees=trainees, learning_paths=learning_paths, current_year=current_year, trainee_domains=all_trainee_domains)

        try:
            learning_path_id_int = int(learning_path_id)
            due_date = datetime.strptime(due_date_str, '%Y-%m-%d') if due_date_str else None
        except (ValueError, TypeError):
            flash('Invalid learning path ID or due date format.', 'danger')
            return render_template('admin/assign_learning_path_training.html', title='Assign Learning Path', trainees=trainees, learning_paths=learning_paths, current_year=current_year, trainee_domains=all_trainee_domains)

        assigned_count = 0
        learning_path_name = db.session.get(LearningPath, learning_path_id_int).name # Fix: Use db.session.get()

        for trainee_id in trainee_ids:
            try:
                trainee_id_int = int(trainee_id)
                
                # Check for existing assignment to prevent duplicates
                existing_assignment = db.session.query(Assignment).filter_by(
                    trainee_id=trainee_id_int,
                    learning_path_id=learning_path_id_int
                ).first()

                if existing_assignment:
                    flash(f'Learning Path "{learning_path_name}" already assigned to trainee ID {trainee_id}. Skipping.', 'info')
                    continue

                new_assignment = Assignment(
                    trainee_id=trainee_id_int,
                    learning_path_id=learning_path_id_int,
                    assigned_by_id=current_user.id,
                    due_date=due_date
                )

                db.session.add(new_assignment)
                db.session.flush()

                # Create notification for the trainee
                notification = Notification(
                    recipient_id=trainee_id_int,
                    sender_id=current_user.id,
                    message=f'You have been assigned a new learning path: "{learning_path_name}".',
                    type='assignment_assigned',
                    related_id=new_assignment.id
                )
                db.session.add(notification)
                assigned_count += 1

            except ValueError:
                flash(f'Invalid trainee ID: {trainee_id}. Skipping.', 'danger')
                continue

        if assigned_count > 0:
            db.session.commit()
            flash(f'{assigned_count} learning path assignments created successfully!', 'success')
            return redirect(url_for('dashboard'))
        else:
            db.session.rollback()
            flash('No new learning path assignments were created.', 'info')

    return render_template('admin/assign_learning_path_training.html', title='Assign Learning Path', trainees=trainees, learning_paths=learning_paths, current_year=current_year, trainee_domains=all_trainee_domains)


# --- Trainee Routes ---

@app.route('/trainee/my_assignments')
@login_required
@trainee_required # Only trainees can access this route
def my_assignments():
    """
    Displays all assignments for the currently logged-in trainee.
    Adds logic to determine due date status for alerts.
    """
    current_year = datetime.now().year
    assignments = db.session.query(Assignment).filter_by(trainee_id=current_user.id).order_by(Assignment.due_date.asc()).all()

    assignments_with_status = []
    today = date.today() # Get today's date for comparison
    
    for assignment in assignments:
        status_info = {
            'assignment': assignment,
            'alert_type': 'none', # 'past_due', 'due_soon', 'on_track'
            'message': ''
        }

        if assignment.status == 'completed':
            status_info['alert_type'] = 'completed'
            status_info['message'] = 'This assignment is completed.'
        elif assignment.due_date:
            due_date_only = assignment.due_date.date() # Extract date part for comparison
            
            if due_date_only < today:
                status_info['alert_type'] = 'past_due'
                status_info['message'] = f'This assignment was due on {due_date_only.strftime("%Y-%m-%d")} and is past due!'
            elif today <= due_date_only <= today + timedelta(days=7):
                status_info['alert_type'] = 'due_soon'
                days_left = (due_date_only - today).days
                if days_left == 0:
                    status_info['message'] = 'This assignment is due today!'
                else:
                    status_info['message'] = f'This assignment is due in {days_left} day(s).'
            else:
                status_info['alert_type'] = 'on_track'
                status_info['message'] = f'Due on {due_date_only.strftime("%Y-%m-%d")}. You have plenty of time.'
        else:
            status_info['alert_type'] = 'no_due_date'
            status_info['message'] = 'No due date set for this assignment.'
        
        assignments_with_status.append(status_info)

    return render_template('trainee/my_assignments.html', 
                           title='My Assignments', 
                           assignments_with_status=assignments_with_status, 
                           current_year=current_year)

@app.route('/trainee/assignments/<int:assignment_id>')
@login_required
@trainee_required
def view_assignment(assignment_id):
    """
    Allows a trainee to view and start a specific assignment (course or assessment or learning path).
    """
    current_year = datetime.now().year
    assignment = db.session.get(Assignment, assignment_id) # Fix: Use db.session.get()
    if assignment is None:
        abort(404)

    # Ensure the assignment belongs to the current user
    if assignment.trainee_id != current_user.id:
        flash('You do not have permission to view this assignment.', 'danger')
        return redirect(url_for('my_assignments'))

    if assignment.course_id:
        course = db.session.get(Course, assignment.course_id) # Fix: Use db.session.get()
        if course is None:
            abort(404)
        modules = db.session.query(Module).filter_by(course_id=course.id).order_by(Module.id.asc()).all()
        
        # Get completion status for each module for this specific assignment
        module_completion_status = {}
        for module in modules:
            completion = db.session.query(TraineeModuleCompletion).filter_by(
                assignment_id=assignment.id,
                module_id=module.id
            ).first()
            module_completion_status[module.id] = True if completion else False

        return render_template('trainee/view_course.html', title=course.name, course=course, assignment=assignment, modules=modules, module_completion_status=module_completion_status, current_year=current_year)
    elif assignment.assessment_id:
        assessment = db.session.get(Assessment, assignment.assessment_id) # Fix: Use db.session.get()
        if assessment is None:
            abort(404)
        questions = db.session.query(Question).filter_by(assessment_id=assessment.id).all()
        # For an assessment, display questions for the trainee to answer
        return render_template('trainee/take_assessment.html', title=assessment.name, assessment=assessment, questions=questions, assignment=assignment, current_year=current_year)
    elif assignment.learning_path_id: # New logic for learning path
        learning_path = db.session.get(LearningPath, assignment.learning_path_id) # Fix: Use db.session.get()
        if learning_path is None:
            abort(404)
        # Fetch courses associated with this learning path
        courses_in_path = learning_path.courses
        return render_template('trainee/view_learning_path.html', title=learning_path.name, learning_path=learning_path, courses_in_path=courses_in_path, assignment=assignment, current_year=current_year)
    else:
        flash('This assignment does not link to a valid course, assessment, or learning path.', 'danger')
        return redirect(url_for('my_assignments'))

@app.route('/trainee/assignments/<int:assignment_id>/submit', methods=['POST'])
@login_required
@trainee_required
def submit_assignment(assignment_id):
    """
    Handles the submission of answers for an assessment.
    Creates a notification for the assigner admin if open-ended questions are submitted.
    """
    assignment = db.session.get(Assignment, assignment_id) # Fix: Use db.session.get()
    if assignment is None:
        abort(404)

    # Ensure the assignment belongs to the current user and is an assessment
    if assignment.trainee_id != current_user.id or not assignment.assessment_id:
        flash('Invalid assignment or permission denied.', 'danger')
        return redirect(url_for('my_assignments'))

    # Prevent re-submission if already completed/graded
    if assignment.status in ['completed', 'graded', 'submitted_for_grading']:
        flash('This assignment has already been submitted or is awaiting grading.', 'info')
        return redirect(url_for('my_assignments'))

    assessment = db.session.get(Assessment, assignment.assessment_id) # Fix: Use db.session.get()
    if assessment is None:
        abort(404)
    questions = db.session.query(Question).filter_by(assessment_id=assessment.id).all()

    total_score = 0
    total_possible_points = 0
    
    # Track if any open-ended questions exist
    has_open_ended = False

    try:
        for question in questions:
            user_answer = request.form.get(f'question_{question.id}')
            
            # Check if a submission already exists for this question/assignment
            existing_submission = db.session.query(Submission).filter_by(
                assignment_id=assignment.id,
                question_id=question.id
            ).first()

            if existing_submission:
                # Update existing submission if it's a re-submission (e.g., saving progress)
                existing_submission.answer_text = user_answer
                existing_submission.submitted_at = datetime.utcnow()
                # Reset auto-graded flags if re-submitting
                if question.type in ['multiple_choice', 'true_false']:
                    existing_submission.is_correct = None
                    existing_submission.grade = None
            else:
                # Create a new submission
                new_submission = Submission(
                    assignment_id=assignment.id,
                    question_id=question.id,
                    answer_text=user_answer,
                    submitted_at=datetime.utcnow()
                )
                db.session.add(new_submission)
                existing_submission = new_submission # Use new_submission for grading logic below

            total_possible_points += question.points

            if question.type == 'multiple_choice' or question.type == 'true_false':
                # Auto-grade multiple choice and true/false questions
                if user_answer and question.correct_answer and user_answer.strip().lower() == question.correct_answer.strip().lower():
                    existing_submission.is_correct = True
                    existing_submission.grade = float(question.points) # Full points for correct
                    total_score += question.points
                else:
                    existing_submission.is_correct = False
                    existing_submission.grade = 0.0 # Zero points for incorrect
            elif question.type == 'open_ended':
                has_open_ended = True
                # Open-ended questions need manual grading, status will be 'in_progress' or 'submitted_for_grading'
                existing_submission.is_correct = None # Not auto-graded
                existing_submission.grade = None # Not graded yet

        # Update assignment status and score
        if has_open_ended:
            assignment.status = 'submitted_for_grading'
            # Score for open-ended will be calculated after manual grading
            # For now, only include auto-graded points in score if there are open-ended questions
            assignment.score = (total_score / total_possible_points * 100) if total_possible_points > 0 else 0.0

            # Create notification for the admin who assigned it
            assigner_admin = db.session.get(User, assignment.assigned_by_id) # Fix: Use db.session.get()
            if assigner_admin:
                notification_message = f'Trainee "{current_user.username}" has submitted assessment "{assessment.name}" for grading.'
                notification = Notification(
                    recipient_id=assigner_admin.id,
                    sender_id=current_user.id,
                    message=notification_message,
                    type='assessment_submitted',
                    related_id=assignment.id
                )
                db.session.add(notification)
        else:
            assignment.status = 'completed'
            assignment.completion_date = datetime.utcnow()
            assignment.score = (total_score / total_possible_points * 100) if total_possible_points > 0 else 0.0
            # If no open-ended, it's fully completed, notify admin
            assigner_admin = db.session.get(User, assignment.assigned_by_id) # Fix: Use db.session.get()
            if assigner_admin:
                notification_message = f'Trainee "{current_user.username}" has completed assessment "{assessment.name}".'
                notification = Notification(
                    recipient_id=assigner_admin.id,
                    sender_id=current_user.id,
                    message=notification_message,
                    type='assessment_completed',
                    related_id=assignment.id
                )
                db.session.add(notification)


        db.session.commit()
        flash('Your assessment has been submitted successfully!', 'success')
        if has_open_ended:
            flash('This assessment contains open-ended questions and requires manual grading by an admin.', 'info')
        return redirect(url_for('my_assignments'))

    except Exception as e:
        db.session.rollback()
        flash(f'An error occurred during submission: {e}', 'danger')
        app.logger.error(f"Submission error: {e}")
        return redirect(url_for('my_assignments'))

@app.route('/trainee/assignments/<int:assignment_id>/mark_module_completed/<int:module_id>', methods=['POST'])
@login_required
@trainee_required
def mark_module_completed(assignment_id, module_id):
    """
    Allows a trainee to mark a specific module within a course assignment as completed.
    """
    assignment = db.session.get(Assignment, assignment_id) # Fix: Use db.session.get()
    if assignment is None:
        abort(404)
    module = db.session.get(Module, module_id) # Fix: Use db.session.get()
    if module is None:
        abort(404)

    # Ensure assignment belongs to current user and module belongs to the course in assignment
    if assignment.trainee_id != current_user.id or assignment.course_id != module.course_id:
        flash('Invalid module completion request or permission denied.', 'danger')
        return redirect(url_for('view_assignment', assignment_id=assignment.id))

    # Check if module is already completed for this assignment
    existing_completion = db.session.query(TraineeModuleCompletion).filter_by(
        assignment_id=assignment.id,
        module_id=module.id
    ).first()

    if existing_completion:
        flash('This module is already marked as completed.', 'info')
        return redirect(url_for('view_assignment', assignment_id=assignment.id))

    try:
        new_completion = TraineeModuleCompletion(
            assignment_id=assignment.id,
            module_id=module.id,
            completed_at=datetime.utcnow()
        )
        db.session.add(new_completion)
        db.session.commit()
        flash(f'Module "{module.name}" marked as completed!', 'success')
    except Exception as e:
        db.session.rollback()
        flash(f'An error occurred while marking the module complete: {e}', 'danger')
        app.logger.error(f"Module completion error: {e}")

    return redirect(url_for('view_assignment', assignment_id=assignment.id))


@app.route('/trainee/assignments/<int:assignment_id>/complete_course', methods=['GET', 'POST'])
@login_required
@trainee_required
def complete_course(assignment_id):
    """
    Handles the final completion of a course assignment, checking if all modules are completed
    and then prompting for a badge link.
    Creates a notification for the assigner admin upon course completion.
    """
    current_year = datetime.now().year
    assignment = db.session.get(Assignment, assignment_id) # Fix: Use db.session.get()
    if assignment is None:
        abort(404)

    if assignment.trainee_id != current_user.id or not assignment.course_id:
        flash('Invalid course assignment or permission denied.', 'danger')
        return redirect(url_for('my_assignments'))

    course = db.session.get(Course, assignment.course_id) # Fix: Use db.session.get()
    if course is None:
        abort(404)
    all_modules = db.session.query(Module).filter_by(course_id=course.id).all()
    completed_modules_count = db.session.query(TraineeModuleCompletion).filter_by(assignment_id=assignment.id).count()

    if len(all_modules) > 0 and completed_modules_count < len(all_modules):
        flash('You must complete all modules before marking the course as fully completed.', 'warning')
        return redirect(url_for('view_assignment', assignment_id=assignment.id))

    if assignment.status == 'completed':
        flash('This course has already been marked as completed.', 'info')
        return redirect(url_for('my_assignments'))

    if request.method == 'POST':
        completion_badge_link = request.form.get('completion_badge_link')

        if not completion_badge_link:
            flash('Please provide a completion badge link to mark the course as completed.', 'danger')
            return render_template('trainee/complete_course_form.html', title='Complete Course', assignment=assignment, current_year=current_year)

        try:
            assignment.status = 'completed'
            assignment.completion_date = datetime.utcnow()
            assignment.score = 100.0 # Courses are typically marked as 100% upon completion
            assignment.completion_badge_link = completion_badge_link # Save the badge link
            db.session.commit()

            # Create notification for the admin who assigned it
            assigner_admin = db.session.get(User, assignment.assigned_by_id) # Fix: Use db.session.get()
            if assigner_admin:
                notification_message = f'Trainee "{current_user.username}" has completed course "{course.name}".'
                notification = Notification(
                    recipient_id=assigner_admin.id,
                    sender_id=current_user.id,
                    message=notification_message,
                    type='course_completed',
                    related_id=assignment.id
                )
                db.session.add(notification)
                db.session.commit() # Commit again to save the notification
            
            flash('Course marked as completed and badge link saved!', 'success')
        except Exception as e:
            db.session.rollback()
            flash(f'An error occurred while completing the course: {e}', 'danger')
            app.logger.error(f"Course completion error: {e}")
        
        return redirect(url_for('my_assignments'))
    
    # If GET request and all modules are completed (or no modules exist), display the form
    return render_template('trainee/complete_course_form.html', title='Complete Course', assignment=assignment, current_year=current_year)

# --- Admin Grading Routes ---

@app.route('/admin/grade_assessments')
@login_required
@admin_required
def grade_assessments():
    """
    Displays a list of assignments that are submitted for grading.
    """
    current_year = datetime.now().year
    # Fetch assignments that are 'submitted_for_grading'
    assignments_to_grade = db.session.query(Assignment).filter_by(status='submitted_for_grading').all()
    return render_template('admin/grade_assessments.html', title='Grade Assessments', assignments=assignments_to_grade, current_year=current_year)

@app.route('/admin/grade_submission/<int:assignment_id>', methods=['GET', 'POST'])
@login_required
@admin_required
def grade_submission(assignment_id):
    """
    Allows an admin to view a specific submission and grade open-ended questions.
    Creates a notification for the trainee upon grading.
    """
    current_year = datetime.now().year
    assignment = db.session.get(Assignment, assignment_id) # Fix: Use db.session.get()
    if assignment is None:
        abort(404)

    # Ensure it's an assessment and submitted for grading
    if not assignment.assessment_id or assignment.status not in ['submitted_for_grading', 'graded']:
        flash('This assignment is not awaiting grading or has already been graded.', 'info')
        return redirect(url_for('grade_assessments'))

    assessment = db.session.get(Assessment, assignment.assessment_id) # Fix: Use db.session.get()
    if assessment is None:
        abort(404)
    
    # Fetch all submissions for this assignment, and eager load questions
    # Use a join to get question details along with submissions
    submissions = db.session.query(Submission, Question)\
                        .join(Question, Submission.question_id == Question.id)\
                        .filter(Submission.assignment_id == assignment.id)\
                        .all()

    if request.method == 'POST':
        total_graded_score = 0
        total_possible_graded_points = 0
        all_graded = True

        for submission, question in submissions:
            if question.type == 'open_ended':
                grade_input = request.form.get(f'grade_{submission.id}')
                if grade_input is not None and grade_input != '':
                    try:
                        grade_value = float(grade_input)
                        if 0 <= grade_value <= question.points:
                            submission.grade = grade_value
                            submission.graded_by_id = current_user.id
                            submission.graded_at = datetime.utcnow()
                        else:
                            flash(f'Grade for question "{question.text}" must be between 0 and {question.points}.', 'danger')
                            all_graded = False # Don't commit if there's an invalid grade
                            break # Exit loop
                    except ValueError:
                        flash(f'Invalid grade format for question "{question.text}". Please enter a number.', 'danger')
                        all_graded = False # Don't commit if there's an invalid grade
                        break # Exit loop
                else:
                    all_graded = False # Not all open-ended questions have been graded

            # Sum up all graded points (auto-graded + manually graded)
            if submission.grade is not None:
                total_graded_score += submission.grade
            total_possible_graded_points += question.points # Sum up points for all questions

        if all_graded:
            assignment.status = 'graded'
            assignment.score = (total_graded_score / total_possible_graded_points * 100) if total_possible_graded_points > 0 else 0.0
            assignment.completion_date = datetime.utcnow() # Mark as completed after final grading
            try:
                db.session.commit()
                
                # Create notification for the trainee
                trainee = db.session.get(User, assignment.trainee_id) # Fix: Use db.session.get()
                if trainee:
                    notification_message = f'Your assessment "{assessment.name}" has been graded. Your score: {assignment.score:.2f}%.'
                    notification = Notification(
                        recipient_id=trainee.id,
                        sender_id=current_user.id,
                        message=notification_message,
                        type='assessment_graded',
                        related_id=assignment.id
                    )
                    db.session.add(notification)
                    db.session.commit() # Commit again to save the notification

                flash('Assessment graded successfully!', 'success')
                return redirect(url_for('grade_assessments'))
            except Exception as e:
                db.session.rollback()
                flash(f'An error occurred while saving grades: {e}', 'danger')
                app.logger.error(f"Grading submission error: {e}")
        else:
            db.session.rollback() # Rollback any changes if not all graded or error
            flash('Not all open-ended questions were graded or there was an input error. Please ensure all grades are entered correctly.', 'warning')


    return render_template('admin/grade_submission.html', title='Grade Submission', assignment=assignment, submissions=submissions, current_year=current_year)

# --- Admin User Management Routes ---

@app.route('/admin/users')
@login_required
@roles_required('admin', 'support') # Allow both admin and support to view all users
def admin_view_users():
    """
    Allows admins and support users to view all users in the system, with optional filtering by domain.
    """
    current_year = datetime.now().year
    selected_domain = request.args.get('domain')
    
    # Get all unique domains from users (trainees and admins) for the filter dropdown
    existing_user_domains = db.session.query(User.domain).filter(User.role.in_(['trainee', 'admin'])).distinct().all()
    existing_user_domains = [d[0] for d in existing_user_domains if d[0] is not None]
    all_user_domains = sorted(list(set(PREDEFINED_DOMAINS + existing_user_domains)))

    if selected_domain and selected_domain != 'all':
        users = db.session.query(User).filter_by(domain=selected_domain).all()
    else:
        users = db.session.query(User).all()

    return render_template('admin/manage_users.html', 
                           title='Manage Users', 
                           users=users, 
                           domains=all_user_domains, # Pass all unique user domains
                           selected_domain=selected_domain, # Pass selected domain for dropdown
                           current_year=current_year)

@app.route('/admin/users/<int:user_id>/edit', methods=['GET', 'POST'])
@login_required
@admin_required
def edit_user(user_id):
    """
    Allows an admin to edit an existing user's details (username, role, password, domain).
    """
    current_year = datetime.now().year
    user_to_edit = db.session.get(User, user_id) # Fix: Use db.session.get()
    if user_to_edit is None:
        abort(404)

    # Get all unique domains for the datalist, including predefined ones
    existing_domains = db.session.query(Course.domain).distinct().all()
    existing_domains = [d[0] for d in existing_domains if d[0] is not None]
    all_domains = sorted(list(set(PREDEFINED_DOMAINS + existing_domains)))


    if request.method == 'POST':
        new_username = request.form.get('username')
        new_role = request.form.get('role')
        new_password = request.form.get('password')
        new_domain = request.form.get('domain') # Get updated domain

        # Basic validation
        if not new_username or not new_role:
            flash('Username and role are required.', 'danger')
            return render_template('admin/edit_user.html', title='Edit User', user_item=user_to_edit, current_year=current_year, domains=all_domains)

        # Check if username already exists for another user
        existing_user_with_username = db.session.query(User).filter(User.username == new_username, User.id != user_to_edit.id).first()
        if existing_user_with_username:
            flash('Username already exists for another user. Please choose a different one.', 'danger')
            return render_template('admin/edit_user.html', title='Edit User', user_item=user_to_edit, current_year=current_year, domains=all_domains)

        # Update user details
        user_to_edit.username = new_username
        user_to_edit.role = new_role
        
        # Only update domain if the user is a trainee or admin
        if user_to_edit.role in ['trainee', 'admin']:
            user_to_edit.domain = new_domain
        else:
            user_to_edit.domain = None # Clear domain if not a trainee or admin

        if new_password: # Only update password if a new one is provided
            user_to_edit.set_password(new_password)
        
        try:
            db.session.commit()
            flash(f'User "{user_to_edit.username}" updated successfully!', 'success')
            return redirect(url_for('admin_view_users'))
        except Exception as e:
            db.session.rollback()
            flash(f'An error occurred while updating the user: {e}', 'danger')
            app.logger.error(f"User update error: {e}")

    return render_template('admin/edit_user.html', title='Edit User', user_item=user_to_edit, current_year=current_year, domains=all_domains)


@app.route('/admin/users/<int:trainee_id>/progress')
@login_required
@roles_required('admin', 'support') # Allow both admin and support to view trainee progress
def admin_view_trainee_progress(trainee_id):
    """
    Allows an admin or support user to view the detailed progress of a specific trainee.
    """
    current_year = datetime.now().year
    trainee = db.session.get(User, trainee_id) # Fix: Use db.session.get()
    if trainee is None:
        abort(404)

    # This check ensures that only actual 'trainee' roles are processed for progress viewing.
    # If a non-trainee user's ID is passed, it will redirect back to manage users.
    if trainee.role != 'trainee':
        flash('User is not a trainee. Progress can only be viewed for trainee accounts.', 'danger')
        return redirect(url_for('admin_view_users')) 

    assignments = db.session.query(Assignment).filter_by(trainee_id=trainee.id).order_by(Assignment.assigned_at.desc()).all()

    # Prepare data for rendering
    trainee_progress_data = []
    for assignment in assignments:
        item_data = {
            'assignment': assignment,
            'type': 'course' if assignment.course_id else ('assessment' if assignment.assessment_id else 'learning_path'), # Added learning_path type
            'details': None,
            'modules': [], # For courses
            'submissions': [], # For assessments
            'courses_in_path': [] # For learning paths
        }

        if assignment.course_id:
            course = db.session.get(Course, assignment.course_id) # Fix: Use db.session.get()
            if course is None:
                abort(404)
            item_data['details'] = course
            
            modules = db.session.query(Module).filter_by(course_id=course.id).order_by(Module.id.asc()).all()
            for module in modules:
                completion = db.session.query(TraineeModuleCompletion).filter_by(
                    assignment_id=assignment.id,
                    module_id=module.id
                ).first()
                item_data['modules'].append({
                    'module': module,
                    'is_completed': True if completion else False,
                    'completed_at': completion.completed_at if completion else None
                })
        elif assignment.assessment_id:
            assessment = db.session.get(Assessment, assignment.assessment_id) # Fix: Use db.session.get()
            if assessment is None:
                abort(404)
            item_data['details'] = assessment
            
            # Fetch submissions along with their questions
            submissions_with_questions = db.session.query(Submission, Question)\
                                            .join(Question, Submission.question_id == Question.id)\
                                            .filter(Submission.assignment_id == assignment.id)\
                                            .all()
            for submission, question in submissions_with_questions:
                item_data['submissions'].append({
                    'submission': submission,
                    'question': question
                })
        elif assignment.learning_path_id: # New logic for learning path progress
            learning_path = db.session.get(LearningPath, assignment.learning_path_id) # Fix: Use db.session.get()
            if learning_path is None:
                abort(404)
            item_data['details'] = learning_path
            item_data['courses_in_path'] = learning_path.courses # Get all courses in the path
            # You might want to add logic here to track progress *within* the learning path,
            # e.g., which courses in the path the trainee has completed.
            # This would require more complex tracking (e.g., another association table or status on AssignmentCourse).
            # For now, it.courses just lists the courses in the path.

        trainee_progress_data.append(item_data)

    # Render the correct template based on the current user's role
    if current_user.role == 'admin':
        return render_template('admin/view_trainee_progress.html', 
                               title=f'Progress for {trainee.username}', 
                               trainee=trainee, 
                               progress_data=trainee_progress_data, 
                               current_year=current_year)
    elif current_user.role == 'support':
        return render_template('support/view_trainee_progress.html', # Use the support-specific template
                               title=f'Progress for {trainee.username}', 
                               trainee=trainee, 
                               progress_data=trainee_progress_data, 
                               current_year=current_year)
    else:
        # Fallback, though roles_required should prevent this
        flash('You do not have permission to view trainee progress.', 'danger')
        return redirect(url_for('dashboard'))


@app.route('/admin/users/<int:user_id>/reset_password', methods=['GET', 'POST'])
@login_required
@admin_required # Only admins can reset passwords
def reset_user_password(user_id):
    """
    Allows an admin to reset the password for any user.
    """
    current_year = datetime.now().year
    user_to_reset = db.session.get(User, user_id) # Fix: Use db.session.get()
    if user_to_reset is None:
        abort(404)

    # Prevent resetting own password via this route (use edit_user for that)
    if user_to_reset.id == current_user.id:
        flash('You cannot reset your own password via this page. Use the "Edit User" page for that.', 'danger')
        return redirect(url_for('admin_view_users'))

    if request.method == 'POST':
        new_password = request.form.get('new_password')
        confirm_password = request.form.get('confirm_password')

        if not new_password or not confirm_password:
            flash('Please enter and confirm the new password.', 'danger')
            return render_template('admin/reset_password.html', title='Reset Password', user_item=user_to_reset, current_year=current_year)
        
        if new_password != confirm_password:
            flash('Passwords do not match.', 'danger')
            return render_template('admin/reset_password.html', title='Reset Password', user_item=user_to_reset, current_year=current_year)
        
        user_to_reset.set_password(new_password)
        try:
            db.session.commit()
            flash(f'Password for user "{user_to_reset.username}" has been reset successfully!', 'success')
            return redirect(url_for('admin_view_users'))
        except Exception as e:
            db.session.rollback()
            flash(f'An error occurred while resetting the password: {e}', 'danger')
            app.logger.error(f"Password reset error: {e}")

    return render_template('admin/reset_password.html', title='Reset Password', user_item=user_to_reset, current_year=current_year)


@app.route('/search')
@login_required
def search():
    """
    Handles search queries across users, courses, and assessments.
    Accessible to all logged-in users.
    """
    current_year = datetime.now().year
    query = request.args.get('query', '').strip()
    
    search_results = {
        'users': [],
        'courses': [],
        'assessments': [],
        'learning_paths': [] # Added for learning paths
    }

    if query:
        search_pattern = f"%{query}%"

        # Search Users (only if admin or support)
        if current_user.role in ['admin', 'support']:
            users = db.session.query(User).filter(User.username.ilike(search_pattern)).all()
            search_results['users'] = users

        # Search Courses
        courses = db.session.query(Course).filter(
            (Course.name.ilike(search_pattern)) | 
            (Course.description.ilike(search_pattern))
        ).all()
        search_results['courses'] = courses

        # Search Assessments
        assessments = db.session.query(Assessment).filter(
            (Assessment.name.ilike(search_pattern)) | 
            (Assessment.description.ilike(search_pattern))
        ).all()
        search_results['assessments'] = assessments

        # Search Learning Paths
        learning_paths = db.session.query(LearningPath).filter(
            (LearningPath.name.ilike(search_pattern)) |
            (LearningPath.description.ilike(search_pattern))
        ).all()
        search_results['learning_paths'] = learning_paths

    return render_template('search_results.html', 
                           title='Search Results', 
                           query=query, 
                           results=search_results, 
                           current_year=current_year)

@app.route('/notifications')
@login_required
def view_notifications():
    """
    Displays all notifications for the current user.
    """
    current_year = datetime.now().year
    notifications = db.session.query(Notification).filter_by(recipient_id=current_user.id).order_by(Notification.created_at.desc()).all()
    return render_template('notifications.html', title='My Notifications', notifications=notifications, current_year=current_year)

@app.route('/notifications/mark_read/<int:notification_id>')
@login_required
def mark_notification_read(notification_id):
    """
    Marks a specific notification as read.
    """
    notification = db.session.get(Notification, notification_id) # Fix: Use db.session.get()
    if notification is None:
        abort(404)
    if notification.recipient_id != current_user.id:
        flash('You do not have permission to mark this notification as read.', 'danger')
        return redirect(url_for('view_notifications'))
    
    notification.is_read = True
    try:
        db.session.commit()
        flash('Notification marked as read.', 'success')
    except Exception as e:
        db.session.rollback()
        flash(f'An error occurred: {e}', 'danger')
        app.logger.error(f"Error marking notification read: {e}")
    
    return redirect(url_for('view_notifications'))


# --- Database Initialization and Seeding ---

def create_db():
    """Creates the database tables."""
    with app.app_context():
        inspector = inspect(db.engine) # Correct way to get an inspector instance

        # Check if the 'course' table exists
        if not inspector.has_table("course"):
            db.create_all()
            print("Database tables created.")
        else:
            print("Database tables already exist. Checking for new columns/tables...")
            # Check if the 'category' column exists in the 'course' table and rename/add 'domain'
            existing_course_columns = [column['name'] for column in inspector.get_columns("course")]
            
            if "category" in existing_course_columns and "domain" not in existing_course_columns:
                # If 'category' exists but 'domain' doesn't, rename 'category' to 'domain'
                with db.engine.connect() as connection:
                    connection.execute(db.text("ALTER TABLE course RENAME COLUMN category TO domain"))
                print("Renamed 'category' column to 'domain' in 'course' table.")
                db.session.commit() # Commit the ALTER TABLE statement
            elif "category" not in existing_course_columns and "domain" not in existing_course_columns:
                # If neither exists, add 'domain'
                with db.engine.connect() as connection:
                    connection.execute(db.text("ALTER TABLE course ADD COLUMN domain VARCHAR(50)"))
                print("Added 'domain' column to 'course' table.")
                db.session.commit() # Commit the ALTER TABLE statement
            else:
                print("'domain' column already exists in 'course' table.")
                if "category" in existing_course_columns and "domain" in existing_course_columns:
                    print("Both 'category' and 'domain' columns exist. This might indicate a previous manual migration or error. No automatic action taken for 'category'.")

            # Check if 'learning_path_id' column exists in 'assignment' table
            existing_assignment_columns = [column['name'] for column in inspector.get_columns("assignment")]
            if "learning_path_id" not in existing_assignment_columns:
                with db.engine.connect() as connection:
                    connection.execute(db.text("ALTER TABLE assignment ADD COLUMN learning_path_id INTEGER"))
                    connection.execute(db.text("CREATE INDEX ix_assignment_learning_path_id ON assignment (learning_path_id)"))
                    connection.execute(db.text("CREATE UNIQUE INDEX ix_learning_path_courses_learning_path_id_course_id ON learning_path_courses (learning_path_id, course_id)"))
                print("Added 'learning_path_id' column to 'assignment' table and created index.")
                db.session.commit()
            else:
                print("'learning_path_id' column already exists in 'assignment' table.")
            
            # Check if 'domain' column exists in 'user' table
            existing_user_columns = [column['name'] for column in inspector.get_columns("user")]
            if "domain" not in existing_user_columns:
                with db.engine.connect() as connection:
                    connection.execute(db.text("ALTER TABLE user ADD COLUMN domain VARCHAR(50)"))
                print("Added 'domain' column to 'user' table.")
                db.session.commit()
            else:
                print("'domain' column already exists in 'user' table.")


        # Ensure all tables are created if they don't exist (e.g., if db file was just deleted or new tables added)
        db.create_all()


def seed_db():
    """
    Seeds the database with initial data, including a trainee user.
    Admin and support users will now be registered via the UI with passcodes.
    """
    with app.app_context():
        # Only seed trainee if no users exist, or if specifically no trainee exists
        if not db.session.query(User).filter_by(role='trainee').first():
            print("Seeding database with initial trainee user...")
            trainee_user = User(username='trainee', role='trainee', domain='Data Collection') # Assign a default domain
            trainee_user.set_password('traineepass')
            db.session.add(trainee_user)
            db.session.commit()
            print("Initial trainee user created.")
        else:
            print("Trainee user already exists. Skipping trainee seeding.")
        
        # Check if an admin user exists, if not, prompt to register
        if not db.session.query(User).filter_by(role='admin').first():
            print("No admin user found. Please register an admin via the UI with passcode 'admincode'.")
        if not db.session.query(User).filter_by(role='support').first():
            print("No support user found. Please register a support user via the UI with passcode 'supportcode'.")

# --- Main execution block ---

if __name__ == '__main__':
    # Create database tables if they don't exist
    create_db()
    # Seed the database with initial users (only trainee now)
    seed_db()
    # Run the Flask application
    app.run(debug=True) # Set debug=False for production
