TrainTrack: Comprehensive Training & Assessment Management System

TrainTrack is a web-based Flask application designed to manage training courses and assessments with role-based access for Administrators, Support Staff, and Trainees.

Key Features:

Role-Based Access Control: Differentiates functionalities for Admins (full control), Support (user/progress viewing), and Trainees (assignment completion, progress tracking).

Course & Assessment Management: Allows creation, editing, and assignment of courses (with modules) and assessments (with various question types, including auto-grading and manual grading).

Assignment System: Facilitates assigning training to trainees, setting due dates, and tracking assignment statuses.

Progress Tracking: Provides detailed views of trainee performance and module completion.

Interactive Dashboards: Offers visual overviews for Admins (total trainees, grading queue, overdue/active assignments/courses) and Support (total trainees, active/overdue assignments).

Trainee Leaderboard: Displays average assessment scores to foster engagement.

Notifications: Real-time alerts for users on assignment status and completions.

Search Functionality: Enables searching across users, courses, and assessments.

Technologies Used:

Backend: Python (Flask, Flask-SQLAlchemy, Flask-Login, Werkzeug), SQLite.

Frontend: Jinja2, HTML5, Tailwind CSS, Custom CSS for animations.

Setup & Installation:

Clone the GitHub repository.

Set up a Python virtual environment and activate it.

Install dependencies from requirements.txt (Flask, Flask-SQLAlchemy, Flask-Login, Werkzeug).

The SQLite database (traintrack.db) is automatically created and seeded with a default 'trainee' user on first run.

Set environment variables for ADMIN_PASSCODE, SUPPORT_PASSCODE, and SECRET_KEY (default passcodes are provided for dev).

Run the application using flask run (typically accessible at http://127.0.0.1:5000/).

Usage: Register new users (admin/support require passcodes), log in, and navigate through the role-specific dashboards and features.
The application will typically be accessible at http://127.0.0.1:5000/ in your web browser.UsageOnce the application is running, you can access it via your web browser.Register:Go to /register.You can register as a trainee directly.To register as support, use the passcode supportcode.To register as admin, use the passcode admincode.Login:Use the credentials you registered with.An initial trainee user is seeded with username: trainee, password: traineepass.Key Routes/: Homepage/login: User login/register: User registration/dashboard: Role-based dashboard/trainee/my_assignments: Trainee's assignments/admin/users: Admin/Support user management hub/admin/courses: Admin course management/admin/assessments: Admin assessment management/admin/assign_training: Admin training assignment/admin/grade_assessments: Admin assessment grading queue/notifications: User notificationsProject Structure.
├── app.py                  # Main Flask application file
├── requirements.txt        # Python dependencies
├── templates/              # Jinja2 HTML templates
│   ├── base.html           # Base template for consistent layout
│   ├── index.html          # Homepage
│   ├── login.html          # Login page
│   ├── register.html       # Registration page
│   ├── dashboard.html      # User dashboard (role-based)
│   ├── notifications.html  # User notifications page
│   ├── search_results.html # Search results page
│   ├── admin/              # Admin-specific templates
│   │   ├── assign_training.html
│   │   ├── create_assessment.html
│   │   ├── create_course.html
│   │   ├── create_module.html
│   │   ├── create_question.html
│   │   ├── edit_assessment.html
│   │   ├── edit_course.html
│   │   ├── edit_user.html
│   │   ├── grade_assessments.html
│   │   ├── grade_submission.html
│   │   ├── manage_users.html
│   │   ├── reset_password.html
│   │   ├── view_assessments.html
│   │   ├── view_course_modules.html
│   │   ├── view_courses.html
│   │   └── view_trainee_progress.html # Admin view of trainee progress
│   ├── support/            # Support-specific templates
│   │   └── view_trainee_progress.html # Support view of trainee progress
│   └── trainee/            # Trainee-specific templates
│       ├── complete_course_form.html
│       ├── my_assignments.html
│       ├── take_assessment.html
│       └── view_course.html
└── traintrack.db           # SQLite database file (generated on first run)
