TrainTrack: Comprehensive Training & Assessment Management SystemTrainTrack is a web-based application designed to streamline the management of training courses and assessments for various user roles: Administrators, Support Staff, and Trainees. It provides a robust platform for assigning training, tracking progress, grading assessments, and fostering a fun and engaging learning environment with interactive dashboards and leaderboards.FeaturesRole-Based Access Control:Admin: Full control over users, courses, assessments, assignments, and grading. Access to comprehensive dashboard insights and trainee leaderboard.Support: View user accounts, monitor trainee progress, and access the trainee leaderboard.Trainee: View assigned courses and assessments, track personal progress, complete modules, submit assessments, and receive notifications.Course Management:Create, edit, and manage training courses with descriptions and external links.Organize courses into modules with individual content links.Trainees can mark modules as complete and finalize course completion.Assessment Management:Create and manage assessments with various question types (multiple choice, true/false, open-ended).Define points for each question.Auto-grading for multiple choice and true/false questions.Manual grading for open-ended questions by administrators.Assignment System:Admins can assign courses and assessments to multiple trainees.Set due dates for assignments.Track assignment status (assigned, in progress, submitted for grading, completed, graded).Progress Tracking:Detailed view of trainee progress on assigned courses and assessments, including module completion and submission details.Interactive Dashboards:Admin Overview: Visual insights into total trainees, assignments awaiting grading, overdue assessments/courses, and active assessments/courses.Support Overview: Key metrics on total trainees, active assignments, and total overdue assignments.Trainee Leaderboard:A dynamic leaderboard displaying trainees' average assessment scores, encouraging friendly competition.Notifications:Real-time notifications for trainees on new assignments, course completion, and assessment grading.Notifications for admins on assessment submissions and course completions.Search Functionality: Easily search for users, courses, and assessments across the platform.Technologies UsedBackend:Python 3.xFlask: Web frameworkFlask-SQLAlchemy: ORM for database interactionFlask-Login: User session managementWerkzeug: WSGI utility library (used by Flask)SQLite: Lightweight relational databaseFrontend:Jinja2: Templating engineHTML5Tailwind CSS: Utility-first CSS framework for rapid stylingCustom CSS for animations and interactive elements.Setup and InstallationFollow these steps to get TrainTrack up and running on your local machine.PrerequisitesPython 3.8+Git1. Clone the RepositoryFirst, clone the project repository to your local machine:git clone https://github.com/your-username/TrainTrack-Flask-App.git
cd TrainTrack-Flask-App
(Replace your-username/TrainTrack-Flask-App.git with your actual GitHub repository URL)2. Set Up a Virtual EnvironmentIt's highly recommended to use a virtual environment to manage project dependencies.python -m venv venv
Activate the virtual environment:macOS/Linux:source venv/bin/activate
Windows (Command Prompt):venv\Scripts\activate.bat
Windows (PowerShell):.\venv\Scripts\Activate.ps1
3. Install DependenciesWith your virtual environment activated, install the required Python packages:pip install -r requirements.txt
The requirements.txt file contains:Flask==2.3.2
Flask-SQLAlchemy==3.0.3
Flask-Login==0.6.2
Werkzeug==2.3.7
4. Database Initialization and SeedingThe application uses an SQLite database. The app.py script will automatically create the database tables and seed an initial trainee user if they don't already exist.5. Set Environment Variables (Passcodes)For admin and support user registration, the application uses passcodes. For production, you should set these as actual environment variables. For local development, they have default values, but it's good practice to set them explicitly:macOS/Linux:export ADMIN_PASSCODE='admincode'
export SUPPORT_PASSCODE='supportcode'
export SECRET_KEY='your_super_secret_key' # Replace with a strong, random key
Windows (Command Prompt):set ADMIN_PASSCODE=admincode
set SUPPORT_PASSCODE=supportcode
set SECRET_KEY=your_super_secret_key
Windows (PowerShell):$env:ADMIN_PASSCODE='admincode'
$env:SUPPORT_PASSCODE='supportcode'
$env:SECRET_KEY='your_super_secret_key'
(Note: These commands set variables for the current session only. For permanent settings, consult your OS documentation or use a .env file with a library like python-dotenv if you prefer.)6. Run the ApplicationFinally, run the Flask application:flask run
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
