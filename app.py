from flask import Flask, jsonify, render_template, request, redirect, url_for, flash, session
from flask_login import LoginManager, login_user, login_required, logout_user, current_user
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from flask_login import UserMixin
import json

app = Flask(__name__)
app.config['SECRET_KEY'] = 'f3e1a87c3df40a29a4f2ef4cd6f10b33'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///job_portal.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app)
login_manager = LoginManager()
login_manager.login_view = 'login'
login_manager.init_app(app)

# Function to load job data from jobs.json
def load_job_data():
    try:
        with open('jobs.json', 'r') as f:
            return json.load(f)
    except FileNotFoundError:
        return []

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(100), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password = db.Column(db.String(200), nullable=False)
    role = db.Column(db.String(20), nullable=False)

    
# Job posting route
@app.route('/post_job', methods=['GET', 'POST'])
def post_job():
    if request.method == 'POST':
        # Get data from the form
        title = request.form['title']
        description = request.form['description']
        salary = request.form['salary']
        location = request.form['location']
        category = request.form['category']
        company = request.form['company']
        user_id = current_user.id

        # Simple form validation (you can add more validation if needed)
        if not title or not description or not salary or not location or not category or not company:
            # If required fields are missing, redirect with failure parameter
            return redirect(url_for('home', job_posted='false'))

        # Read current jobs from jobs.json
        try:
            with open('jobs.json', 'r') as f:
                jobs = json.load(f)
        except FileNotFoundError:
            jobs = []

        # Generate a new job id (assuming jobs are indexed sequentially)
        job_id = len(jobs) + 1

        # Create new job entry with salary included
        new_job = {
            'id': job_id,
            'title': title,
            'description': description,
            'salary': salary,
            'location': location,
            'category': category,
            'company': company,
            'user_id': user_id
        }

        # Add the new job to the list
        jobs.append(new_job)

        # Write the updated jobs list back to jobs.json
        with open('jobs.json', 'w') as f:
            json.dump(jobs, f, indent=4)

        # Redirect to the home page with the 'job_posted=true' parameter
        return redirect(url_for('home', job_posted='true'))

    return render_template('post_job.html')  # Template for job posting form


@app.route('/', methods=['GET', 'POST'])
def home():
    # Handle job browsing
    try:
        with open('jobs.json', 'r') as file:
            jobs_data = json.load(file)
    except Exception as e:
        print(f"Error loading jobs data: {e}")
        jobs_data = []

    # Apply filters if provided (location, category, company)
    location = request.args.get('location', '')
    category = request.args.get('category', '')
    company = request.args.get('company', '')

    # Filter jobs
    filtered_jobs = [job for job in jobs_data if
                     (not location or location.lower() in job['location'].lower()) and
                     (not category or category.lower() in job['category'].lower()) and
                     (not company or company.lower() in job['company'].lower())]

    # Debug filtered result
    print(f"Filtered jobs: {filtered_jobs}")

    return render_template('index.html', jobs=filtered_jobs, location=location, category=category, company=company)


@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        email = request.form['email']
        role = request.form['role']

        existing_user = User.query.filter_by(username=username, email=email).first()

        if existing_user:
            print(f"⚠️ Registration failed: Username '{username}' already exists.")
            # Redirect to the register page with a failure message
            return redirect(url_for('register', registration_status='failure'))

        hashed_password = generate_password_hash(password, method='pbkdf2:sha256')
        new_user = User(username=username, email=email, password=hashed_password, role=role)
        db.session.add(new_user)
        db.session.commit()

        # 👇 Print to CMD after successful registration
        print(f"🆕 New user registered: {username} | Role: {role}")

        # Redirect to login page with success status
        return redirect(url_for('login', registration_status='success'))
    
    # 👇 This handles the GET request
    return render_template('register.html')

    
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        user = User.query.filter_by(username=username).first()

        if not user or not check_password_hash(user.password, password):
            print(f"❌ Failed login attempt for username: {username}")
            # Redirect to login page with failure status
            return redirect(url_for('login', login_status='failure'))
        
        login_user(user)

        # 👇 This will print info to CMD
        print(f"✅ {user.username} has logged in as {user.role}")

        # Redirect to different pages based on the role
        if user.role == 'admin':
            return redirect(url_for('admin_jobs'))  # Redirect to admin jobs page for admin
        else:
            # Redirect with success status for login
            return redirect(url_for('home', login_status='success'))  # Redirect to home page for other users
    
    return render_template('login.html')

@app.route('/my_listings')
def my_listings():
    # Read jobs data from the jobs.json file
    with open('jobs.json', 'r') as f:
        jobs = json.load(f)

    # Filter jobs by user_id (assuming current_user has an attribute `user_id`)
    user_jobs = [job for job in jobs if job.get('user_id') == current_user.id]

    return render_template('my_listings.html', jobs=user_jobs)

@app.route('/delete_job/<int:job_id>', methods=['POST'])
def delete_job(job_id):
    # Read jobs data
    with open('jobs.json', 'r') as f:
        jobs = json.load(f)

    # Filter out the job with the given id
    jobs = [job for job in jobs if job.get('id') != job_id]

    # Save the updated list back to jobs.json
    with open('jobs.json', 'w') as f:
        json.dump(jobs, f, indent=4)

    flash('Job deleted successfully!', 'success')
    return redirect(url_for('my_listings'))



@app.route('/edit_job/<int:job_id>', methods=['GET', 'POST'])
def edit_job(job_id):
    # Read jobs data from the jobs.json file
    with open('jobs.json', 'r') as f:
        jobs = json.load(f)

    # Find the job by ID
    job_to_edit = next((job for job in jobs if job['id'] == job_id), None)

    if job_to_edit is None:
        return 'Job not found!', 404

    if request.method == 'POST':
        # Update the job details
        job_to_edit['title'] = request.form['title']
        job_to_edit['description'] = request.form['description']
        job_to_edit['salary'] = request.form['salary']
        job_to_edit['location'] = request.form['location']
        job_to_edit['category'] = request.form['category']
        job_to_edit['company'] = request.form['company']

        # Write updated jobs data back to jobs.json
        with open('jobs.json', 'w') as f:
            json.dump(jobs, f, indent=4)

        flash('Job updated successfully!', 'success')
        return redirect(url_for('my_listings'))

    # Display the current job details in the edit form
    return render_template('edit_job.html', job=job_to_edit)


@app.route('/profile', methods=['GET', 'POST'])
@login_required
def profile():
    if request.method == 'POST':
        # Retrieve form data
        username = request.form['username']
        email = request.form['email']
        role = request.form['role']
        
        # Update user details
        current_user.username = username
        current_user.email = email
        current_user.role = role
        
        # Commit changes to the database
        db.session.commit()  # Make sure you're using SQLAlchemy
        
        flash('Profile updated successfully!', 'success')
        return redirect(url_for('profile'))

    return render_template('profile.html', user=current_user)

@app.route('/dashboard')
@login_required
def dashboard():
    return render_template('dashboard.html', username=current_user.username, role=current_user.role)

@app.route('/view_users')
@login_required
def view_users():
    if current_user.role != 'admin':  # Only allow access for the admin role
        return "Unauthorized", 403  # You can also redirect to another page like the dashboard if needed
    
    users = User.query.all()  # Fetch all users from the database
    return render_template('view_users.html', users=users)

@app.route('/delete_user/<int:user_id>', methods=['POST'])
@login_required
def delete_user(user_id):
    if current_user.role != 'admin':
        return "Unauthorized", 403  # Only admin can delete users

    user_to_delete = User.query.get_or_404(user_id)
    db.session.delete(user_to_delete)
    db.session.commit()

    print(f"🗑️ User {user_to_delete.username} has been deleted.")

    return redirect(url_for('view_users'))

@app.route('/edit_user/<int:user_id>', methods=['GET', 'POST'])
@login_required
def edit_user(user_id):
    if current_user.role != 'admin':
        return "Unauthorized", 403  # Only admin can edit users

    user_to_edit = User.query.get_or_404(user_id)

    if request.method == 'POST':
        user_to_edit.username = request.form['username']
        user_to_edit.role = request.form['role']
        db.session.commit()

        print(f"✏️ User {user_to_edit.username} has been edited.")

        return redirect(url_for('view_users'))

    return render_template('edit_user.html', user=user_to_edit)

@app.route('/admin/jobs')
@login_required
def admin_jobs():
    if current_user.role != 'admin':
        return "Unauthorized", 403
    jobs = load_job_data()
    return render_template('admin_jobs.html', jobs=jobs)

@app.route('/admin/users')
@login_required
def admin_users():
    if current_user.role != 'admin':
        return "Unauthorized", 403
    users = User.query.all()
    return render_template('admin_users.html', users=users)

@app.route('/logout')
@login_required
def logout():
    logout_user()
    print("User has logged out.")
    return redirect(url_for('login'))


if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(debug=True)
