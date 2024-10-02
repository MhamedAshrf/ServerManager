from flask import Flask, render_template, request, redirect, url_for, flash
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from flask_apscheduler import APScheduler
scheduler = APScheduler()

app = Flask(__name__)
app.config['SECRET_KEY'] = 'your_secret_key'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///users.db'
db = SQLAlchemy(app)

# Initialize Flask-Login
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'
from flask_migrate import Migrate

migrate = Migrate(app, db)

# Association table for User and Server (many-to-many relationship)
user_server = db.Table('user_server',
    db.Column('user_id', db.Integer, db.ForeignKey('user.id')),
    db.Column('server_id', db.Integer, db.ForeignKey('server.id'))
)

# User Model
class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(150), nullable=False, unique=True)
    email = db.Column(db.String(150), nullable=False, unique=True)
    password = db.Column(db.String(200), nullable=False)
    percentage = db.Column(db.Integer, nullable=True)  # Percentage value
    work = db.Column(db.String(150), nullable=True)    # Work information
    position = db.Column(db.String(150), nullable=True) # Position
    is_admin = db.Column(db.Boolean, default=False, nullable=False)  # Admin flag

    # Other fields like servers, reserved_slots, etc.

    def __repr__(self):
        return f'<User {self.username}>'


# Server Model
class Server(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(150), nullable=False)
    ip_address = db.Column(db.String(50), nullable=False)
    specs = db.Column(db.String(250))
    location = db.Column(db.String(100))

from datetime import datetime, timedelta

# TimeSlot model
# TimeSlot model
class TimeSlot(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    start_time = db.Column(db.DateTime, nullable=False)
    end_time = db.Column(db.DateTime, nullable=False)
    server_id = db.Column(db.Integer, db.ForeignKey('server.id'), nullable=False)
    server = db.relationship('Server', backref='time_slots')
    reserved_by_user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=True)  # Who reserved the slot
    reserved_by_user = db.relationship('User', backref='reserved_slots')

# Flask-Login loader
@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# Create database
with app.app_context():
    db.create_all()
# Function to generate time slots
def generate_time_slots(server, days_ahead=90):
    """Generate 2-hour time slots for the next 'days_ahead' days for the given server."""
    now = datetime.now()
    start_date = now.replace(hour=0, minute=0, second=0, microsecond=0)  # Start from midnight today
    end_date = start_date + timedelta(days=days_ahead)

    # Find the latest time slot for this server
    last_slot = TimeSlot.query.filter_by(server=server).order_by(TimeSlot.start_time.desc()).first()
    
    # If there are existing slots, start from the last one; otherwise, start from today
    if last_slot:
        start_date = last_slot.end_time + timedelta(seconds=1)

    while start_date < end_date:
        # Generate 2-hour slots
        for hour in range(0, 24, 2):
            slot_start = start_date.replace(hour=hour, minute=0)
            slot_end = slot_start + timedelta(hours=2)

            # Create a new time slot
            new_slot = TimeSlot(start_time=slot_start, end_time=slot_end, server=server)
            db.session.add(new_slot)

        # Move to the next day
        start_date += timedelta(days=1)
    
    db.session.commit()
# Routes
@app.route('/')
def index():
    return render_template('index.html')

# Admin adding a user
@app.route('/admin/add_user', methods=['GET', 'POST'])
@login_required
def add_user():
    if not current_user.is_admin:
        flash("Access restricted to admins only.", 'danger')
        return redirect(url_for('index'))

    if request.method == 'POST':
        username = request.form.get('username')
        email = request.form.get('email')
        password = request.form.get('password')
        percentage = request.form.get('percentage')
        work = request.form.get('work')
        position = request.form.get('position')

        # Hash the password
        hashed_password = generate_password_hash(password, method='sha256')

        # Create a new user object
        new_user = User(username=username, email=email, password=hashed_password, 
                        percentage=percentage, work=work, position=position)

        try:
            # Add and commit to the database
            db.session.add(new_user)
            db.session.commit()
            flash(f"User {username} has been added.", 'success')
            return redirect(url_for('add_user'))
        except:
            flash("There was an issue adding the user.", 'danger')

    return render_template('add_user.html')


# Admin creating a server
# Admin creating a server
@app.route('/admin/create_server', methods=['GET', 'POST'])
@login_required
def create_server():
    if not current_user.is_admin:
        flash("You don't have permission to access this page.", 'danger')
        return redirect(url_for('index'))

    if request.method == 'POST':
        server_name = request.form['server_name']
        ip_address = request.form['ip_address']
        specs = request.form['specs']
        location = request.form['location']

        # Create new server
        new_server = Server(name=server_name, ip_address=ip_address, specs=specs, location=location)
        db.session.add(new_server)
        db.session.commit()

        # Generate time slots for the next 3 months
        generate_time_slots(new_server, days_ahead=90)

        flash(f'Server {server_name} created successfully and time slots generated!', 'success')
        return redirect(url_for('index'))

    return render_template('create_server.html')

# Admin assigning users to a server
@app.route('/admin/assign_users/<int:server_id>', methods=['GET', 'POST'])
@login_required
def assign_users(server_id):
    if not current_user.is_admin:
        flash("You don't have permission to access this page.", 'danger')
        return redirect(url_for('index'))

    server = Server.query.get_or_404(server_id)
    users = User.query.all()  # Get all users to assign

    if request.method == 'POST':
        user_id = request.form.get('user_id')
        user = User.query.get(user_id)
        if user:
            server.users.append(user)
            db.session.commit()
            flash(f"User {user.username} has been assigned to {server.name}.", 'success')
        else:
            flash("User not found.", 'danger')
        return redirect(url_for('assign_users', server_id=server.id))

    return render_template('assign_users.html', server=server, users=users)


# User login
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        user = User.query.filter_by(username=username).first()

        if user and check_password_hash(user.password, password):
            login_user(user)
            flash(f'Welcome, {user.username}!', 'success')
            return redirect(url_for('index'))
        else:
            flash('Login failed. Check your username and password.', 'danger')
    return render_template('login.html')
@app.route('/admin/servers')
@login_required
def list_servers():
    if not current_user.is_admin:
        flash("You don't have permission to access this page.", 'danger')
        return redirect(url_for('index'))

    servers = Server.query.all()
    return render_template('list_servers.html', servers=servers)
@app.route('/admin/server/<int:server_id>')
@login_required
def view_server(server_id):
    if not current_user.is_admin:
        flash("You don't have permission to access this page.", 'danger')
        return redirect(url_for('index'))

    server = Server.query.get_or_404(server_id)
    return render_template('view_server.html', server=server)

# Function to generate time slots for all servers
def generate_daily_time_slots():
    """Generate time slots for all servers for the next 90 days, but only add the next day's slots."""
    with app.app_context():
        for server in Server.query.all():
            generate_time_slots(server, days_ahead=1)
        print("Daily time slots generated for all servers!")

# Scheduler job to run daily at midnight
scheduler.add_job(id='generate_daily_time_slots', func=generate_daily_time_slots, trigger='interval', days=1)


@app.route('/reserve_slot_list', methods=['GET', 'POST'])
@login_required
def reserve_slot_list():
    if current_user.is_admin:
        flash("Admins cannot reserve servers.", 'danger')
        return redirect(url_for('index'))

    # Fetch servers the user is assigned to
    servers = Server.query.filter(Server.users.contains(current_user)).all()

    if not servers:
        flash("You are not assigned to any servers.", 'danger')
        return redirect(url_for('index'))

    # Handle POST request to reserve a time slot
    if request.method == 'POST':
        slot_id = request.form.get('slot_id')  # Get slot_id from form data
        slot = TimeSlot.query.get_or_404(slot_id)

        # Check if the slot is already reserved
        if slot.reserved_by_user:
            flash(f"The slot from {slot.start_time} to {slot.end_time} is already reserved.", 'danger')
        else:
            slot.reserved_by_user = current_user
            db.session.commit()
            flash(f"You have successfully reserved the slot from {slot.start_time} to {slot.end_time}.", 'success')

        return redirect(url_for('reserve_slot_list'))

    return render_template('reserve_slot_list.html', servers=servers)




@app.route('/admin/server/<int:server_id>/time_slots')
@login_required
def view_time_slots(server_id):
    server = Server.query.get_or_404(server_id)
    time_slots = TimeSlot.query.filter_by(server=server).order_by(TimeSlot.start_time.asc()).all()
    return render_template('view_time_slots.html', server=server, time_slots=time_slots)

@app.route('/admin/dashboard')
@login_required
def admin_dashboard():
    if not current_user.is_admin:
        flash("Access restricted to admins only.", 'danger')
        return redirect(url_for('index'))

    # Get all users and servers
    users = User.query.all()
    servers = Server.query.all()

    # Pass data to the template
    return render_template('admin_dashboard.html', users=users, servers=servers)

@app.route('/dashboard')
@login_required
def dashboard():
    # Fetch servers assigned to the current user
    assigned_servers = Server.query.filter(Server.users.contains(current_user)).all()

    # Debugging: Ensure that the assigned_servers list is being populated correctly
    if not assigned_servers:
        print("No servers assigned to this user.")
    else:
        print("Assigned Servers:", assigned_servers)

    # Render the template and pass assigned_servers
    return render_template('dashboard.html', assigned_servers=assigned_servers)

# User logout
@app.route('/logout')
@login_required
def logout():
    logout_user()
    flash('You have been logged out.', 'info')
    return redirect(url_for('login'))

if __name__ == '__main__':
    app.run(debug=True)
