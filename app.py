import io
from flask import Flask, flash, render_template, request, jsonify, redirect, send_file, url_for, session
from flask_sqlalchemy import SQLAlchemy
import qrcode
from werkzeug.security import check_password_hash, generate_password_hash
from werkzeug.utils import secure_filename
import hashlib
import os
import secrets  # To generate secure random tokens
from datetime import datetime
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from PIL import Image  # Ensure this import is correct
import bcrypt
# Import Blockchain and Block classes
from blockchain import AssignmentBlockchain, Block, Blockchain, StaffBlockchain, StudentBlockchain
from models import Staff

# Initialize Flask application
app = Flask(__name__)

# Add the correct database URI
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///staff.db'  # Update as per your DB
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.secret_key = os.getenv('SECRET_KEY', 'your_default_secret_key')

db = SQLAlchemy(app)

# Ensure database tables are created
with app.app_context():
    db.create_all()  # Automatically creates tables if they do not exist

# Initialize the blockchain instance
blockchain = Blockchain()
# Example:
staff_blockchain = StaffBlockchain()
student_blockchain = StudentBlockchain()
assignment_blockchain= AssignmentBlockchain()
# Directory for storing uploaded files
UPLOAD_FOLDER = 'uploads'
ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg'}
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
os.makedirs(UPLOAD_FOLDER, exist_ok=True)

# Admin credentials (hashed password should be stored securely)
ADMIN_USERNAME = 'admin'
ADMIN_PASSWORD_HASH = generate_password_hash('password')  # Change password as needed


# Email configuration
SMTP_SERVER = 'smtp.gmail.com'  # Example for Gmail, use your email provider's server
SMTP_PORT = 587
SMTP_USERNAME = 'justsecret4411@gmail.com'  # Replace with your email
SMTP_PASSWORD = 'tmob lbjy ngnz oway'  # Replace with your email password



def hash_usn(usn):
    # Create a hash of the USN using SHA256
    return hashlib.sha256(usn.encode()).hexdigest()

# Helper function to send email
def send_email(to_address, subject, body):
    msg = MIMEMultipart()
    msg['From'] = SMTP_USERNAME
    msg['To'] = to_address
    msg['Subject'] = subject

    msg.attach(MIMEText(body, 'plain'))

    try:
        server = smtplib.SMTP(SMTP_SERVER, SMTP_PORT)
        server.starttls()
        server.login(SMTP_USERNAME, SMTP_PASSWORD)
        text = msg.as_string()
        server.sendmail(SMTP_USERNAME, to_address, text)
        server.quit()
        print(f"Email sent to {to_address}")
    except Exception as e:
        print(f"Failed to send email to {to_address}: {str(e)}")
# Helper function to check file extensions
def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

# Helper function to save files and return their hashes
def save_file_and_get_hash(file):
    if allowed_file(file.filename):
        filename = secure_filename(file.filename)
        file_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
        file.save(file_path)
        file.seek(0)
        file_hash = hashlib.sha256(file.read()).hexdigest()
        return file_hash, filename
    return None, None

# Function to hash the USN using SHA-256
def hash_usn(usn):
    return hashlib.sha256(usn.encode()).hexdigest()

# Route for the landing page (home page)
@app.route('/')
def index():
    return render_template('home.html')

# Route to add staff details
# Route to add staff details
@app.route('/add_staff', methods=['GET', 'POST'])
def add_staff():
    if not session.get('logged_in'):
        return redirect(url_for('login'))

    if request.method == 'POST':
        # Collect staff details from the form
        staff_data = {
            "name": request.form.get('name'),
            "phone_number": request.form.get('phone_number'),
            "branch": request.form.get('branch'),
            "email": request.form.get('email')
        }

        # Ensure all fields are provided
        if not all(staff_data.values()):
            return jsonify({"message": "All fields are required"}), 400

        # Generate the hashed password using the email
        email_hash = hashlib.sha256(staff_data['email'].encode()).hexdigest()
        password = email_hash[:12]  # First 12 characters of the hash as the password
        hashed_password = generate_password_hash(password)
        staff_data['password'] = hashed_password

        # Get the previous hash for creating the blockchain
        previous_hash = staff_blockchain.get_latest_block().hash if staff_blockchain.chain else '0'

        # Add the staff data to the blockchain
        staff_blockchain.create_block(previous_hash, staff_data)

        print(f"Staff added to blockchain: {staff_data}")

        try:
            # Send email notification with login credentials
            subject = 'Your Staff Login Credentials'
            body = (
                f"Hello {staff_data['name']},\n\n"
                f"Your login credentials have been added to the system.\n"
                f"Username: {staff_data['email']}\n"
                f"Password: {password}\n"
                f"Please change your password after your first login.\n\n"
                f"Best regards,\nAdmin Team"
            )
            send_email(staff_data['email'], subject, body)

        except Exception as e:
            return jsonify({"message": "Staff added, but email sending failed.", "error": str(e)}), 500

        return jsonify({"message": f"Staff {staff_data['name']} added successfully!"}), 200

    return render_template('add_staff.html')

@app.route('/staff_login', methods=['GET', 'POST'])
def staff_login():
    error = None

    if request.method == 'POST':
        # Fetch email and password from the form
        email = request.form.get('email')
        password = request.form.get('password')

        # Debugging logs to verify data retrieval
        logging.info(f"Email received: {email}")
        logging.info(f"Password received: {password}")

        # Ensure both fields are provided
        if not email or not password:
            error = "Email and password are required"
            return render_template('staff_login.html', error=error)

        # Search for the staff in the blockchain by email
        staff_block = next((block for block in staff_blockchain.chain if block.staff_data.get('email') == email), None)

        if staff_block:
            # Get the hashed password and name from the blockchain
            stored_hashed_password = staff_block.staff_data.get('password')
            staff_name = staff_block.staff_data.get('name')  # Retrieve the staff's name

            # Validate the provided password against the stored hashed password
            if check_password_hash(stored_hashed_password, password):
                # Successful login
                session['staff_logged_in'] = True
                session['email'] = email
                session['name'] = staff_name  # Store staff's name in the session

                logging.info(f"Staff logged in: {email}")
                return redirect(url_for('staff_dashboard'))
            else:
                error = "Invalid password"
        else:
            error = "Staff with this email not found"

    return render_template('staff_login.html', error=error)

# Route to view all staff details
@app.route('/staff_details', methods=['GET'])
def staff_details():
    staff_list = staff_blockchain.get_all_staff_details()

    # Log staff_list to check for duplicates
    print(staff_list)

    if staff_list:
        return render_template('staff_details.html', staff_list=staff_list)
    else:
        return render_template('staff_details.html', message="No staff data found")

@app.route('/assignments', methods=['GET'])
def assignments():
    if not session.get('staff_logged_in'):
        return redirect(url_for('staff_login'))

    staff_name = session.get('name', 'Unknown')  # Fallback if name is not found

    # Debugging: Print blockchain contents
    logging.info(f"Blockchain contents: {assignment_blockchain.chain}")

    assignments = []
    for block in assignment_blockchain.chain:
        if block.index == 0:
            continue  # Skip the genesis block

        logging.info(f"Processing block: {block.staff_data}")  # Debug each block

        assignments.append({
            "index": block.index,
            "batch": block.staff_data.get("branch", "Unknown"),
            "subject": block.staff_data.get("subject", "Unknown"),
            "work": block.staff_data.get("work", "Unknown"),
            "due_date": block.staff_data.get("due_date", "Unknown"),
           "assigned_by": session.get('name', block.staff_data.get('assigned_by', 'Unknown'))  # Priority to session name
         })

    return render_template('assignments.html', assignments=assignments)

@app.route('/login', methods=['GET', 'POST'])
def login():
    error = None

    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')

        if username == ADMIN_USERNAME and check_password_hash(ADMIN_PASSWORD_HASH, password):
            session['logged_in'] = True
            session['username'] = username

            # Check if admin has already changed their password
            if not session.get('password_changed'):
                return redirect(url_for('change_password'))

            return redirect(url_for('add_student'))

        else:
            error = 'Invalid username or password'

    return render_template('login.html', error=error)

@app.route('/change_password', methods=['GET', 'POST'])
def change_password():
    if not session.get('logged_in'):
        return redirect(url_for('login'))

    if request.method == 'POST':
        new_password = request.form.get('new_password')
        confirm_password = request.form.get('confirm_password')

        # Check if passwords match and meet requirements
        if new_password != confirm_password:
            flash('Passwords do not match.', 'danger')
            return redirect(url_for('change_password'))

        if len(new_password) < 8:
            flash('Password must be at least 8 characters long.', 'danger')
            return redirect(url_for('change_password'))

        # Hash and store the new password
        global ADMIN_PASSWORD_HASH
        ADMIN_PASSWORD_HASH = generate_password_hash(new_password)

        # Mark password as changed
        session['password_changed'] = True

        # Send email notification
        try:
            sender_email = "justsecret4411@gmail.com"
            sender_password = "tmob lbjy ngnz oway"
            recipient_email = "justsecret4411@gmail.com"

            subject = "Password Changed Notification"
            body = "The administrator password has been successfully changed."

            # Create the email
            msg = MIMEMultipart()
            msg['From'] = sender_email
            msg['To'] = recipient_email
            msg['Subject'] = subject
            msg.attach(MIMEText(body, 'plain'))

            # Connect to the server and send the email
            with smtplib.SMTP('smtp.gmail.com', 587) as server:
                server.starttls()
                server.login(sender_email, sender_password)
                server.send_message(msg)

            flash('Password changed successfully! Notification email sent.', 'success')

        except Exception as e:
            flash(f'Password changed, but email could not be sent: {e}', 'warning')

        return redirect(url_for('add_student'))

    return render_template('change_password.html')

# Route to log out the admin
@app.route('/logout')
def logout():
    session.pop('logged_in', None)
    return redirect(url_for('login'))

def hash_password(password):
    return hashlib.sha256(password.encode()).hexdigest()



@app.route('/add_student', methods=['GET', 'POST'])
def add_student():
    if not session.get('logged_in'):
        return redirect(url_for('login'))

    if request.method == 'POST':
        # Get form data
        student_data = {
            "name": request.form.get('name'),
            "usn": request.form.get('usn'),
            "email": request.form.get('email'),
            "course": request.form.get('course'),
            "institute": request.form.get('institute'),
            "college": request.form.get('college'),
            "gender": request.form.get('gender'),
            "dob": request.form.get('dob'),
            
            "skills": [skill.strip() for skill in request.form.get('skills').split(',') if skill.strip()]
        }
        # Validate Date of Birth (must be on or after 2004-01-01)
        try:
            dob_date = datetime.strptime(student_data["dob"], '%Y-%m-%d')
            if dob_date < datetime(2001, 1, 1):
                return jsonify({"message": "Invalid Date of Birth. Must be born on or after January 1, 2004."}), 400
        except ValueError:
            return jsonify({"message": "Invalid Date of Birth format."}), 400

        # Generate a unique secret key for the student
        student_data['secret_key'] = secrets.token_hex(16)

        profile_picture = request.files.get('profilePicture')

        # Validate input data
        if not all(student_data.values()):
            return jsonify({"message": "Invalid input"}), 400

        # Hash the USN
        usn_hash = hashlib.sha256(student_data["usn"].encode()).hexdigest()
        student_data["usn_hash"] = usn_hash

        # Save the profile picture if provided
        if profile_picture:
            file_hash, filename = save_file_and_get_hash(profile_picture)
            if file_hash:
                student_data["profile_picture"] = filename

        # Create a new block to store the student data on the student blockchain
        new_block = Block(
            index=len(student_blockchain.chain),
            student_data=student_data,
            previous_hash=student_blockchain.get_latest_block().hash if student_blockchain.chain else '0'
        )
        student_blockchain.create_block(previous_hash=new_block.previous_hash, data=new_block.student_data)


        # Display or save the secret key securely
        print(f"Secret Key for {student_data['name']}: {student_data['secret_key']}")

        # Send email to the student with the secret key
        subject = 'Your Student Information and Secret Key'
        body = (f"Hello {student_data['name']},\n\n"
                f"Your student details have been successfully added to the system.\n"
                f"Here is your secret key: {student_data['secret_key']}\n"
                f"Keep it safe as you will need it to access your information.\n\n"
                f"Best regards,\nAdmin Team")
        send_email(student_data['email'], subject, body)

        return jsonify({"message": "Student added successfully!", "secret_key": student_data['secret_key']}), 200

    return render_template('add_student.html')


# Mock function to retrieve staff details
def get_staff_details_by_email(email):
    for block in staff_blockchain.chain:
        if block.staff_data and block.staff_data.get('email') == email:
            return block.staff_data
    return None

# Route to display login page
import logging

logging.basicConfig(level=logging.INFO)



# Staff dashboard
@app.route('/staff_dashboard', methods=['GET', 'POST'])
def staff_dashboard():
    if not session.get('staff_logged_in'):
        flash("Please log in first.", "warning")
        return redirect(url_for('staff_login'))

    current_date = datetime.now().strftime('%Y-%m-%d')  # Current date in YYYY-MM-DD format

    if request.method == 'POST':
        assignment_data = {
            "branch": request.form.get('branch'),
            "subject": request.form.get('subject'),
            "work": request.form.get('work'),
            "due_date": request.form.get('due_date'),
            "assigned_by": "Placeholder Staff"  # Temporarily use a placeholder value
        }

        # Validate that the due date is provided and is after today's date
        if not assignment_data["due_date"]:
            flash("Due date is required!", "danger")
            return redirect(url_for('staff_dashboard'))

        if assignment_data["due_date"] <= current_date:
            flash("Due date must be after today's date!", "danger")
            return redirect(url_for('staff_dashboard'))

        # Process and create blockchain entry as before
        assignment_str = f"{assignment_data['branch']}{assignment_data['subject']}{assignment_data['due_date']}"
        assignment_hash = hashlib.sha256(assignment_str.encode()).hexdigest()
        print(f"Generated Assignment Hash: {assignment_hash}")

        # Add the hash to the assignment data
        assignment_data["hash"] = assignment_hash

        new_block = Block(
            index=len(assignment_blockchain.chain),
            previous_hash=assignment_blockchain.get_latest_block().hash if assignment_blockchain.chain else '0',
            student_data=None,
            staff_data=assignment_data
        )
        assignment_blockchain.create_block(previous_hash=new_block.previous_hash, data=new_block.staff_data)

        flash(f"Assignment added successfully!", "success")
        return redirect(url_for('staff_dashboard'))

    return render_template('staff_dashboard.html', assignment_blockchain=assignment_blockchain, current_date=current_date)

# Route to view all students
@app.route('/view_students')
def view_students():
    if not session.get('logged_in'):
        return redirect(url_for('login'))

    students = []
    for block in student_blockchain.chain:  # Only iterate through the student-specific blockchain
        student_data = block.student_data
        usn_hash = student_data.get("usn_hash", "N/A")  # Use "N/A" if 'usn_hash' is missing

        students.append({
            "index": block.index,
            "usn_hash": usn_hash,  # Display USN hash or "N/A"
            "student_data": student_data,
            "timestamp": block.timestamp,
            "previous_hash": block.previous_hash,
            "current_hash": block.hash
        })

    return render_template('view_students.html', students=students)

# Route to edit student details
@app.route('/edit_student/<int:student_id>', methods=['GET', 'POST'])
def edit_student(student_id):
    if not session.get('logged_in'):
        return redirect(url_for('login'))

    # Find the student block in the student-specific blockchain
    student_block = next((block for block in student_blockchain.chain if block.index == student_id), None)

    if not student_block:
        return "Student not found", 404

    if request.method == 'POST':
        # Get the current student data from the block
        current_student_data = student_block.student_data

        # Get the updated data from the form (only non-empty fields)
        updated_student_data = {
            'name': request.form.get('name') or current_student_data['name'],
            'usn': request.form.get('usn') or current_student_data['usn'],
            'course': request.form.get('course') or current_student_data['course'],
            'institute': request.form.get('institute') or current_student_data['institute'],
            'college': request.form.get('college') or current_student_data['college'],
            'gender': request.form.get('gender') or current_student_data['gender'],
            'dob': request.form.get('dob') or current_student_data['dob'],
            'skills': [skill.strip() for skill in request.form.get('skills').split(',') if skill.strip()]
        }

        # Check for changes
        changes = {}
        for key, new_value in updated_student_data.items():
            if new_value != current_student_data.get(key):
                changes[key] = new_value

        # If no changes were detected
        if not changes:
            return "No changes detected", 400

        # Add a timestamp for the update
        changes['updated_at'] = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

        # Create a new block with the updated data
        new_block = Block(
            index=len(student_blockchain.chain),
            student_data={**current_student_data, **changes},
            previous_hash=student_block.hash
        )

        # Add the new block to the student-specific blockchain
        student_blockchain.add_block(new_block)

        return redirect(url_for('view_students'))

    return render_template('edit_student.html', student=student_block)

@app.route('/student_login', methods=['GET', 'POST'])
def student_login():
    error = None

    if request.method == 'POST':
        usn = request.form.get('usn')
        secret_key = request.form.get('secret_key')

        # Hash the provided USN to check if it exists in the blockchain
        usn_hash = hashlib.sha256(usn.encode()).hexdigest()

        # Search for the student in the student-specific blockchain by the USN hash
        student_block = next((block for block in student_blockchain.chain if block.student_data.get('usn_hash') == usn_hash), None)

        if student_block:
            # Check if the provided secret key matches the stored one
            stored_secret_key = student_block.student_data.get('secret_key')
            if secret_key == stored_secret_key:
                # Successful login
                session['student_logged_in'] = True
                session['student_usn'] = usn
                return redirect(url_for('student_dashboard'))
            else:
                error = 'Invalid secret key'
        else:
            error = 'Student with this USN not found'

    return render_template('student_login.html', error=error)

# Route for student dashboard after successful login
@app.route('/student_dashboard')
def student_dashboard():
    if not session.get('student_logged_in'):
        return redirect(url_for('student_login'))

    # Student dashboard logic here (e.g., show student details, etc.)
    return render_template('student_dashboard.html', usn=session.get('student_usn'))
@app.route('/generate_qr/<usn>')
def generate_qr(usn):
    # Hash the USN
    usn_hash = hashlib.sha256(usn.encode()).hexdigest()

    # Create the QR code data with the hashed USN in the URL
    qr_data = f"{request.host_url}add_certificates/{usn_hash}"
    qr = qrcode.make(qr_data)

    # Save the QR code to a BytesIO object
    img_io = io.BytesIO()
    qr.save(img_io, 'PNG')  
    img_io.seek(0)

    # Send the QR code image as a downloadable file
    return send_file(img_io, mimetype='image/png', as_attachment=True, download_name=f"{usn}_qr_code.png")


@app.route('/add_certificates/<usn_hash>', methods=['GET', 'POST'])
def add_certificates(usn_hash):
    # Find the student block by USN hash in the student-specific blockchain
    student_block = next((block for block in student_blockchain.chain if block.student_data.get('usn_hash') == usn_hash), None)

    if not student_block:
        return "Student not found", 404

    if request.method == 'POST':
        # Ensure the 'certificates' attribute exists
        if 'certificates' not in student_block.student_data:
            student_block.student_data['certificates'] = []

        # Check if the student has already added 10 certificates
        if len(student_block.student_data['certificates']) >= 10:
            return "Cannot add more than 10 certificates", 400

        # Get the certificate image from the request
        certificate_image = request.files.get('certificate_image')

        # Save the certificate image
        if certificate_image:
            file_hash, filename = save_file_and_get_hash(certificate_image)
            if file_hash:
                # Update the existing block's student data with the new certificate
                student_block.student_data['certificates'].append(filename)

                # Redirect to refresh the page
                return redirect(url_for('add_certificates', usn_hash=usn_hash))

    # Render the add_certificates page with the updated certificates
    return render_template(
        'add_certificates.html',
        usn=usn_hash,
        certificates=student_block.student_data.get('certificates', [])
    )

@app.route('/dashboard')
def dashboard():
    # Your logic for the dashboard
    return render_template('dashboard.html')  # or redirect to your dashboard

def get_student_details(usn):
    # Hash the provided USN to search for it in the student blockchain
    usn_hash = hashlib.sha256(usn.encode()).hexdigest()

    # Retrieve student data from the student blockchain
    student_data = next((block.student_data for block in student_blockchain.chain if block.student_data.get('usn_hash') == usn_hash), None)

    if student_data is None:
        return None  # Return None if no student is found
    return student_data


@app.route('/view_details/<usn>')
def view_details(usn):
    print(f"Received request for USN: {usn}")  # Log the incoming USN

    # Hash the provided USN to search in the student blockchain
    usn_hash = hashlib.sha256(usn.encode()).hexdigest()

    # Search for the student in the student blockchain
    student_details = next((block.student_data for block in student_blockchain.chain if block.student_data.get('usn_hash') == usn_hash), None)

    if student_details is None:
        print("No student found with the provided USN.")  # Log the not found case
        return "Student not found", 404  # Handle case when student isn't found

    student_hash = usn_hash  # Since it's already hashed
    return render_template('view_details.html', student_details=student_details, hash_usn=student_hash)

@app.route('/profile')
def profile():
    if not session.get('logged_in'):
        return redirect(url_for('login'))

    # Filter out the genesis block (assuming genesis block has index 0)
    students = [
        {
            "index": block.index,
            "name": block.student_data.get("name", "Unknown"),  # Safely access name
            "usn_hash": block.student_data.get("usn_hash", "N/A")  # Safely access usn_hash
        }
        for block in student_blockchain.chain if block.index != 0  # Exclude genesis block
    ]

    return render_template('profile.html', students=students)

@app.route('/view_student_details/<usn_hash>')
def view_student_details(usn_hash):
    # Find the student by their USN hash in the student blockchain
    student_block = next((block for block in student_blockchain.chain if block.student_data.get('usn_hash') == usn_hash), None)

    if not student_block:
        return "Student not found", 404

    student_data = student_block.student_data
    certificates = student_data.get('certificates', [])

    return render_template('student_details.html', student_data=student_data, certificates=certificates)

# Route to log out the student
@app.route('/student_logout')
def student_logout():
    session.pop('student_logged_in', None)
    session.pop('student_usn', None)
    return redirect(url_for('student_login'))

if __name__ == '__main__':
    with app.app_context():
        db.create_all()  # Ensures database tables are created
    app.run(debug=True)
