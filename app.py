import os
import sqlite3
import uuid
from flask import Flask, render_template, request, url_for, g, jsonify, redirect, flash, send_from_directory, abort
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
from datetime import datetime, timedelta
import logging

# --- Setup ---
logging.basicConfig(level=logging.INFO)
BASE_DIR = os.path.abspath(os.path.dirname(__file__))
DATABASE = os.path.join(BASE_DIR, 'users.db')
USER_FILES_DIR = os.path.join(BASE_DIR, 'user_files')

app = Flask(__name__)
app.config['SECRET_KEY'] = 'medscan-5.0-the-final-frontier'
app.config['USER_FILES_DIR'] = USER_FILES_DIR

def get_db():
    if 'db' not in g:
        g.db = sqlite3.connect(DATABASE)
        g.db.row_factory = sqlite3.Row
    return g.db

@app.teardown_appcontext
def close_db(exception):
    db = g.pop('db', None)
    if db is not None:
        db.close()

def log_action(admin_id, action, target_id=None):
    get_db().execute('INSERT INTO audit_log (admin_id, action, target_id) VALUES (?, ?, ?)', (admin_id, action, target_id))
    get_db().commit()

def init_db():
    with app.app_context():
        db = get_db()
        for table in ['sharing_links', 'payments', 'invoice_items', 'appointments', 'medical_records', 'visits', 'scanners', 'orders', 'users', 'hospitals', 'audit_log']:
            db.execute(f'DROP TABLE IF EXISTS {table};')
        
        db.execute('''
            CREATE TABLE users (
                id INTEGER PRIMARY KEY AUTOINCREMENT, username TEXT NOT NULL UNIQUE, password TEXT NOT NULL,
                first_name TEXT NOT NULL, last_name TEXT NOT NULL, email TEXT NOT NULL UNIQUE,
                role TEXT NOT NULL, uid TEXT UNIQUE, shipping_address TEXT, hospital_id INTEGER,
                specialization TEXT, degree TEXT, office_floor TEXT, status TEXT NOT NULL DEFAULT 'Active',
                is_superadmin BOOLEAN NOT NULL DEFAULT 0
            );''')
        db.execute('INSERT INTO users (username, password, first_name, last_name, role, email, is_superadmin) VALUES (?, ?, ?, ?, ?, ?, ?)',
                   ('admin', generate_password_hash('admin'), 'Admin', 'User', 'admin', 'admin@medscan.com', 1))

        db.execute('CREATE TABLE hospitals (id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT NOT NULL UNIQUE, address TEXT NOT NULL);')
        db.execute('''
            CREATE TABLE orders (id INTEGER PRIMARY KEY AUTOINCREMENT, user_id INTEGER, hospital_id INTEGER,
                order_type TEXT NOT NULL, status TEXT NOT NULL DEFAULT 'Pending Fulfillment',
                created_at DATETIME DEFAULT CURRENT_TIMESTAMP);''')
        db.execute('''
            CREATE TABLE scanners (id INTEGER PRIMARY KEY AUTOINCREMENT, hospital_id INTEGER NOT NULL, name TEXT, 
                activation_code TEXT UNIQUE NOT NULL, status TEXT NOT NULL DEFAULT 'Pending Activation');''')
        db.execute('''
            CREATE TABLE visits (id INTEGER PRIMARY KEY AUTOINCREMENT, patient_id INTEGER, hospital_id INTEGER, 
                doctor_id INTEGER, visit_timestamp DATETIME DEFAULT CURRENT_TIMESTAMP);''')
        db.execute('''
            CREATE TABLE medical_records (id INTEGER PRIMARY KEY AUTOINCREMENT, visit_id INTEGER, filename TEXT, 
                category TEXT, filepath TEXT);''')
        db.execute('''
            CREATE TABLE payments (id INTEGER PRIMARY KEY AUTOINCREMENT, visit_id INTEGER, total_amount REAL, 
                status TEXT NOT NULL DEFAULT 'Due', bill_date DATE);''')
        db.execute('''
            CREATE TABLE invoice_items (id INTEGER PRIMARY KEY AUTOINCREMENT, payment_id INTEGER, 
                description TEXT, amount REAL);''')
        db.execute('''
            CREATE TABLE audit_log (id INTEGER PRIMARY KEY AUTOINCREMENT, admin_id INTEGER, action TEXT, 
                target_id INTEGER, timestamp DATETIME DEFAULT CURRENT_TIMESTAMP);''')
        db.execute('''
            CREATE TABLE appointments (id INTEGER PRIMARY KEY AUTOINCREMENT, patient_id INTEGER NOT NULL, doctor_id INTEGER NOT NULL,
                appointment_datetime DATETIME NOT NULL);''')
        db.execute('''
            CREATE TABLE sharing_links (id INTEGER PRIMARY KEY AUTOINCREMENT, patient_id INTEGER NOT NULL, token TEXT NOT NULL UNIQUE,
                record_ids TEXT NOT NULL, expires_at DATETIME NOT NULL);''')
        db.commit()

# --- Core Routes ---
@app.route('/')
def index(): return render_template('index.html')

@app.route('/login', methods=['POST'])
def login():
    user = get_db().execute('SELECT * FROM users WHERE username = ?', (request.form['username'],)).fetchone()
    if user and check_password_hash(user['password'], request.form['password']):
        role_map = {'admin': 'admin_dashboard', 'doctor': 'doctor_dashboard', 'patient': 'patient_dashboard'}
        url = url_for(role_map[user['role']], user_id=user['id'])
        return jsonify({'success': True, 'dashboard_url': url})
    return jsonify({'success': False, 'message': 'Invalid credentials.'})

@app.route('/register_page')
def register_page():
    return render_template('register.html', hospitals=get_db().execute('SELECT id, name FROM hospitals ORDER BY name').fetchall())

@app.route('/register', methods=['POST'])
def register():
    db, form = get_db(), request.form
    role, password = form['role'], generate_password_hash(form['password'])
    try:
        if role == 'patient':
            cursor = db.execute('INSERT INTO users (username, password, first_name, last_name, email, shipping_address, role, status) VALUES (?, ?, ?, ?, ?, ?, ?, ?)',
                       (form['username'], password, form['first_name'], form['last_name'], form['email'], form['shipping_address'], 'patient', 'Pending Activation'))
            db.execute('INSERT INTO orders (user_id, order_type, status, created_at) VALUES (?, ?, ?, ?)', (cursor.lastrowid, 'patient_kit', 'Pending Fulfillment', datetime.now()))
        else:
            hospital_id = form.get('hospital_id')
            if hospital_id == 'new':
                cursor = db.execute('INSERT INTO hospitals (name, address) VALUES (?, ?)', (form['new_hospital_name'], form['new_hospital_address']))
                hospital_id = cursor.lastrowid
            db.execute('INSERT INTO users (username, password, first_name, last_name, email, hospital_id, role, specialization, degree, office_floor) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)',
                       (form['username'], password, form['first_name'], form['last_name'], form['email'], hospital_id, 'doctor', form['specialization'], form['degree'], form['office_floor']))
            if 'order_scanner' in form:
                db.execute('INSERT INTO orders (hospital_id, order_type, status, created_at) VALUES (?, ?, ?, ?)', (hospital_id, 'scanner_kit', 'Pending Fulfillment', datetime.now()))
        db.commit()
    except sqlite3.IntegrityError:
        return jsonify({'success': False, 'message': 'Username or Email already exists.'})
    return jsonify({'success': True, 'login_url': url_for('index')})

# --- Admin Routes ---
@app.route('/admin/dashboard/<int:user_id>')
def admin_dashboard(user_id):
    db = get_db()
    admin = db.execute("SELECT * FROM users WHERE id = ?", (user_id,)).fetchone()
    orders = db.execute('''
        SELECT o.*, u.id as user_id, u.first_name, u.last_name, u.shipping_address, h.id as hospital_id, h.name as hospital_name, h.address as hospital_address
        FROM orders o LEFT JOIN users u ON o.user_id = u.id LEFT JOIN hospitals h ON o.hospital_id = h.id
        WHERE o.status = 'Pending Fulfillment' ORDER BY o.created_at ASC
    ''').fetchall()
    return render_template('admin_dashboard.html', orders=orders, admin=admin)

@app.route('/admin/provision_card/<int:admin_id>', methods=['POST'])
def provision_card(admin_id):
    db = get_db()
    db.execute('UPDATE users SET uid = ? WHERE id = ?', (request.form['card_uid'], request.form['user_id']))
    db.execute("UPDATE orders SET status = 'Shipped' WHERE id = ?", (request.form['order_id'],))
    log_action(admin_id, f"Provisioned card for patient ID {request.form['user_id']}", request.form['user_id'])
    return redirect(url_for('admin_dashboard', user_id=admin_id))

@app.route('/admin/provision_scanner/<int:admin_id>', methods=['POST'])
def provision_scanner(admin_id):
    db = get_db()
    db.execute('INSERT INTO scanners (hospital_id, name, activation_code, status) VALUES (?, ?, ?, ?)', 
               (request.form['hospital_id'], 'MedScan Scanner', request.form['activation_code'], 'Pending Activation'))
    db.execute("UPDATE orders SET status = 'Shipped' WHERE id = ?", (request.form['order_id'],))
    log_action(admin_id, f"Provisioned scanner for hospital ID {request.form['hospital_id']}", request.form['hospital_id'])
    return redirect(url_for('admin_dashboard', user_id=admin_id))

@app.route('/admin/<int:user_id>/manage_admins', methods=['GET', 'POST'])
def manage_admins(user_id):
    db = get_db()
    current_admin = db.execute('SELECT * FROM users WHERE id = ?', (user_id,)).fetchone()
    if not current_admin['is_superadmin']: abort(403)
        
    if request.method == 'POST':
        form = request.form
        db.execute('INSERT INTO users (username, password, first_name, last_name, role, email, is_superadmin) VALUES (?, ?, ?, ?, ?, ?, ?)',
                   (form['username'], generate_password_hash(form['password']), form['first_name'], form['last_name'], 'admin', form['email'], form.get('is_superadmin') == 'on'))
        db.commit()
        log_action(user_id, f"Added new admin: {form['username']}")
        flash("New admin user created.", "success")
        return redirect(url_for('manage_admins', user_id=user_id))
        
    admins = db.execute("SELECT * FROM users WHERE role = 'admin'").fetchall()
    return render_template('admin_manage_users.html', admins=admins, admin=current_admin)

@app.route('/admin/<int:user_id>/history')
def admin_audit_log(user_id):
    db = get_db()
    admin = db.execute("SELECT * FROM users WHERE id = ?", (user_id,)).fetchone()
    logs = db.execute("SELECT a.*, u.username as admin_username FROM audit_log a JOIN users u ON a.admin_id = u.id ORDER BY a.timestamp DESC").fetchall()
    return render_template('admin_audit_log.html', logs=logs, admin=admin)

# --- Patient Routes ---
@app.route('/patient/dashboard/<int:user_id>')
def patient_dashboard(user_id):
    db = get_db()
    patient = db.execute('SELECT * FROM users WHERE id = ?', (user_id,)).fetchone()
    if patient['status'] == 'Pending Activation':
        order = db.execute("SELECT status FROM orders WHERE user_id = ? ORDER BY id DESC", (user_id,)).fetchone()
        return render_template('patient_onboarding.html', patient=patient, order_status=order['status'])
    
    hospitals = db.execute('SELECT DISTINCT h.* FROM hospitals h JOIN visits v ON h.id = v.hospital_id WHERE v.patient_id = ?', (user_id,)).fetchall()
    appointments = db.execute('SELECT a.*, u.first_name, u.last_name, h.name as hospital_name FROM appointments a JOIN users u ON a.doctor_id = u.id JOIN hospitals h ON u.hospital_id = h.id WHERE a.patient_id = ? AND a.appointment_datetime > ? ORDER BY a.appointment_datetime ASC', (user_id, datetime.now())).fetchall()
    return render_template('patient_dashboard.html', patient=patient, hospitals=hospitals, appointments=appointments)

@app.route('/patient/profile/<int:user_id>', methods=['GET', 'POST'])
def patient_profile(user_id):
    db = get_db()
    if request.method == 'POST':
        db.execute("UPDATE users SET uid = NULL, status = 'Pending Activation' WHERE id = ?", (user_id,))
        db.execute("INSERT INTO orders (user_id, order_type, status, created_at) VALUES (?, ?, ?, ?)", (user_id, 'patient_kit', 'Pending Fulfillment', datetime.now()))
        db.commit()
        flash("Your old card has been deactivated. A new card is on the way.", "success")
        return redirect(url_for('patient_dashboard', user_id=user_id))
    
    patient = db.execute('SELECT * FROM users WHERE id = ?', (user_id,)).fetchone()
    return render_template('patient_profile.html', patient=patient)

@app.route('/patient/billing/<int:user_id>')
def patient_billing(user_id):
    db = get_db()
    patient = db.execute('SELECT * FROM users WHERE id = ?', (user_id,)).fetchone()
    payments = db.execute('''
        SELECT p.*, v.visit_timestamp, h.name as hospital_name FROM payments p
        JOIN visits v ON p.visit_id = v.id JOIN hospitals h ON v.hospital_id = h.id
        WHERE v.patient_id = ? ORDER BY p.bill_date DESC
    ''', (user_id,)).fetchall()
    return render_template('patient_billing.html', patient=patient, payments=payments)

@app.route('/patient/invoice/<int:user_id>/<int:payment_id>')
def patient_invoice_view(user_id, payment_id):
    db = get_db()
    patient = db.execute("SELECT * FROM users WHERE id = ?", (user_id,)).fetchone()
    payment = db.execute("SELECT * FROM payments WHERE id = ?", (payment_id,)).fetchone()
    visit = db.execute("SELECT * FROM visits WHERE id = ?", (payment['visit_id'],)).fetchone()
    doctor = db.execute("SELECT * FROM users WHERE id = ?", (visit['doctor_id'],)).fetchone()
    hospital = db.execute("SELECT * FROM hospitals WHERE id = ?", (visit['hospital_id'],)).fetchone()
    items = db.execute("SELECT * FROM invoice_items WHERE payment_id = ?", (payment_id,)).fetchall()
    return render_template('patient_invoice_view.html', patient=patient, payment=payment, visit=visit, doctor=doctor, hospital=hospital, items=items)

@app.route('/patient/delete_record/<int:record_id>', methods=['POST'])
def delete_record(record_id):
    db = get_db()
    record = db.execute('SELECT mr.filepath, v.patient_id, v.hospital_id FROM medical_records mr JOIN visits v on mr.visit_id = v.id WHERE mr.id = ?', (record_id,)).fetchone()
    if record and os.path.exists(record['filepath']):
        os.remove(record['filepath'])
        db.execute('DELETE FROM medical_records WHERE id = ?', (record_id,))
        db.commit()
        flash("Record deleted successfully.", "success")
        return redirect(url_for('patient_hospital_detail', user_id=record['patient_id'], hospital_id=record['hospital_id']))
    flash("Could not delete record.", "error")
    return redirect(request.referrer)

@app.route('/patient/<int:user_id>/hospital/<int:hospital_id>')
def patient_hospital_detail(user_id, hospital_id):
    db = get_db()
    patient = db.execute('SELECT * FROM users WHERE id = ?', (user_id,)).fetchone()
    hospital = db.execute('SELECT * FROM hospitals WHERE id = ?', (hospital_id,)).fetchone()
    visits = db.execute('SELECT v.*, u.first_name, u.last_name FROM visits v LEFT JOIN users u ON v.doctor_id = u.id WHERE v.patient_id = ? AND v.hospital_id = ? ORDER BY v.visit_timestamp DESC', (user_id, hospital_id)).fetchall()
    records = {v['id']: db.execute('SELECT * FROM medical_records WHERE visit_id = ?', (v['id'],)).fetchall() for v in visits}
    return render_template('patient_hospital_detail.html', patient=patient, hospital=hospital, visits=visits, records=records)

# --- Doctor Routes ---
@app.route('/doctor/dashboard/<int:user_id>')
def doctor_dashboard(user_id):
    db = get_db()
    doctor = db.execute('SELECT u.*, h.name as hospital_name FROM users u JOIN hospitals h ON u.hospital_id = h.id WHERE u.id = ?', (user_id,)).fetchone()
    if not doctor: return "Doctor not found", 404
    patients = db.execute('SELECT u.*, MAX(v.visit_timestamp) as last_visit FROM users u JOIN visits v ON u.id = v.patient_id WHERE v.hospital_id = ? GROUP BY u.id ORDER BY last_visit DESC', (doctor['hospital_id'],)).fetchall()
    return render_template('doctor_dashboard.html', doctor=doctor, patients=patients)

@app.route('/doctor/profile/<int:user_id>', methods=['GET', 'POST'])
def doctor_profile(user_id):
    db = get_db()
    if request.method == 'POST':
        form = request.form
        db.execute('UPDATE users SET first_name=?, last_name=?, email=?, specialization=?, degree=?, office_floor=? WHERE id = ?',
                   (form['first_name'], form['last_name'], form['email'], form['specialization'], form['degree'], form['office_floor'], user_id))
        db.commit()
        flash("Profile updated successfully!", "success")
        return redirect(url_for('doctor_profile', user_id=user_id))

    doctor = db.execute('SELECT u.*, h.name as hospital_name FROM users u JOIN hospitals h ON u.hospital_id = h.id WHERE u.id = ?', (user_id,)).fetchone()
    return render_template('doctor_profile.html', doctor=doctor)

@app.route('/doctor/<int:user_id>/patient/<int:patient_id>')
def doctor_patient_view(user_id, patient_id):
    db = get_db()
    doctor = db.execute('SELECT * FROM users WHERE id=?', (user_id,)).fetchone()
    patient = db.execute('SELECT * FROM users WHERE id=?', (patient_id,)).fetchone()
    visits = db.execute('SELECT v.*, p.id as payment_id, p.status as payment_status, p.total_amount FROM visits v LEFT JOIN payments p ON v.id = p.visit_id WHERE v.patient_id = ? AND v.hospital_id = ? ORDER BY v.visit_timestamp DESC', (patient_id, doctor['hospital_id'])).fetchall()
    records = {v['id']: db.execute('SELECT * FROM medical_records WHERE visit_id = ?', (v['id'],)).fetchall() for v in visits}
    payments = db.execute('SELECT p.*, v.visit_timestamp FROM payments p JOIN visits v ON p.visit_id = v.id WHERE v.patient_id = ? AND v.hospital_id = ? ORDER BY p.bill_date DESC', (patient_id, doctor['hospital_id'])).fetchall()
    return render_template('doctor_patient_view.html', doctor=doctor, patient=patient, visits=visits, records=records, payments=payments)

@app.route('/doctor/<int:user_id>/upload_record', methods=['POST'])
def upload_record(user_id):
    db, form = get_db(), request.form
    file = request.files.get('file')
    visit_id, category, patient_id = form.get('visit_id'), form.get('category'), form.get('patient_id')

    if not all([file, visit_id, category, patient_id]):
        flash("Missing data in upload form.", "error")
        return redirect(url_for('doctor_patient_view', user_id=user_id, patient_id=patient_id))

    if not os.path.exists(app.config['USER_FILES_DIR']): os.makedirs(app.config['USER_FILES_DIR'])
    patient_dir = os.path.join(app.config['USER_FILES_DIR'], str(patient_id))
    if not os.path.exists(patient_dir): os.makedirs(patient_dir)
    
    filename = secure_filename(file.filename)
    filepath = os.path.join(patient_dir, filename)
    file.save(filepath)

    db.execute('INSERT INTO medical_records (visit_id, filename, category, filepath) VALUES (?, ?, ?, ?)',
               (visit_id, filename, category, filepath))
    db.commit()
    flash("Record uploaded successfully.", "success")
    return redirect(url_for('doctor_patient_view', user_id=user_id, patient_id=patient_id))

@app.route('/doctor/create_invoice/<int:user_id>', methods=['POST'])
def create_invoice(user_id):
    db, form = get_db(), request.form
    visit_id, patient_id = form.get('visit_id'), form.get('patient_id')
    descriptions, amounts = form.getlist('description[]'), form.getlist('amount[]')
    
    total_amount = sum(float(a) for a in amounts if a)
    
    cursor = db.execute('INSERT INTO payments (visit_id, total_amount, status, bill_date) VALUES (?, ?, ?, ?)',
                      (visit_id, total_amount, 'Due', datetime.now().date()))
    payment_id = cursor.lastrowid
    
    for desc, amt in zip(descriptions, amounts):
        if desc and amt:
            db.execute('INSERT INTO invoice_items (payment_id, description, amount) VALUES (?, ?, ?)',
                       (payment_id, desc, float(amt)))
    db.commit()
    flash("Invoice created successfully.", "success")
    return redirect(url_for('doctor_patient_view', user_id=user_id, patient_id=patient_id))

@app.route('/doctor/mark_paid/<int:user_id>', methods=['POST'])
def mark_paid(user_id):
    db, form = get_db(), request.form
    payment_id, patient_id = form.get('payment_id'), form.get('patient_id')
    db.execute("UPDATE payments SET status = 'Paid' WHERE id = ?", (payment_id,))
    db.commit()
    flash("Invoice marked as paid.", "success")
    return redirect(url_for('doctor_patient_view', user_id=user_id, patient_id=patient_id))

@app.route('/doctor/schedule_appointment/<int:user_id>', methods=['POST'])
def schedule_appointment(user_id):
    db = get_db()
    patient_id, appt_datetime = request.form['patient_id'], request.form['appointment_datetime']
    db.execute('INSERT INTO appointments (patient_id, doctor_id, appointment_datetime) VALUES (?, ?, ?)',
               (patient_id, user_id, appt_datetime))
    db.commit()
    flash("Appointment scheduled successfully.", "success")
    return redirect(url_for('doctor_patient_view', user_id=user_id, patient_id=patient_id))

@app.route('/doctor/settings/<int:user_id>')
def doctor_settings(user_id):
    db = get_db()
    doctor = db.execute('SELECT u.*, h.name as hospital_name FROM users u JOIN hospitals h ON u.hospital_id = h.id WHERE u.id = ?', (user_id,)).fetchone()
    scanners = db.execute("SELECT * FROM scanners WHERE hospital_id = ?", (doctor['hospital_id'],)).fetchall()
    order_pending = db.execute("SELECT * FROM orders WHERE hospital_id = ? AND status = 'Pending Fulfillment'", (doctor['hospital_id'],)).fetchone()
    return render_template('doctor_settings.html', doctor=doctor, scanners=scanners, order_pending=order_pending)

@app.route('/doctor/order_scanner/<int:user_id>', methods=['POST'])
def order_scanner(user_id):
    db = get_db()
    doctor = db.execute('SELECT hospital_id FROM users WHERE id = ?', (user_id,)).fetchone()
    existing_order = db.execute("SELECT id FROM orders WHERE hospital_id = ? AND status = 'Pending Fulfillment'", (doctor['hospital_id'],)).fetchone()
    if not existing_order:
        db.execute('INSERT INTO orders (hospital_id, order_type, status, created_at) VALUES (?, ?, ?, ?)', (doctor['hospital_id'], 'scanner_kit', 'Pending Fulfillment', datetime.now()))
        db.commit()
        flash("New scanner ordered successfully! An admin will provision it shortly.", "success")
    else:
        flash("You already have a scanner order pending fulfillment.", "info")
    return redirect(url_for('doctor_settings', user_id=user_id))

@app.route('/doctor/activate_scanner/<int:user_id>', methods=['POST'])
def activate_scanner(user_id):
    db = get_db()
    cursor = db.execute("UPDATE scanners SET status = 'Active' WHERE activation_code = ? AND hospital_id = ? AND status = 'Pending Activation'", 
                      (request.form['activation_code'], request.form['hospital_id']))
    if cursor.rowcount > 0:
        db.commit()
        log_action(user_id, f"Activated scanner {request.form['activation_code']}")
        flash("Scanner activated successfully!", "success")
    else:
        db.rollback()
        flash("Activation failed. The code is incorrect or the scanner is already active.", "error")
    return redirect(url_for('doctor_settings', user_id=user_id))
    
# --- Scan Route ---
@app.route('/scan/<activation_code>/<patient_uid>')
def handle_scan(activation_code, patient_uid):
    db = get_db()
    scanner = db.execute("SELECT hospital_id FROM scanners WHERE activation_code = ? AND status = 'Active'", (activation_code,)).fetchone()
    patient = db.execute("SELECT id, status FROM users WHERE uid = ? AND role = 'patient'", (patient_uid,)).fetchone()
    
    if scanner and patient:
        cursor = db.execute('INSERT INTO visits (patient_id, hospital_id) VALUES (?, ?)', (patient['id'], scanner['hospital_id']))
        if patient['status'] == 'Pending Activation':
            db.execute("UPDATE users SET status = 'Active' WHERE id = ?", (patient['id'],))
            db.execute("UPDATE orders SET status = 'Delivered & Active' WHERE user_id = ? AND order_type = 'patient_kit'", (patient['id'],))
        db.commit()
        return jsonify(status="ok", message=f"Visit created for patient ID {patient['id']}.")
    
    logging.warning(f"Scan failed. Scanner found: {bool(scanner)}. Patient found: {bool(patient)}.")
    return jsonify(status="error", message="Invalid or inactive scanner, or invalid patient UID."), 404

# --- File Viewing Route ---
@app.route('/view_file/<int:record_id>')
def view_file_route(record_id):
    record = get_db().execute('SELECT filepath FROM medical_records WHERE id = ?', (record_id,)).fetchone()
    if record and record['filepath'] and os.path.exists(record['filepath']):
        return send_from_directory(os.path.dirname(record['filepath']), os.path.basename(record['filepath']))
    return "File not found or path is missing.", 404

# --- Sharing Routes ---
@app.route('/patient/generate_share_link/<int:user_id>', methods=['POST'])
def generate_share_link(user_id):
    record_ids = request.form.getlist('record_ids')
    if not record_ids:
        return jsonify({'success': False, 'message': 'No records selected.'})
    
    db = get_db()
    token = str(uuid.uuid4())
    expires_at = datetime.now() + timedelta(hours=24)
    db.execute('INSERT INTO sharing_links (patient_id, token, record_ids, expires_at) VALUES (?, ?, ?, ?)',
               (user_id, token, ','.join(record_ids), expires_at))
    db.commit()
    
    link = url_for('share_view', token=token, _external=True)
    return jsonify({'success': True, 'link': link})

@app.route('/share/<token>')
def share_view(token):
    link = get_db().execute("SELECT * FROM sharing_links WHERE token = ? AND expires_at > ?", (token, datetime.now())).fetchone()
    if not link:
        return render_template('share_expired.html'), 404
        
    record_ids = tuple(map(int, link['record_ids'].split(',')))
    records_query = f'SELECT mr.*, v.visit_timestamp, h.name as hospital_name FROM medical_records mr JOIN visits v ON mr.visit_id = v.id JOIN hospitals h ON v.hospital_id = h.id WHERE mr.id IN ({",".join("?"*len(record_ids))})'
    records = get_db().execute(records_query, record_ids).fetchall()
    patient = get_db().execute('SELECT first_name, last_name FROM users WHERE id = ?', (link['patient_id'],)).fetchone()
    
    return render_template('share_view.html', records=records, patient=patient, expires_at=link['expires_at'])

if __name__ == '__main__':
    if not os.path.exists(USER_FILES_DIR): os.makedirs(USER_FILES_DIR)
    with app.app_context():
        if not os.path.exists(DATABASE) or not get_db().execute("SELECT name FROM sqlite_master WHERE type='table' AND name='users';").fetchone():
            init_db()
    app.run(host='0.0.0.0', port=5000, debug=True)
