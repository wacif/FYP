from flask import Flask, render_template, request, redirect, url_for, flash, session
from functools import wraps
import os
from datetime import timedelta
from werkzeug.utils import secure_filename
import pandas as pd
import numpy as np
import uuid
import json

app = Flask(__name__)
app.config['SECRET_KEY'] = 'your-secure-secret-key-here'
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(days=7)
app.config['UPLOAD_FOLDER'] = 'uploads'
app.config['MAX_CONTENT_LENGTH'] = 50 * 1024 * 1024  # 50MB max file size
app.config['ALLOWED_EXTENSIONS'] = {'csv', 'pcap'}

# Create uploads directory if it doesn't exist
if not os.path.exists(app.config['UPLOAD_FOLDER']):
    os.makedirs(app.config['UPLOAD_FOLDER'])

# Simple dictionary to store test user
test_user = {
    'email': 'test@example.com',
    'password': 'test123'
}

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in app.config['ALLOWED_EXTENSIONS']

def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user' not in session:
            flash('Please login first', 'error')
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function

@app.route('/login', methods=['GET', 'POST'])
def login():
    if 'user' in session:
        return redirect(url_for('home'))
        
    if request.method == 'POST':
        email = request.form.get('email')
        password = request.form.get('password')
        remember = request.form.get('remember')
        
        if email == test_user['email'] and password == test_user['password']:
            session['user'] = email
            if remember:
                session.permanent = True
            flash('Login successful!', 'success')
            return redirect(url_for('home'))
        
        flash('Invalid email or password', 'error')
        return redirect(url_for('login'))
    
    return render_template('login.html')

@app.route('/logout')
def logout():
    session.pop('user', None)
    session.permanent = False
    flash('Logged out successfully', 'success')
    return redirect(url_for('login'))

@app.route('/')
@login_required
def home():
    return render_template('home.html')

@app.route('/upload', methods=['GET', 'POST'])
@login_required
def upload():
    if request.method == 'POST':
        if 'file' not in request.files:
            flash('No file part', 'danger')
            return redirect(request.url)
            
        file = request.files['file']
        if file.filename == '':
            flash('No selected file', 'danger')
            return redirect(request.url)
            
        if file and allowed_file(file.filename):
            try:
                filename = str(uuid.uuid4()) + os.path.splitext(file.filename)[1]
                file_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
                file.save(file_path)
                
                if file.filename.endswith('.csv'):
                    results, malicious_count = analyze_csv(file_path)
                    session['results'] = results
                    session['malicious_count'] = malicious_count
                    return redirect(url_for('results'))
                elif file.filename.endswith('.pcap'):
                    flash('PCAP analysis is not implemented in this demo', 'warning')
                    return redirect(request.url)
            except Exception as e:
                flash(f'Error processing file: {str(e)}', 'danger')
                return redirect(request.url)
        else:
            flash('Invalid file type. Only CSV or PCAP files are allowed.', 'danger')
            return redirect(request.url)
            
    return render_template('upload.html')

@app.route('/results')
@login_required
def results():
    if 'results' not in session or 'malicious_count' not in session:
        flash('No analysis results available. Please upload a file first.', 'warning')
        return redirect(url_for('upload'))
    
    results = session['results']
    malicious_count = session['malicious_count']
    
    return render_template('results.html', results=results, malicious_count=malicious_count)

@app.route('/documentation')
def documentation():
    return render_template('documentation.html')

@app.route('/contact')
def contact():
    return render_template('contact.html')

@app.errorhandler(404)
def not_found_error(error):
    return render_template('404.html'), 404

@app.errorhandler(500)
def internal_error(error):
    return render_template('500.html'), 500

def analyze_csv(file_path):
    """Analyze the uploaded CSV file and return results"""
    # Read the CSV file
    df = pd.read_csv(file_path)
    
    # Basic statistics
    total_packets = len(df)
    
    # Identify potentially malicious packets (simplified for demo)
    # In a real application, this would use the ML models
    df['prediction'] = 'Benign'
    df['confidence'] = 0.0
    
    # Flag repeated SYN packets to the same destination as potential port scans
    syn_packets = df[df['flags'] == 'SYN']
    syn_counts = syn_packets.groupby(['src_ip', 'dst_ip']).size().reset_index(name='count')
    port_scanners = syn_counts[syn_counts['count'] > 1]['src_ip'].tolist()
    
    # Flag external IPs targeting common service ports
    service_ports = [22, 23, 3389, 445]
    suspicious_ports = df[(df['dst_port'].isin(service_ports)) & 
                          (~df['src_ip'].str.startswith('192.168.')) & 
                          (df['flags'] == 'SYN')]
    
    # Mark suspicious packets
    for idx, row in df.iterrows():
        # Port scanning detection
        if row['src_ip'] in port_scanners and row['flags'] == 'SYN':
            df.at[idx, 'prediction'] = 'Malicious'
            df.at[idx, 'confidence'] = np.random.uniform(95.0, 99.9)
        
        # External IPs targeting service ports
        elif row['src_ip'] in suspicious_ports['src_ip'].values and row['flags'] == 'SYN':
            df.at[idx, 'prediction'] = 'Malicious'
            df.at[idx, 'confidence'] = np.random.uniform(97.0, 99.5)
        
        # Repeated connection attempts to SMB port
        elif row['dst_port'] == 445 and row['flags'] == 'SYN':
            df.at[idx, 'prediction'] = 'Malicious'
            df.at[idx, 'confidence'] = np.random.uniform(96.0, 98.5)
        
        # Set confidence for benign packets
        else:
            df.at[idx, 'confidence'] = np.random.uniform(90.0, 97.0)
    
    # Format results for the template
    results = []
    for idx, row in df.iterrows():
        results.append({
            'timestamp': row['timestamp'],
            'src_ip': row['src_ip'],
            'dst_ip': row['dst_ip'],
            'protocol': row['protocol'],
            'size': row['packet_size'],
            'prediction': row['prediction'],
            'confidence': round(row['confidence'], 1)
        })
    
    # Count malicious packets
    malicious_count = sum(1 for r in results if r['prediction'] == 'Malicious')
    
    return results, malicious_count

if __name__ == '__main__':
    app.run(debug=True)