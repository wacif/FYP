from flask import Flask, render_template, request, redirect, url_for, flash, session
from functools import wraps
import os
from datetime import timedelta
from werkzeug.utils import secure_filename
import pandas as pd
import numpy as np
import uuid
import json
from catboost import CatBoostClassifier
from lightgbm import LGBMClassifier
from pytorch_tabnet.tab_model import TabNetClassifier
import joblib
from sklearn.preprocessing import LabelEncoder, StandardScaler
import pickle
import time

app = Flask(__name__)
app.config['SECRET_KEY'] = 'your-secure-secret-key-here'
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(days=7)
app.config['UPLOAD_FOLDER'] = 'uploads'
app.config['MAX_CONTENT_LENGTH'] = 50 * 1024 * 1024  # 50MB max file size
app.config['ALLOWED_EXTENSIONS'] = {'csv', 'pcap'}
app.config['RESULTS_FOLDER'] = 'results'  # Folder to store analysis results

# Model configuration
app.config['MODEL_PATHS'] = {
    'catboost': 'trained_models/catboost_model.cbm',
    'lightgbm': 'trained_models/lightgbm_model.pkl',  # Full model, not just booster
    'tabnet': 'trained_models/tabnet_model.zip'
}

# Create required directories
for folder in [app.config['UPLOAD_FOLDER'], app.config['RESULTS_FOLDER']]:
    if not os.path.exists(folder):
        os.makedirs(folder)

# Simple dictionary to store test user
test_user = {
    'email': 'test@example.com',
    'password': 'test123'
}

# Check if models exist
print("CWD:", os.getcwd())
print("Trained models path exists:", os.path.exists("trained_models"))
print("Contents of trained_models:", os.listdir("trained_models") if os.path.exists("trained_models") else "Directory not found")

# Initialize models as None first
cat_model = None
lgb_model = None
tabnet_model = None

# Load models if they exist
def load_models():
    global cat_model, lgb_model, tabnet_model
    
    models_loaded = []
    models_failed = []
    
    # Try to load CatBoost
    if os.path.exists(app.config['MODEL_PATHS']['catboost']):
        try:
            cat_model = CatBoostClassifier()
            cat_model.load_model(app.config['MODEL_PATHS']['catboost'])
            models_loaded.append('CatBoost')
        except Exception as e:
            models_failed.append(f'CatBoost: {str(e)}')
    else:
        models_failed.append('CatBoost: File not found')
        
    # Try to load LightGBM
    if os.path.exists(app.config['MODEL_PATHS']['lightgbm']):
        try:
            # Check if it's a full model or just a booster
            lgb_model = joblib.load(app.config['MODEL_PATHS']['lightgbm'])
            models_loaded.append('LightGBM')
        except Exception as e:
            models_failed.append(f'LightGBM: {str(e)}')
    else:
        models_failed.append('LightGBM: File not found')
        
    # Try to load TabNet
    if os.path.exists(app.config['MODEL_PATHS']['tabnet']):
        try:
            tabnet_model = TabNetClassifier()
            tabnet_model.load_model(app.config['MODEL_PATHS']['tabnet'])
            models_loaded.append('TabNet')
        except Exception as e:
            models_failed.append(f'TabNet: {str(e)}')
    else:
        models_failed.append('TabNet: File not found')
    
    print(f"Models successfully loaded: {', '.join(models_loaded)}")
    if models_failed:
        print(f"Models failed to load: {', '.join(models_failed)}")
    
    return models_loaded, models_failed

# Load the models
loaded_models, failed_models = load_models()

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
    # Clear previous results from session
    session.pop('results_file', None)
    session.pop('malicious_count', None)
    session.pop('total_packets', None)
    session.pop('processing_time', None)
    
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
                    results, malicious_count, processing_time = analyze_csv(file_path)
                    
                    # Generate a unique ID for this analysis
                    result_id = str(uuid.uuid4())
                    result_file = os.path.join(app.config['RESULTS_FOLDER'], f"{result_id}.pkl")
                    
                    # Save full results to file
                    with open(result_file, 'wb') as f:
                        pickle.dump(results, f)
                    
                    # Store only the file reference and counts in session
                    session['results_file'] = result_file
                    session['malicious_count'] = malicious_count
                    session['total_packets'] = len(results)
                    session['processing_time'] = processing_time
                    
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
    return render_template('upload.html', 
                          loaded_models=loaded_models, 
                          model_paths=app.config['MODEL_PATHS'])

@app.route('/results')
@login_required
def results():
    if 'results_file' not in session or 'malicious_count' not in session or 'total_packets' not in session:
        flash('No analysis results available. Please upload a file first.', 'warning')
        return redirect(url_for('upload'))
    
    try:
        # Load results from file
        with open(session['results_file'], 'rb') as f:
            all_results = pickle.load(f)
        
        # Get only the first 100 results for display
        display_results = all_results[:100]
        
        malicious_count = session['malicious_count']
        total_packets = session['total_packets']
        processing_time = session.get('processing_time', 0.8)  # Default to 0.8s if not available
        
        return render_template('results.html', 
                              results=display_results, 
                              malicious_count=malicious_count,
                              total_results=total_packets,
                              showing_limit=len(display_results),
                              has_more=(total_packets > len(display_results)),
                              processing_time=processing_time)
    except Exception as e:
        flash(f'Error loading results: {str(e)}', 'danger')
        return redirect(url_for('upload'))

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

def preprocess(df):
    """Preprocess the data to match the format needed by models."""
    df = df.copy()
    print(f"Original columns before preprocessing: {df.columns.tolist()}")
    
    # Try to map common column names to our expected format
    column_mapping = {
        # For Source
        'src': 'Source', 'src_ip': 'Source', 'source_ip': 'Source', 'source': 'Source',
        # For Destination
        'dst': 'Destination', 'dst_ip': 'Destination', 'destination_ip': 'Destination', 'destination': 'Destination',
        # For Protocol
        'proto': 'Protocol', 'protocol': 'Protocol', 
        # For Length
        'len': 'Length', 'length': 'Length', 'packet_size': 'Length', 'size': 'Length'
    }
    
    # Apply column mapping - convert to lowercase for case-insensitive matching
    for col in df.columns:
        if col.lower() in [k.lower() for k in column_mapping.keys()]:
            # Find the correct key ignoring case
            for k in column_mapping.keys():
                if col.lower() == k.lower():
                    df[column_mapping[k]] = df[col]
                    break
    
    # Drop irrelevant columns if present
    for col in ['No.', 'Info', 'Time', 'info']:
        if col in df.columns:
            df.drop(col, axis=1, inplace=True)
    
    # Check required columns
    required_cols = ['Source', 'Destination', 'Protocol', 'Length']
    missing_cols = [col for col in required_cols if col not in df.columns]
    if missing_cols:
        print(f"Missing required columns: {missing_cols}")
        raise ValueError(f"Missing required columns: {missing_cols}")
    
    print(f"Columns after mapping: {df.columns.tolist()}")
    
    # Ensure correct dtypes
    df['Source'] = df['Source'].astype(str)
    df['Destination'] = df['Destination'].astype(str)
    df['Protocol'] = df['Protocol'].astype(str)
    
    # Label encoding
    le = LabelEncoder()
    df['Source'] = le.fit_transform(df['Source'])
    df['Destination'] = le.fit_transform(df['Destination'])
    df['Protocol'] = le.fit_transform(df['Protocol'])
    
    # Scale Length (z-score normalization)
    df['Length'] = (df['Length'] - df['Length'].mean()) / df['Length'].std() if len(df) > 1 else 0
    
    # Use only the features used in training
    X = df[['Source', 'Destination', 'Protocol', 'Length']]
    print(f"Final X shape: {X.shape}")
    print(f"Final X head:\n{X.head()}")
    return X

def analyze_csv(file_path):
    """Analyze the uploaded CSV file and return results using ML models"""
    print(f"Analyzing file: {file_path}")
    
    # Start timing
    start_time = time.time()
    
    # Debug the CSV structure
    df = pd.read_csv(file_path)
    print(f"CSV columns: {df.columns.tolist()}")
    print(f"CSV shape before preprocessing: {df.shape}")
    print(f"CSV sample:\n{df.head()}")
    
    # Preprocess
    try:
        X = preprocess(df)
        
        # Initialize predictions
        predictions = {}
        
        # Get model predictions if models are loaded
        if cat_model is not None:
            print("Getting CatBoost predictions...")
            predictions['catboost'] = cat_model.predict(X)
            print(f"CatBoost predictions: {predictions['catboost'][:5]}")
        else:
            print("CatBoost model not available")
            predictions['catboost'] = ["N/A"] * len(X)
            
        if lgb_model is not None:
            print("Getting LightGBM predictions...")
            try:
                # Try using predict method (for full model)
                predictions['lightgbm'] = lgb_model.predict(X)
            except AttributeError:
                # Try using predict method on booster directly
                predictions['lightgbm'] = lgb_model.predict(X.values)
            print(f"LightGBM predictions: {predictions['lightgbm'][:5]}")
        else:
            print("LightGBM model not available")
            predictions['lightgbm'] = ["N/A"] * len(X)
            
        if tabnet_model is not None:
            print("Getting TabNet predictions...")
            predictions['tabnet'] = tabnet_model.predict(X.values)
            print(f"TabNet predictions: {predictions['tabnet'][:5]}")
        else:
            print("TabNet model not available")
            predictions['tabnet'] = ["N/A"] * len(X)
            
        # Add predictions to DataFrame
        df['CatBoost Prediction'] = predictions['catboost']
        df['LightGBM Prediction'] = predictions['lightgbm']
        df['TabNet Prediction'] = predictions['tabnet']
        
        # Format results for the template (showing all three predictions)
        results = []
        for idx, row in df.iterrows():
            results.append({
                'timestamp': str(row.get('Time', idx)),
                'src_ip': row.get('Source', 'N/A'),
                'dst_ip': row.get('Destination', 'N/A'),
                'protocol': row.get('Protocol', 'N/A'),
                'size': str(row.get('Length', 'N/A')),
                'catboost_pred': row['CatBoost Prediction'],
                'lgbm_pred': row['LightGBM Prediction'],
                'tabnet_pred': row['TabNet Prediction']
            })
        
        # Count malicious packets (assuming 'Malicious' label is 1 or 'Malicious')
        malicious_count = sum(
            1 for r in results if (
                (r['catboost_pred'] == 1 or r['catboost_pred'] == 'Malicious') or
                (r['lgbm_pred'] == 1 or r['lgbm_pred'] == 'Malicious') or
                (r['tabnet_pred'] == 1 or r['tabnet_pred'] == 'Malicious')
            )
        )
        
        # Calculate processing time
        processing_time = round(time.time() - start_time, 2)
        print(f"Malicious count: {malicious_count}")
        print(f"Processing time: {processing_time} seconds")
        
        return results, malicious_count, processing_time
        
    except Exception as e:
        import traceback
        print(f"Error in analyze_csv: {e}")
        print(traceback.format_exc())
        
        # Calculate processing time even for errors
        processing_time = round(time.time() - start_time, 2)
        print(f"Processing time (error): {processing_time} seconds")
        
        # Fallback to error logic
        return [{
            'timestamp': 'Error',
            'src_ip': 'Error',
            'dst_ip': 'Error',
            'protocol': 'Error',
            'size': 'Error',
            'catboost_pred': str(e),
            'lgbm_pred': str(e),
            'tabnet_pred': str(e)
        }], 0, processing_time

if __name__ == '__main__':
    app.run(debug=True)