from flask import Flask, request, render_template, redirect, url_for, flash
import pandas as pd
import os
from model import predict  # Placeholder for your machine learning model

app = Flask(__name__)
app.secret_key = 'supersecretkey'  # Required for flashing messages

# Configuration
UPLOAD_FOLDER = 'uploads'
ALLOWED_EXTENSIONS = {'csv'}
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER

# Ensure upload folder exists
os.makedirs(UPLOAD_FOLDER, exist_ok=True)

def allowed_file(filename):
    """Check if the file has an allowed extension."""
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

@app.route('/', methods=['GET', 'POST'])
def index():
    """Home page for uploading Wireshark CSV files."""
    if request.method == 'POST':
        # Check if a file was uploaded
        if 'file' not in request.files:
            flash('No file uploaded!', 'error')
            return redirect(request.url)

        file = request.files['file']

        # Check if the file is empty
        if file.filename == '':
            flash('No file selected!', 'error')
            return redirect(request.url)

        # Check if the file has an allowed extension
        if file and allowed_file(file.filename):
            # Save the file to the upload folder
            filepath = os.path.join(app.config['UPLOAD_FOLDER'], file.filename)
            file.save(filepath)

            # Process the file (placeholder for now)
            try:
                df = pd.read_csv(filepath)
                results = predict(df)  # Call your machine learning model here
                return render_template('results.html', results=results)
            except Exception as e:
                flash(f'Error processing file: {str(e)}', 'error')
                return redirect(request.url)
        else:
            flash('Invalid file type! Only CSV files are allowed.', 'error')
            return redirect(request.url)

    return render_template('index.html')

@app.route('/results')
def results():
    """Page to display intrusion detection results."""
    return render_template('results.html')

if __name__ == '__main__':
    app.run(debug=True)