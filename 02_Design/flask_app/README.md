# Network Traffic Analyzer with ML Models

A Flask web application that analyzes network traffic data using multiple machine learning models to detect malicious packets.

## Project Overview

This application allows users to upload network traffic data in CSV format, which is then analyzed by three different machine learning models (CatBoost, LightGBM, and TabNet) to identify potential security threats.

## Features

- User authentication system
- File upload for CSV network traffic data
- Data preprocessing pipeline that matches the training pipeline
- Real-time analysis using three ML models:
  - CatBoost
  - LightGBM
  - TabNet
- Results dashboard showing:
  - Total number of packets analyzed
  - Count of malicious packets detected
  - Actual processing time
  - Detailed packet information in a paginated table
- Session management for large datasets
- Model status indicators

## Installation

1. Clone this repository
2. Create a virtual environment:
   ```
   python -m venv .venv
   source .venv/bin/activate  # On Windows: .venv\Scripts\activate
   ```
3. Install required packages:
   ```
   pip install -r requirements.txt
   ```
4. Ensure you have the trained models in the `trained_models` directory:
   - `trained_models/catboost_model.cbm`
   - `trained_models/lightgbm_model.pkl`
   - `trained_models/tabnet_model.zip`

## Requirements

- Python 3.7+
- Flask
- pandas
- numpy
- CatBoost
- LightGBM
- PyTorch and TabNet
- joblib
- scikit-learn

## Usage

1. Start the application:
   ```
   python app.py
   ```
2. Navigate to `http://127.0.0.1:5000` in your web browser
3. Log in using the test credentials:
   - Email: test@example.com
   - Password: test123
4. Upload a CSV file containing network traffic data
5. View the analysis results

## Input Data Format

The application expects CSV files with network traffic data. The following columns are required:
- Source (IP address)
- Destination (IP address)
- Protocol
- Length (packet size)

The application has column mapping capabilities to handle slight variations in column names.

## Project Structure

- `app.py`: Main application file
- `templates/`: HTML templates for the web interface
- `static/`: Static files (CSS, JS, images)
- `trained_models/`: Directory containing the trained ML models
- `uploads/`: Temporary storage for uploaded files
- `results/`: Storage for analysis results

## Sample Data

A sample CSV file is included in `static/sample_network_traffic.csv` for testing purposes.

## Future Improvements

- PCAP file analysis support
- Additional machine learning models
- User management system
- Enhanced visualization of analysis results
- API endpoints for programmatic access 