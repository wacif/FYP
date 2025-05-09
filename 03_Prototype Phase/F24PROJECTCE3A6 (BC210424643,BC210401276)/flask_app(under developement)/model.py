import pandas as pd

def predict(df):
    """
    Placeholder function for intrusion detection.
    Replace this with your actual machine learning model.
    """
    results = []
    for _, row in df.iterrows():
        results.append({
            'timestamp': row.get('frame.time', 'N/A'),
            'src_ip': row.get('ip.src', 'N/A'),
            'dst_ip': row.get('ip.dst', 'N/A'),
            'protocol': row.get('_ws.col.Protocol', 'N/A'),
            'packet_size': row.get('frame.len', 'N/A'),
            'prediction': 'Malicious' if row.get('frame.len', 0) > 1000 else 'Normal'
        })
    return results