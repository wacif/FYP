# Network Traffic Analyzer - Test Sample

This repository contains a sample CSV file for testing the Network Traffic Analyzer application.

## Sample Data Description

The `static/sample_network_traffic.csv` file contains simulated network traffic data with the following characteristics:

- 30 packet records with timestamps, IP addresses, protocols, and various network metrics
- Mix of TCP, UDP, and ICMP traffic
- Contains both normal and potentially malicious traffic patterns
- Includes port scanning attempts, normal web browsing, and DNS queries

## How to Use the Sample Data

1. Start your Flask application
2. Navigate to the upload page
3. Upload the `sample_network_traffic.csv` file
4. The application will analyze the data and display the results on the results page

## Expected Results

When you upload the sample file, you should see:

- Total of 30 packets analyzed
- Several packets flagged as potentially malicious (port scan attempts)
- Protocol distribution showing primarily TCP traffic with some UDP and ICMP
- Traffic analysis over time showing patterns of normal and suspicious activity
- Security recommendations based on the detected threats

## Sample Malicious Patterns

The sample data includes the following suspicious patterns:

1. **Port Scanning**: Multiple SYN packets from external IPs targeting common service ports (22, 23, 3389)
2. **Failed SMB Connection Attempts**: Repeated connection attempts to port 445
3. **Unusual Response Patterns**: Several connections with no response packets

## Notes

This is test data only and does not represent actual network threats. It is designed to demonstrate the functionality of the Network Traffic Analyzer application. 