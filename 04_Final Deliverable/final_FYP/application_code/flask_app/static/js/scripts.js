// Initialize Protocol Distribution Chart
const protocolCtx = document.getElementById('protocolChart').getContext('2d');
new Chart(protocolCtx, {
    type: 'pie',
    data: {
        labels: ['TCP', 'UDP', 'HTTP', 'Other'],
        datasets: [{
            data: [45, 30, 15, 10],
            backgroundColor: ['#00B4D8', '#FF4D4D', '#2E7D32', '#FFD700']
        }]
    }
});

// Initialize Threat Severity Chart
const threatCtx = document.getElementById('threatChart').getContext('2d');
new Chart(threatCtx, {
    type: 'bar',
    data: {
        labels: ['Low', 'Medium', 'High'],
        datasets: [{
            label: 'Threat Count',
            data: [12, 8, 5],
            backgroundColor: ['#00B4D8', '#FFD700', '#FF4D4D']
        }]
    }
});

// Handle File Upload Drag & Drop
function handleDrop(e) {
    e.preventDefault();
    const fileInput = document.getElementById('fileInput');
    const files = e.dataTransfer.files;
    if (files.length > 0) {
        fileInput.files = files;
    }
}