document.addEventListener("DOMContentLoaded", () => {
    // Helper function to format bytes into KB, MB, GB
    function formatBytes(bytes) {
        if (bytes === 0) return '0 B';
        const k = 1024;
        const sizes = ['B', 'KB', 'MB', 'GB'];
        const i = Math.floor(Math.log(bytes) / Math.log(k));
        return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i];
    }
    // ==========================================
    // 1. LIVE CHART.JS SETUP
    // ==========================================
    const ctx = document.getElementById('trafficChart').getContext('2d');
    
    // Gradients for the chart lines
    let gradientBlue = ctx.createLinearGradient(0, 0, 0, 400);
    gradientBlue.addColorStop(0, 'rgba(59, 130, 246, 0.5)');
    gradientBlue.addColorStop(1, 'rgba(59, 130, 246, 0.0)');

    let gradientPurple = ctx.createLinearGradient(0, 0, 0, 400);
    gradientPurple.addColorStop(0, 'rgba(139, 92, 246, 0.5)');
    gradientPurple.addColorStop(1, 'rgba(139, 92, 246, 0.0)');

    // Start with empty data!
    const trafficChart = new Chart(ctx, {
        type: 'line',
        data: {
            labels: [], 
            datasets: [
                {
                    label: 'TCP Packets / 2s',
                    data: [],
                    borderColor: '#3b82f6',
                    backgroundColor: gradientBlue,
                    borderWidth: 2,
                    tension: 0.4,
                    fill: true,
                    pointBackgroundColor: '#0f111a',
                    pointBorderColor: '#3b82f6',
                    pointBorderWidth: 2,
                    pointRadius: 3
                },
                {
                    label: 'UDP Packets / 2s',
                    data: [],
                    borderColor: '#8b5cf6',
                    backgroundColor: gradientPurple,
                    borderWidth: 2,
                    tension: 0.4,
                    fill: true,
                    pointBackgroundColor: '#0f111a',
                    pointBorderColor: '#8b5cf6',
                    pointBorderWidth: 2,
                    pointRadius: 3
                }
            ]
        },
        options: {
            responsive: true,
            maintainAspectRatio: false,
            animation: {
                duration: 400, // Smooth transition between data points
                easing: 'linear'
            },
            plugins: {
                legend: { position: 'top', labels: { color: '#94a3b8', usePointStyle: true, boxWidth: 8 } }
            },
            scales: {
                x: { grid: { color: 'rgba(42, 46, 69, 0.5)', drawBorder: false }, ticks: { color: '#94a3b8' } },
                y: { grid: { color: 'rgba(42, 46, 69, 0.5)', drawBorder: false }, ticks: { color: '#94a3b8' }, beginAtZero: true }
            },
            interaction: { intersect: false, mode: 'index' },
        }
    });

    // --- REAL-TIME CHART UPDATER ---
    let lastTCP = 0;
    let lastUDP = 0;
    let isFirstFetch = true;

    // Fetch new packet data every 2 seconds
    setInterval(() => {
        fetch('/api/traffic')
            .then(response => response.json())
            .then(data => {
                if (data.error) return;

                const currentTCP = data.stats.TCP;
                const currentUDP = data.stats.UDP;

                // Establish a baseline on the first load so the chart doesn't spike to 10,000 instantly
                if (isFirstFetch) {
                    lastTCP = currentTCP;
                    lastUDP = currentUDP;
                    isFirstFetch = false;
                    return; 
                }

                // Calculate packets that arrived in the last 2 seconds
                const tcpRate = currentTCP - lastTCP;
                const udpRate = currentUDP - lastUDP;

                // Update baseline for the next loop
                lastTCP = currentTCP;
                lastUDP = currentUDP;

                // Generate a timestamp like "14:05:30"
                const now = new Date();
                const timeLabel = now.getHours().toString().padStart(2, '0') + ':' + 
                                  now.getMinutes().toString().padStart(2, '0') + ':' + 
                                  now.getSeconds().toString().padStart(2, '0');

                // Push new data into the chart
                trafficChart.data.labels.push(timeLabel);
                trafficChart.data.datasets[0].data.push(tcpRate);
                trafficChart.data.datasets[1].data.push(udpRate);

                // Keep only the last 15 data points so the chart scrolls horizontally
                if (trafficChart.data.labels.length > 15) {
                    trafficChart.data.labels.shift();
                    trafficChart.data.datasets[0].data.shift();
                    trafficChart.data.datasets[1].data.shift();
                }

                // Tell Chart.js to redraw!
                trafficChart.update();
                    // Update the "Active Threats" number card on the dashboard
                const threatCard = document.querySelector('.stat-card .red').nextElementSibling.querySelector('h2');
                if(threatCard) threatCard.innerText = data.alerts.length;
                const volumeCard = document.getElementById('traffic-volume-count');
                if (volumeCard) {
                    volumeCard.innerText = formatBytes(data.stats.total_bytes);
                }
                // Update the sidebar badge
                const sidebarBadge = document.querySelector('.sidebar-nav .badge.red');
                if(sidebarBadge) sidebarBadge.innerText = data.alerts.length;

                // If a NEW alert came in, spawn a popup notification!
                if (data.alerts.length > knownAlertCount) {
                    const latestAlert = data.alerts[0]; // Get the newest one
                    knownAlertCount = data.alerts.length;

                    const toastContainer = document.getElementById('toast-container');
                    const toast = document.createElement('div');
                    toast.className = 'toast';
                    toast.innerHTML = `
                        <i class="fa-solid fa-triangle-exclamation toast-icon"></i>
                        <div>
                            <div class="toast-title">${latestAlert.message}</div>
                            <div class="toast-body">Source: ${latestAlert.src_ip} | Time: ${latestAlert.time}</div>
                        </div>
                    `;
                    toastContainer.appendChild(toast);

                    // Remove the toast after 6 seconds
                    setTimeout(() => {
                        toast.style.animation = "fadeOut 0.5s ease forwards";
                        setTimeout(() => toast.remove(), 500);
                    }, 6000);
                }
            
            })
            .catch(err => console.error("Error fetching live traffic:", err));
    }, 2000); // 2000ms = 2 seconds


    // ==========================================
    // 2. LIVE NETWORK SCANNER TABLE
    // ==========================================
    const tableBody = document.getElementById('device-table-body');
    const refreshBtn = document.getElementById('refresh-scan-btn'); // Grab the new button
    
    function runNetworkScan() {
        if(!tableBody) return;

        // 1. Show the loading radar in the table
        tableBody.innerHTML = `
            <tr>
                <td colspan="7" style="text-align: center; padding: 50px;">
                    <i class="fa-solid fa-radar fa-spin" style="font-size: 2.5rem; color: var(--accent-blue); margin-bottom: 15px;"></i>
                    <h3 style="color: var(--text-main); margin-bottom: 5px;">Scanning Network...</h3>
                    <p style="color: var(--text-muted); font-size: 0.9rem;">Running Nmap engine to discover live devices.</p>
                </td>
            </tr>
        `;
        

        // 2. Make the refresh button spin so the user knows it's working
        if(refreshBtn) {
            refreshBtn.innerHTML = '<i class="fa-solid fa-arrows-rotate fa-spin"></i> Scanning...';
            refreshBtn.disabled = true; // Prevent spam-clicking
        }

        // 3. Call the Python API
        fetch('/api/scan')
            .then(response => response.json())
            .then(devices => {
                tableBody.innerHTML = '';
                const totalDevicesCard = document.getElementById('total-devices-count');
                if (totalDevicesCard) {
                    // If devices is an array, show the length. If it failed, show 0.
                    totalDevicesCard.innerText = devices.length ? devices.length : 0;
                }
                if(devices.length === 0 || devices.error) {
                    tableBody.innerHTML = `
                        <tr>
                            <td colspan="7" style="text-align: center; padding: 30px; color: var(--text-muted);">
                                <i class="fa-solid fa-triangle-exclamation" style="font-size: 2rem; margin-bottom: 10px; color: var(--accent-red);"></i>
                                <br>No devices found. Ensure the Flask server is running as Administrator!
                            </td>
                        </tr>
                    `;
                    return;
                }

                // Generate the rows
                devices.forEach(device => {
                    const row = document.createElement('tr');
                    
                    let icon = "fa-circle-question";
                    let colorClass = "text-gray";
                    
                    if(device.type === 'Router') { icon = 'fa-router'; colorClass = 'text-gray'; }
                    else if(device.type === 'Phone/Tablet') { icon = 'fa-mobile-screen'; colorClass = 'text-purple'; }
                    else if(device.type === 'Laptop/PC') { icon = 'fa-laptop'; colorClass = 'text-blue'; }
                    else if(device.type === 'IoT Device') { icon = 'fa-lightbulb'; colorClass = 'text-green'; }

                    const isOffline = device.status === 'Offline';
                    const statusDot = isOffline ? 'red' : 'green';
                    const rowOpacity = isOffline ? 'opacity: 0.5;' : '';

                    row.innerHTML = `
                        <td style="${rowOpacity}">
                            <div class="device-cell">
                                <i class="fa-solid ${icon} ${colorClass}"></i>
                                <span>${device.type}</span>
                            </div>
                        </td>
                        <td class="ip-text" style="${rowOpacity}">${device.ip}</td>
                        <td class="mono-text" style="${rowOpacity}">${device.mac}</td>
                        <td style="${rowOpacity}">${device.hostname}</td>
                        <td style="${rowOpacity}">${device.vendor}</td>
                        <td><span class="status-dot ${statusDot}"></span> ${device.status}</td>
                        <td class="mono-text" style="${rowOpacity}">${device.last_seen}</td>
                    `;
                    tableBody.appendChild(row);
                });
            })
            .catch(error => {
                console.error("Error scanning network:", error);
                tableBody.innerHTML = `<tr><td colspan="7" style="text-align:center; color:red;">Error connecting to scanner engine.</td></tr>`;
            })
            .finally(() => {
                // 4. Reset the refresh button back to normal when finished
                if(refreshBtn) {
                    refreshBtn.innerHTML = '<i class="fa-solid fa-arrows-rotate"></i> Refresh';
                    refreshBtn.disabled = false;
                }
            });
    }

    // Run the scan automatically when the page first loads
    runNetworkScan();

    // Run the scan again whenever the refresh button is clicked
    if(refreshBtn) {
        refreshBtn.addEventListener('click', runNetworkScan);
    }
});