// CyberGuard Pro - Popup Script
// Handles the extension popup interface

document.addEventListener('DOMContentLoaded', async () => {
    await initializePopup();
    setupEventListeners();
});

async function initializePopup() {
    try {
        // Get current active tab
        const tabs = await chrome.tabs.query({ active: true, currentWindow: true });
        const currentTab = tabs[0];

        if (!currentTab || !currentTab.url) {
            showError('Unable to get current tab information');
            return;
        }

        document.getElementById('current-url').textContent = currentTab.url;

        // Check if we have cached data for this tab
        const cacheKey = `url_${currentTab.id}`;
        const result = await chrome.storage.local.get([cacheKey]);
        
        if (result[cacheKey]) {
            // Use cached data
            displayUrlStatus(result[cacheKey], currentTab.url);
        } else {
            // Fetch fresh data from API
            await checkCurrentUrl(currentTab.url);
        }

    } catch (error) {
        console.error('Error initializing popup:', error);
        showError('Failed to initialize CyberGuard popup');
    }
}

async function checkCurrentUrl(url) {
    try {
        // Skip internal browser pages
        if (url.startsWith('chrome://') || url.startsWith('chrome-extension://') || 
            url.startsWith('about:') || url.startsWith('moz-extension://')) {
            displayBrowserPage();
            return;
        }

        const response = await fetch('http://localhost:5000/extension/check_url', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
            },
            body: JSON.stringify({ url: url })
        });

        if (!response.ok) {
            throw new Error(`API request failed: ${response.status}`);
        }

        const result = await response.json();
        displayUrlStatus(result, url);

    } catch (error) {
        console.error('Error checking URL:', error);
        showError('Unable to connect to CyberGuard backend. Make sure the application is running.');
    }
}

function displayUrlStatus(data, url) {
    // Hide loading and show content
    document.getElementById('loading').style.display = 'none';
    document.getElementById('status-content').style.display = 'block';

    const statusCard = document.getElementById('status-card');
    const statusIcon = document.getElementById('status-icon');
    const statusTitle = document.getElementById('status-title');
    const statusDescription = document.getElementById('status-description');
    const threatDetails = document.getElementById('threat-details');

    // Update URL display
    document.getElementById('current-url').textContent = url;

    if (data.is_safe) {
        // Safe site
        statusCard.className = 'status-card';
        statusIcon.textContent = '✅';
        statusTitle.textContent = 'Site is Safe';
        statusDescription.textContent = 'No threats detected. This website appears to be legitimate and secure.';
        threatDetails.style.display = 'none';
    } else {
        // Unsafe site
        statusCard.className = 'status-card threat';
        statusIcon.textContent = '🚫';
        statusTitle.textContent = 'Threat Detected!';
        statusDescription.textContent = 'This website has been identified as potentially dangerous. Exercise caution.';
        
        // Show threat details
        threatDetails.style.display = 'block';
        
        // Threat type
        document.getElementById('threat-type').textContent = data.threat_type || 'Unknown';
        
        // Risk score
        const riskScore = data.risk_score || 0;
        const riskElement = document.getElementById('risk-score');
        riskElement.textContent = `${riskScore}/10`;
        
        // Set risk score color
        riskElement.className = 'risk-score';
        if (riskScore <= 3) {
            riskElement.classList.add('risk-low');
        } else if (riskScore <= 6) {
            riskElement.classList.add('risk-medium');
        } else {
            riskElement.classList.add('risk-high');
        }
        
        // Reasons
        if (data.reasons && data.reasons.length > 0) {
            document.getElementById('reasons-row').style.display = 'block';
            const reasonsList = document.getElementById('reasons-list');
            reasonsList.innerHTML = data.reasons.map(reason => `• ${reason}`).join('<br>');
        } else {
            document.getElementById('reasons-row').style.display = 'none';
        }
    }
}

function displayBrowserPage() {
    // Hide loading and show content
    document.getElementById('loading').style.display = 'none';
    document.getElementById('status-content').style.display = 'block';

    const statusCard = document.getElementById('status-card');
    const statusIcon = document.getElementById('status-icon');
    const statusTitle = document.getElementById('status-title');
    const statusDescription = document.getElementById('status-description');

    statusCard.className = 'status-card';
    statusIcon.textContent = '🌐';
    statusTitle.textContent = 'Browser Page';
    statusDescription.textContent = 'This is an internal browser page that cannot be scanned for threats.';
    
    document.getElementById('threat-details').style.display = 'none';
}

function showError(message) {
    // Hide loading and show content
    document.getElementById('loading').style.display = 'none';
    document.getElementById('status-content').style.display = 'block';

    const statusCard = document.getElementById('status-card');
    const statusIcon = document.getElementById('status-icon');
    const statusTitle = document.getElementById('status-title');
    const statusDescription = document.getElementById('status-description');

    statusCard.className = 'status-card warning';
    statusIcon.textContent = '⚠️';
    statusTitle.textContent = 'Connection Error';
    statusDescription.textContent = message;
    
    document.getElementById('threat-details').style.display = 'none';
}

function setupEventListeners() {
    // Refresh button
    document.getElementById('refresh-btn').addEventListener('click', async () => {
        document.getElementById('loading').style.display = 'block';
        document.getElementById('status-content').style.display = 'none';
        
        const tabs = await chrome.tabs.query({ active: true, currentWindow: true });
        const currentTab = tabs[0];
        
        if (currentTab && currentTab.url) {
            await checkCurrentUrl(currentTab.url);
        }
    });

    // Dashboard button
    document.getElementById('dashboard-btn').addEventListener('click', () => {
        chrome.tabs.create({ url: 'http://localhost:5000' });
        window.close();
    });

    // Settings link
    document.getElementById('settings-link').addEventListener('click', (e) => {
        e.preventDefault();
        chrome.runtime.openOptionsPage();
    });

    // Help link
    document.getElementById('help-link').addEventListener('click', (e) => {
        e.preventDefault();
        chrome.tabs.create({ url: 'http://localhost:5000' });
        window.close();
    });
}