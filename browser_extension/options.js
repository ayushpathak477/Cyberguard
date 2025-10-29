// CyberGuard Pro - Options Page Script
// Handles extension settings and configuration

// Default settings
const DEFAULT_SETTINGS = {
    apiEndpoint: 'http://localhost:5000',
    enableRealtime: true,
    enableWarnings: true,
    enablePhishing: true,
    enableMalware: true,
    checkFrequency: 30,
    enableLogging: false
};

document.addEventListener('DOMContentLoaded', async () => {
    await loadSettings();
    await checkApiConnection();
    setupEventListeners();
});

async function loadSettings() {
    try {
        const settings = await chrome.storage.sync.get(DEFAULT_SETTINGS);
        
        // Populate form fields
        document.getElementById('api-endpoint').value = settings.apiEndpoint;
        document.getElementById('enable-realtime').checked = settings.enableRealtime;
        document.getElementById('enable-warnings').checked = settings.enableWarnings;
        document.getElementById('enable-phishing').checked = settings.enablePhishing;
        document.getElementById('enable-malware').checked = settings.enableMalware;
        document.getElementById('check-frequency').value = settings.checkFrequency;
        document.getElementById('enable-logging').checked = settings.enableLogging;
        
    } catch (error) {
        console.error('Error loading settings:', error);
        showMessage('Error loading settings. Using defaults.', 'error');
    }
}

async function saveSettings() {
    try {
        const settings = {
            apiEndpoint: document.getElementById('api-endpoint').value.trim(),
            enableRealtime: document.getElementById('enable-realtime').checked,
            enableWarnings: document.getElementById('enable-warnings').checked,
            enablePhishing: document.getElementById('enable-phishing').checked,
            enableMalware: document.getElementById('enable-malware').checked,
            checkFrequency: parseInt(document.getElementById('check-frequency').value) || 30,
            enableLogging: document.getElementById('enable-logging').checked
        };

        // Validate settings
        if (!settings.apiEndpoint) {
            showMessage('API endpoint cannot be empty.', 'error');
            return;
        }

        if (settings.checkFrequency < 5 || settings.checkFrequency > 300) {
            showMessage('Check frequency must be between 5 and 300 seconds.', 'error');
            return;
        }

        // Save to storage
        await chrome.storage.sync.set(settings);
        
        // Notify background script of settings change
        chrome.runtime.sendMessage({
            action: 'settingsUpdated',
            settings: settings
        });

        showMessage('Settings saved successfully!', 'success');
        
    } catch (error) {
        console.error('Error saving settings:', error);
        showMessage('Error saving settings. Please try again.', 'error');
    }
}

async function resetSettings() {
    try {
        await chrome.storage.sync.clear();
        await loadSettings();
        showMessage('Settings reset to defaults.', 'success');
    } catch (error) {
        console.error('Error resetting settings:', error);
        showMessage('Error resetting settings.', 'error');
    }
}

async function checkApiConnection() {
    const apiStatusElement = document.getElementById('api-status');
    const apiEndpoint = document.getElementById('api-endpoint').value.trim();
    
    apiStatusElement.textContent = 'Checking...';
    apiStatusElement.className = 'api-status';
    
    try {
        const response = await fetch(`${apiEndpoint}/extension/check_url`, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
            },
            body: JSON.stringify({ url: 'https://google.com' })
        });

        if (response.ok) {
            apiStatusElement.textContent = 'Online';
            apiStatusElement.className = 'api-status api-online';
        } else {
            throw new Error(`HTTP ${response.status}`);
        }
        
    } catch (error) {
        console.error('API connection test failed:', error);
        apiStatusElement.textContent = 'Offline';
        apiStatusElement.className = 'api-status api-offline';
    }
}

function showMessage(message, type) {
    const messageElement = document.getElementById('status-message');
    messageElement.textContent = message;
    messageElement.className = `status-message status-${type}`;
    messageElement.style.display = 'block';
    
    // Auto-hide after 5 seconds
    setTimeout(() => {
        messageElement.style.display = 'none';
    }, 5000);
}

function setupEventListeners() {
    // Save settings button
    document.getElementById('save-settings').addEventListener('click', saveSettings);
    
    // Reset settings button
    document.getElementById('reset-settings').addEventListener('click', () => {
        if (confirm('Are you sure you want to reset all settings to defaults?')) {
            resetSettings();
        }
    });
    
    // Test connection button
    document.getElementById('test-connection').addEventListener('click', checkApiConnection);
    
    // API endpoint change
    document.getElementById('api-endpoint').addEventListener('blur', checkApiConnection);
    
    // Dashboard link
    document.getElementById('dashboard-link').addEventListener('click', (e) => {
        e.preventDefault();
        const apiEndpoint = document.getElementById('api-endpoint').value.trim();
        chrome.tabs.create({ url: apiEndpoint });
    });
    
    // Help link
    document.getElementById('help-link').addEventListener('click', (e) => {
        e.preventDefault();
        const apiEndpoint = document.getElementById('api-endpoint').value.trim();
        chrome.tabs.create({ url: apiEndpoint });
    });
    
    // Auto-save on certain changes
    const autoSaveElements = [
        'enable-realtime',
        'enable-warnings', 
        'enable-phishing',
        'enable-malware',
        'enable-logging'
    ];
    
    autoSaveElements.forEach(id => {
        document.getElementById(id).addEventListener('change', () => {
            setTimeout(saveSettings, 500); // Auto-save after 500ms
        });
    });
}