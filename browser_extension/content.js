// CyberGuard Pro - Content Script
// Runs on all web pages to provide real-time protection

console.log('🛡️ CyberGuard Pro content script loaded');

// Configuration
const CYBERGUARD_API = 'http://localhost:5000';
let isCheckingUrl = false;
let lastWarningTime = 0;

// Initialize protection when page loads
document.addEventListener('DOMContentLoaded', initializeProtection);

// Also run immediately in case DOM is already loaded
if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', initializeProtection);
} else {
    initializeProtection();
}

async function initializeProtection() {
    // Skip internal browser pages
    if (window.location.href.startsWith('chrome://') || 
        window.location.href.startsWith('chrome-extension://') || 
        window.location.href.startsWith('about:') || 
        window.location.href.startsWith('moz-extension://')) {
        return;
    }

    console.log('🔍 CyberGuard: Initializing protection for', window.location.href);
    
    // Check current page safety
    await checkPageSafety();
    
    // Monitor for form submissions (phishing protection)
    monitorForms();
    
    // Monitor for suspicious JavaScript execution
    monitorSuspiciousActivity();
}

async function checkPageSafety() {
    if (isCheckingUrl) return;
    isCheckingUrl = true;

    try {
        const currentUrl = window.location.href;
        
        const response = await fetch(`${CYBERGUARD_API}/extension/check_url`, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
            },
            body: JSON.stringify({ url: currentUrl })
        });

        if (!response.ok) {
            console.warn('CyberGuard API error:', response.status);
            return;
        }

        const result = await response.json();
        
        // Send result to background script for badge update
        chrome.runtime.sendMessage({
            action: 'urlChecked',
            result: result,
            url: currentUrl
        });

        // Show warning if site is unsafe
        if (!result.is_safe) {
            showThreatWarning(result);
        }

    } catch (error) {
        console.error('CyberGuard protection error:', error);
    } finally {
        isCheckingUrl = false;
    }
}

function showThreatWarning(threatData) {
    // Prevent spam warnings
    const now = Date.now();
    if (now - lastWarningTime < 10000) return; // 10 second cooldown
    lastWarningTime = now;

    // Remove any existing warnings
    const existingWarning = document.getElementById('cyberguard-warning');
    if (existingWarning) {
        existingWarning.remove();
    }

    // Create warning overlay
    const overlay = document.createElement('div');
    overlay.id = 'cyberguard-warning';
    overlay.style.cssText = `
        position: fixed !important;
        top: 0 !important;
        left: 0 !important;
        width: 100% !important;
        height: 100% !important;
        background: rgba(0, 0, 0, 0.95) !important;
        z-index: 2147483647 !important;
        display: flex !important;
        align-items: center !important;
        justify-content: center !important;
        font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Arial, sans-serif !important;
        font-size: 16px !important;
        line-height: 1.5 !important;
    `;

    overlay.innerHTML = `
        <div style="
            background: linear-gradient(135deg, #1a1a1a, #2d2d2d) !important;
            color: white !important;
            padding: 40px !important;
            border-radius: 15px !important;
            max-width: 500px !important;
            margin: 20px !important;
            text-align: center !important;
            border: 2px solid #ff3333 !important;
            box-shadow: 0 0 30px rgba(255, 51, 51, 0.5) !important;
            font-family: inherit !important;
        ">
            <div style="margin-bottom: 20px !important;">
                <h1 style="color: #ff3333 !important; margin: 0 0 10px 0 !important; font-size: 24px !important;">🛡️ CyberGuard Pro</h1>
                <p style="margin: 0 !important; opacity: 0.8 !important; font-size: 14px !important;">Website Security Protection</p>
            </div>
            
            <div style="
                background: #ff3333 !important;
                padding: 20px !important;
                border-radius: 10px !important;
                margin: 20px 0 !important;
            ">
                <h2 style="margin: 0 !important; font-size: 22px !important;">🚫 THREAT DETECTED</h2>
                <p style="margin: 10px 0 0 0 !important; font-size: 16px !important;">This website may be dangerous!</p>
            </div>
            
            <div style="
                background: rgba(255,255,255,0.1) !important;
                padding: 20px !important;
                border-radius: 10px !important;
                margin: 20px 0 !important;
                text-align: left !important;
            ">
                <h3 style="margin: 0 0 15px 0 !important; color: #ff3333 !important; font-size: 16px !important;">Threat Details:</h3>
                <p style="margin: 5px 0 !important; font-size: 14px !important;"><strong>URL:</strong> ${threatData.url}</p>
                <p style="margin: 5px 0 !important; font-size: 14px !important;"><strong>Threat Type:</strong> ${threatData.threat_type || 'Unknown'}</p>
                <p style="margin: 5px 0 !important; font-size: 14px !important;"><strong>Risk Score:</strong> ${threatData.risk_score}/10</p>
                ${threatData.reasons && threatData.reasons.length > 0 ? 
                    `<div style="margin-top: 10px !important;">
                        <p style="margin: 5px 0 !important; font-size: 14px !important;"><strong>Reasons:</strong></p>
                        <ul style="margin: 5px 0 !important; padding-left: 20px !important; font-size: 13px !important;">
                            ${threatData.reasons.map(reason => `<li style="margin: 3px 0 !important;">${reason}</li>`).join('')}
                        </ul>
                    </div>` : ''
                }
            </div>
            
            <div style="margin-top: 30px !important;">
                <button id="cyberguard-go-back" style="
                    padding: 12px 20px !important;
                    margin: 0 10px !important;
                    background: #4CAF50 !important;
                    color: white !important;
                    border: none !important;
                    border-radius: 5px !important;
                    cursor: pointer !important;
                    font-size: 16px !important;
                    font-family: inherit !important;
                ">← Go Back Safely</button>
                
                <button id="cyberguard-continue" style="
                    padding: 12px 20px !important;
                    margin: 0 10px !important;
                    background: rgba(255,255,255,0.1) !important;
                    color: white !important;
                    border: 1px solid #666 !important;
                    border-radius: 5px !important;
                    cursor: pointer !important;
                    font-size: 16px !important;
                    font-family: inherit !important;
                ">Continue Anyway</button>
            </div>
            
            <p style="margin-top: 20px !important; font-size: 12px !important; color: #aaa !important; opacity: 0.7 !important;">
                Protected by CyberGuard Pro Browser Extension
            </p>
        </div>
    `;

    // Add to page
    document.body.appendChild(overlay);

    // Add event listeners
    document.getElementById('cyberguard-go-back').addEventListener('click', () => {
        window.history.back();
    });

    document.getElementById('cyberguard-continue').addEventListener('click', () => {
        overlay.remove();
    });

    // Auto-remove after 60 seconds if user doesn't interact
    setTimeout(() => {
        const warning = document.getElementById('cyberguard-warning');
        if (warning) {
            warning.remove();
        }
    }, 60000);

    console.warn('🚫 CyberGuard: Threat warning displayed for', threatData.url);
}

function monitorForms() {
    // Monitor form submissions for potential phishing
    document.addEventListener('submit', (event) => {
        const form = event.target;
        if (form.tagName === 'FORM') {
            const hasPasswordField = form.querySelectorAll('input[type="password"]').length > 0;
            const hasEmailField = form.querySelectorAll('input[type="email"], input[name*="email"], input[placeholder*="email"]').length > 0;
            
            if (hasPasswordField || hasEmailField) {
                console.log('🔐 CyberGuard: Monitoring sensitive form submission');
                // Could add additional phishing checks here
            }
        }
    });
}

function monitorSuspiciousActivity() {
    // Monitor for suspicious JavaScript patterns
    let suspiciousPatterns = 0;
    
    // Override common malicious functions (basic detection)
    const originalEval = window.eval;
    window.eval = function(...args) {
        console.warn('🚨 CyberGuard: eval() detected - potential malicious activity');
        suspiciousPatterns++;
        return originalEval.apply(this, args);
    };
    
    // Monitor for excessive redirects
    let redirectCount = 0;
    const originalReplace = window.location.replace;
    window.location.replace = function(...args) {
        redirectCount++;
        if (redirectCount > 3) {
            console.warn('🚨 CyberGuard: Excessive redirects detected');
        }
        return originalReplace.apply(this, args);
    };
}

// Listen for messages from background script
chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
    if (message.action === 'checkPage') {
        checkPageSafety();
        sendResponse({ status: 'checking' });
    }
});

console.log('✅ CyberGuard Pro protection initialized');