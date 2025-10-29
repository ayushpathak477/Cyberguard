// CyberGuard Pro - Background Script
// Monitors tab navigation and checks URLs for threats

const CYBERGUARD_API = 'http://localhost:5000';
let lastCheckedUrls = new Map();

// Listen for tab updates (navigation)
chrome.tabs.onUpdated.addListener(async (tabId, changeInfo, tab) => {
  // Only check when navigation is complete
  if (changeInfo.status === 'complete' && tab.url) {
    await checkUrlSafety(tab.url, tabId);
  }
});

// Listen for new tabs
chrome.tabs.onCreated.addListener(async (tab) => {
  if (tab.url) {
    await checkUrlSafety(tab.url, tab.id);
  }
});

// Check URL safety with CyberGuard backend
async function checkUrlSafety(url, tabId) {
  try {
    // Skip internal browser pages
    if (url.startsWith('chrome://') || url.startsWith('chrome-extension://') || 
        url.startsWith('about:') || url.startsWith('moz-extension://')) {
      return;
    }

    // Skip if we've already checked this URL recently
    const now = Date.now();
    if (lastCheckedUrls.has(url) && (now - lastCheckedUrls.get(url)) < 30000) {
      return;
    }

    console.log('🔍 CyberGuard: Checking URL:', url);

    // Call CyberGuard API
    const response = await fetch(`${CYBERGUARD_API}/extension/check_url`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
      },
      body: JSON.stringify({ url: url })
    });

    if (!response.ok) {
      console.error('CyberGuard API error:', response.status);
      return;
    }

    const result = await response.json();
    lastCheckedUrls.set(url, now);

    // If URL is unsafe, show warning
    if (!result.is_safe) {
      console.warn('🚫 CyberGuard: Threat detected!', result);
      await showThreatWarning(tabId, result);
      
      // Update badge to show threat detected
      chrome.action.setBadgeText({
        text: '⚠️',
        tabId: tabId
      });
      chrome.action.setBadgeBackgroundColor({
        color: '#ff3333',
        tabId: tabId
      });
    } else {
      // Clear badge for safe sites
      chrome.action.setBadgeText({
        text: '',
        tabId: tabId
      });
      
      console.log('✅ CyberGuard: Site is safe');
    }

    // Store result for popup
    chrome.storage.local.set({[`url_${tabId}`]: result});

  } catch (error) {
    console.error('CyberGuard check failed:', error);
  }
}

// Show threat warning popup
async function showThreatWarning(tabId, threatData) {
  try {
    // Inject warning popup into the page
    await chrome.scripting.executeScript({
      target: { tabId: tabId },
      func: showWarningPopup,
      args: [threatData]
    });
  } catch (error) {
    console.error('Failed to show warning popup:', error);
  }
}

// Function to be injected into the page (run in page context)
function showWarningPopup(threatData) {
  // Remove any existing warnings
  const existingWarning = document.getElementById('cyberguard-warning');
  if (existingWarning) {
    existingWarning.remove();
  }

  // Create warning overlay
  const overlay = document.createElement('div');
  overlay.id = 'cyberguard-warning';
  overlay.innerHTML = `
    <div style="
      position: fixed;
      top: 0;
      left: 0;
      width: 100%;
      height: 100%;
      background: rgba(0, 0, 0, 0.9);
      z-index: 999999;
      display: flex;
      align-items: center;
      justify-content: center;
      font-family: Arial, sans-serif;
    ">
      <div style="
        background: linear-gradient(135deg, #1a1a1a, #2d2d2d);
        color: white;
        padding: 40px;
        border-radius: 15px;
        max-width: 500px;
        text-align: center;
        border: 2px solid #ff3333;
        box-shadow: 0 0 30px rgba(255, 51, 51, 0.5);
      ">
        <h1 style="color: #ff3333; margin: 0 0 20px 0;">🛡️ CyberGuard Pro</h1>
        <div style="
          background: #ff3333;
          padding: 20px;
          border-radius: 10px;
          margin: 20px 0;
        ">
          <h2 style="margin: 0; font-size: 24px;">🚫 THREAT DETECTED</h2>
          <p style="margin: 10px 0 0 0;">This website may be dangerous!</p>
        </div>
        
        <div style="
          background: rgba(255,255,255,0.1);
          padding: 20px;
          border-radius: 10px;
          margin: 20px 0;
          text-align: left;
        ">
          <h3 style="margin: 0 0 15px 0; color: #ff3333;">Threat Details:</h3>
          <p><strong>URL:</strong> ${threatData.url}</p>
          <p><strong>Threat Type:</strong> ${threatData.threat_type || 'Unknown'}</p>
          <p><strong>Risk Score:</strong> ${threatData.risk_score}/10</p>
          ${threatData.reasons && threatData.reasons.length > 0 ? 
            `<p><strong>Reasons:</strong></p>
             <ul style="margin: 5px 0; padding-left: 20px;">
               ${threatData.reasons.map(reason => `<li>${reason}</li>`).join('')}
             </ul>` : ''
          }
        </div>
        
        <div style="margin-top: 30px;">
          <button onclick="history.back()" style="
            padding: 12px 20px;
            margin: 0 10px;
            background: #666;
            color: white;
            border: none;
            border-radius: 5px;
            cursor: pointer;
            font-size: 16px;
          ">← Go Back</button>
          
          <button onclick="document.getElementById('cyberguard-warning').style.display='none'" style="
            padding: 12px 20px;
            margin: 0 10px;
            background: #ff3333;
            color: white;
            border: none;
            border-radius: 5px;
            cursor: pointer;
            font-size: 16px;
          ">Continue Anyway (Not Recommended)</button>
        </div>
        
        <p style="margin-top: 20px; font-size: 12px; color: #aaa;">
          Protected by CyberGuard Pro
        </p>
      </div>
    </div>
  `;

  document.body.appendChild(overlay);
  
  // Auto-remove after 30 seconds if user doesn't interact
  setTimeout(() => {
    const warning = document.getElementById('cyberguard-warning');
    if (warning) {
      warning.style.display = 'none';
    }
  }, 30000);
}

// Handle extension installation
chrome.runtime.onInstalled.addListener(() => {
  console.log('🛡️ CyberGuard Pro extension installed!');
});