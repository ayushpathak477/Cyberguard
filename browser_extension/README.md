# CyberGuard Pro Browser Extension

A powerful browser extension that provides real-time website security monitoring and threat detection, integrated with the CyberGuard Pro cybersecurity dashboard.

## Features

🛡️ **Real-time Threat Detection** - Automatically scans websites as you browse
🚫 **Malicious Site Warnings** - Shows popup warnings for dangerous websites  
🔒 **Phishing Protection** - Monitors forms and login pages for phishing attempts
🦠 **Malware Detection** - Scans for suspicious JavaScript and malware activity
📊 **Integrated Dashboard** - Seamless connection with CyberGuard Pro backend
⚙️ **Customizable Settings** - Configure protection levels and preferences

## Installation

### Prerequisites
- Google Chrome or Chromium-based browser
- CyberGuard Pro backend running on `http://localhost:5000`

### Step 1: Load Extension in Chrome

1. Open Chrome and navigate to `chrome://extensions/`
2. Enable "Developer mode" (toggle in top-right corner)
3. Click "Load unpacked" button
4. Select the `browser_extension` folder from your CyberGuard Pro project directory:
   ```
   C:\Users\Ayush\Desktop\Data Science\Projects\Cyberguard\browser_extension
   ```
5. The extension should now appear in your extensions list

### Step 2: Verify Installation

1. Look for the CyberGuard Pro icon in your browser toolbar (🛡️)
2. Click the icon to open the popup interface
3. Verify it shows "Checking current website..." then displays site status

### Step 3: Configure Settings (Optional)

1. Right-click the extension icon and select "Options"
2. Or go to `chrome://extensions/` and click "Details" → "Extension options"
3. Configure your protection preferences:
   - API endpoint (default: http://localhost:5000)
   - Enable/disable protection features
   - Adjust check frequency
   - Enable debug logging

## Usage

### Automatic Protection
- The extension automatically monitors all websites you visit
- Threat warnings appear as full-screen overlays on dangerous sites
- Safe sites show a green checkmark in the extension popup
- Unsafe sites show a red warning badge on the extension icon

### Manual Checking
- Click the extension icon to view current site status
- Use the "🔄 Recheck" button to manually scan the current page
- Click "📊 Dashboard" to open the CyberGuard Pro web interface

### Threat Warnings
When a threat is detected, you'll see:
- Full-screen warning overlay with threat details
- Risk score and threat classification
- Options to go back safely or continue anyway
- Detailed reasons for the threat detection

## Extension Components

### Files Structure
```
browser_extension/
├── manifest.json          # Extension configuration
├── background.js           # Service worker for tab monitoring
├── content.js             # Runs on all web pages
├── popup.html             # Extension popup interface
├── popup.js               # Popup functionality
├── options.html           # Settings page
├── options.js             # Settings functionality
└── README.md              # This file
```

### Key Features

#### Background Script (`background.js`)
- Monitors tab navigation and URL changes
- Communicates with CyberGuard Pro API
- Updates extension badge with threat status
- Caches recent URL checks to improve performance

#### Content Script (`content.js`)
- Runs on all web pages for real-time protection
- Displays threat warning overlays
- Monitors form submissions for phishing
- Detects suspicious JavaScript activity

#### Popup Interface (`popup.html` / `popup.js`)
- Shows current website security status
- Displays threat details and risk scores
- Provides quick access to dashboard and settings
- Real-time connection status

#### Options Page (`options.html` / `options.js`)
- Configure API endpoint and connection settings
- Enable/disable protection features
- Adjust scanning frequency and behavior
- Test backend connectivity

## API Integration

The extension communicates with the CyberGuard Pro backend via the `/extension/check_url` endpoint:

```json
POST /extension/check_url
{
    "url": "https://example.com"
}

Response:
{
    "is_safe": false,
    "threat_type": "Phishing",
    "risk_score": 8,
    "reasons": ["Suspicious domain", "Known phishing patterns"],
    "url": "https://example.com"
}
```

## Troubleshooting

### Extension Not Working
1. Ensure CyberGuard Pro backend is running on `http://localhost:5000`
2. Check extension permissions in `chrome://extensions/`
3. Verify API endpoint in extension settings
4. Enable debug logging in options for detailed console output

### API Connection Issues
1. Test connection in extension options page
2. Verify backend is accessible at configured endpoint
3. Check browser console for error messages
4. Ensure no firewall blocking localhost connections

### Warnings Not Showing
1. Verify "Show Threat Warnings" is enabled in settings
2. Check if popup blockers are interfering
3. Test on a known malicious site (use caution)
4. Enable debug logging to see detection activity

## Development

### Testing the Extension
1. Load extension in developer mode
2. Open browser console (F12) to see debug messages
3. Visit test websites to verify functionality
4. Check extension popup for current site status

### Debugging
- Enable "Debug Logging" in extension options
- Check browser console for detailed logs
- Use `chrome://extensions/` to view extension errors
- Test API connectivity using browser network tools

## Security Notes

⚠️ **Important Security Considerations:**

1. The extension requires broad website permissions to monitor all pages
2. It communicates with a local backend service - ensure this is secure
3. Threat warnings can be bypassed by users - they are advisory only
4. The extension relies on the backend threat intelligence - keep it updated

## Support

For issues with the browser extension:
1. Check the CyberGuard Pro dashboard for backend status
2. Verify extension settings and permissions
3. Review browser console for error messages
4. Test API connectivity using the options page

## Version History

**v1.0** - Initial release
- Real-time website monitoring
- Threat warning overlays
- Dashboard integration
- Configurable settings
- Phishing and malware detection