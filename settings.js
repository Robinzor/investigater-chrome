// Settings page script for InvestigateR

// Load saved API keys on page load
document.addEventListener('DOMContentLoaded', async () => {
  const storage = await chrome.storage.local.get(['apiKeys', 'investigatorOptions']);
  const apiKeys = storage.apiKeys || {};
  const options = storage.investigatorOptions || {};
  
  // Populate input fields
  for (const [key, value] of Object.entries(apiKeys)) {
    const input = document.getElementById(key);
    if (input && value) {
      input.value = value;
    }
  }
  
  // Load options
  if (options.autoResolveIP !== undefined) {
    document.getElementById('autoResolveIP').checked = options.autoResolveIP;
  }
  if (options.passiveMode !== undefined) {
    document.getElementById('passiveMode').checked = options.passiveMode;
  }
  
  // Event listeners
  document.getElementById('saveBtn').addEventListener('click', saveSettings);
  document.getElementById('testBtn').addEventListener('click', testApiKeys);
  document.getElementById('clearBtn').addEventListener('click', clearSettings);
});

// Save settings
async function saveSettings() {
  const apiKeys = {
    virustotal: document.getElementById('virustotal')?.value.trim() || '',
    abuseipdb: document.getElementById('abuseipdb')?.value.trim() || '',
    alienvault: document.getElementById('alienvault')?.value.trim() || '',
    abusech: document.getElementById('abusech')?.value.trim() || '',
    urlquery: document.getElementById('urlquery')?.value.trim() || '',
    urlscan: document.getElementById('urlscan')?.value.trim() || '',
    ipinfo: document.getElementById('ipinfo')?.value.trim() || '',
    hybridanalysis: document.getElementById('hybridanalysis')?.value.trim() || '',
    shodan: document.getElementById('shodan')?.value.trim() || '',
    greynoise: document.getElementById('greynoise')?.value.trim() || ''
  };
  
  const investigatorOptions = {
    autoResolveIP: document.getElementById('autoResolveIP')?.checked || false,
    passiveMode: document.getElementById('passiveMode')?.checked || false
  };
  
  // Remove empty keys
  Object.keys(apiKeys).forEach(key => {
    if (!apiKeys[key]) delete apiKeys[key];
  });
  
  console.log('Saving API keys:', Object.keys(apiKeys));
  console.log('Saving options:', investigatorOptions);
  
  try {
    await chrome.storage.local.set({ apiKeys, investigatorOptions });
    
    // Verify save worked
    const verification = await chrome.storage.local.get(['apiKeys', 'investigatorOptions']);
    console.log('Verification - Saved keys:', verification.apiKeys);
    console.log('Verification - Saved options:', verification.investigatorOptions);
    
    showSuccess(`Settings saved successfully! ✓ (${Object.keys(apiKeys).length} API keys saved)`);
  } catch (error) {
    console.error('Save error:', error);
    showError(`Failed to save settings: ${error.message}`);
  }
}

// Test API keys
async function testApiKeys() {
  const testBtn = document.getElementById('testBtn');
  testBtn.disabled = true;
  testBtn.textContent = '🧪 Testing...';
  
  const apiKeys = {
    virustotal: document.getElementById('virustotal').value.trim(),
    abuseipdb: document.getElementById('abuseipdb').value.trim(),
    alienvault: document.getElementById('alienvault').value.trim(),
    abusech: document.getElementById('abusech').value.trim(),
    urlquery: document.getElementById('urlquery').value.trim(),
    urlscan: document.getElementById('urlscan').value.trim(),
    ipinfo: document.getElementById('ipinfo').value.trim(),
    hybridanalysis: document.getElementById('hybridanalysis').value.trim(),
    shodan: document.getElementById('shodan').value.trim(),
    greynoise: document.getElementById('greynoise').value.trim()
  };
  
  const results = [];
  
  // Test each API key
  for (const [service, apiKey] of Object.entries(apiKeys)) {
    if (!apiKey) {
      results.push(`${service}: Skipped (no key provided)`);
      continue;
    }
    
    try {
      const isValid = await testApiKey(service, apiKey);
      results.push(`${service}: ${isValid ? '✓ Valid' : '✗ Invalid'}`);
    } catch (error) {
      results.push(`${service}: ✗ Error - ${error.message}`);
    }
  }
  
  testBtn.disabled = false;
  testBtn.textContent = '🧪 Test API Keys';
  
  // Show results
  const hasErrors = results.some(r => r.includes('✗'));
  if (hasErrors) {
    showError('Test Results:\n' + results.join('\n'));
  } else {
    showSuccess('Test Results:\n' + results.join('\n'));
  }
}

// Test individual API key
async function testApiKey(service, apiKey) {
  switch (service) {
    case 'virustotal':
      const vtResponse = await fetch('https://www.virustotal.com/api/v3/ip_addresses/8.8.8.8', {
        headers: { 'x-apikey': apiKey }
      });
      return vtResponse.ok;
      
    case 'abuseipdb':
      const abuseResponse = await fetch('https://api.abuseipdb.com/api/v2/check?ipAddress=8.8.8.8', {
        headers: { 'Key': apiKey, 'Accept': 'application/json' }
      });
      return abuseResponse.ok;
      
    case 'alienvault':
      const otxResponse = await fetch('https://otx.alienvault.com/api/v1/indicators/IPv4/8.8.8.8/general', {
        headers: { 'X-OTX-API-KEY': apiKey }
      });
      return otxResponse.ok;
      
    case 'urlscan':
      return apiKey.length > 20;
      
    case 'ipinfo':
      const ipinfoResponse = await fetch(`https://ipinfo.io/8.8.8.8?token=${apiKey}`);
      return ipinfoResponse.ok;
      
    case 'hybridanalysis':
      return apiKey.length > 20;
      
    default:
      return false;
  }
}

// Clear all settings
async function clearSettings() {
  if (!confirm('Are you sure you want to clear all API keys? This action cannot be undone.')) {
    return;
  }
  
  try {
    await chrome.storage.local.remove(['apiKeys', 'investigatorOptions']);
    
    // Clear input fields
    document.getElementById('virustotal').value = '';
    document.getElementById('abuseipdb').value = '';
    document.getElementById('alienvault').value = '';
    document.getElementById('abusech').value = '';
    document.getElementById('urlscan').value = '';
    document.getElementById('ipinfo').value = '';
    document.getElementById('hybridanalysis').value = '';
    document.getElementById('shodan').value = '';
    document.getElementById('greynoise').value = '';
    document.getElementById('autoResolveIP').checked = false;
    document.getElementById('passiveMode').checked = false;
    
    showSuccess('All settings cleared successfully!');
  } catch (error) {
    showError(`Failed to clear settings: ${error.message}`);
  }
}

// Show success message
function showSuccess(message) {
  const successDiv = document.getElementById('successMessage');
  const errorDiv = document.getElementById('errorMessage');
  
  errorDiv.style.display = 'none';
  successDiv.textContent = message;
  successDiv.style.display = 'block';
  
  setTimeout(() => {
    successDiv.style.display = 'none';
  }, 5000);
}

// Show error message
function showError(message) {
  const successDiv = document.getElementById('successMessage');
  const errorDiv = document.getElementById('errorMessage');
  
  successDiv.style.display = 'none';
  errorDiv.textContent = message;
  errorDiv.style.display = 'block';
  
  setTimeout(() => {
    errorDiv.style.display = 'none';
  }, 8000);
}
