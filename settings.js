// Settings page script for InvestigateR

// Load saved API keys on page load
document.addEventListener('DOMContentLoaded', async () => {
  console.log('Settings page loaded - fetching stored data...');
  
  try {
    const storage = await chrome.storage.local.get(['apiKeys', 'investigatorOptions']);
    const apiKeys = storage.apiKeys || {};
    const options = storage.investigatorOptions || {};
    
    console.log('Loaded from storage:', {
      apiKeys: Object.keys(apiKeys),
      keyCount: Object.keys(apiKeys).length,
      options: options
    });
    
    // Populate input fields
    let fieldsPopulated = 0;
    for (const [key, value] of Object.entries(apiKeys)) {
      const input = document.getElementById(key);
      if (input && value) {
        input.value = value;
        fieldsPopulated++;
        console.log(`Populated field: ${key} (${value.length} chars)`);
      } else if (!input) {
        console.warn(`Input field not found: ${key}`);
      }
    }
    
    console.log(`✓ Populated ${fieldsPopulated} API key fields`);
    
    // Load options - check if elements exist first
    const autoResolveIPCheckbox = document.getElementById('autoResolveIP');
    if (autoResolveIPCheckbox && options.autoResolveIP !== undefined) {
      autoResolveIPCheckbox.checked = options.autoResolveIP;
    }
    
    const passiveModeCheckbox = document.getElementById('passiveMode');
    if (passiveModeCheckbox && options.passiveMode !== undefined) {
      passiveModeCheckbox.checked = options.passiveMode;
    }
    
    // Event listeners
    document.getElementById('saveBtn').addEventListener('click', saveSettings);
    document.getElementById('testBtn').addEventListener('click', testApiKeys);
    document.getElementById('clearBtn').addEventListener('click', clearSettings);
    
  } catch (error) {
    console.error('Error loading settings:', error);
    showError(`Failed to load settings: ${error.message}`);
  }
});

// Track if save is in progress
let isSaving = false;

// Save settings
async function saveSettings() {
  // Prevent concurrent saves
  if (isSaving) {
    console.warn('Save already in progress, ignoring duplicate request');
    return;
  }
  
  const saveBtn = document.getElementById('saveBtn');
  const originalText = saveBtn.textContent;
  
  try {
    // Set save state
    isSaving = true;
    saveBtn.disabled = true;
    saveBtn.textContent = '💾 Saving...';
    
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
    
    // Save to storage with explicit key names
    const dataToSave = {
      apiKeys: apiKeys,
      investigatorOptions: investigatorOptions
    };
    
    console.log('Data object to save:', dataToSave);
    
    // Save to storage
    await chrome.storage.local.set(dataToSave);
    console.log('chrome.storage.local.set() completed');
    
    // Wait a bit to ensure write completes
    await new Promise(resolve => setTimeout(resolve, 100));
    
    // Verify save worked
    const verification = await chrome.storage.local.get(['apiKeys', 'investigatorOptions']);
    console.log('Verification - Saved keys:', verification.apiKeys);
    console.log('Verification - Saved options:', verification.investigatorOptions);
    
    // Check if all keys were saved
    const savedKeyCount = Object.keys(verification.apiKeys || {}).length;
    const expectedKeyCount = Object.keys(apiKeys).length;
    
    if (savedKeyCount !== expectedKeyCount) {
      throw new Error(`Save verification failed: expected ${expectedKeyCount} keys but found ${savedKeyCount}`);
    }
    
    showSuccess(`Settings saved successfully! ✓ (${savedKeyCount} API keys saved)`);
  } catch (error) {
    console.error('Save error:', error);
    showError(`Failed to save settings: ${error.message}`);
  } finally {
    // Always restore button state
    isSaving = false;
    saveBtn.disabled = false;
    saveBtn.textContent = originalText;
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
    document.getElementById('urlquery').value = '';
    document.getElementById('urlscan').value = '';
    document.getElementById('ipinfo').value = '';
    document.getElementById('hybridanalysis').value = '';
    document.getElementById('shodan').value = '';
    document.getElementById('greynoise').value = '';
    
    // Clear checkboxes - check if they exist
    const autoResolveIPCheckbox = document.getElementById('autoResolveIP');
    if (autoResolveIPCheckbox) autoResolveIPCheckbox.checked = false;
    
    const passiveModeCheckbox = document.getElementById('passiveMode');
    if (passiveModeCheckbox) passiveModeCheckbox.checked = false;
    
    showSuccess('All settings cleared successfully!');
  } catch (error) {
    showError(`Failed to clear settings: ${error.message}`);
  }
}

// Show success message
function showSuccess(message) {
  console.log('✓ Success notification:', message);
  const successDiv = document.getElementById('successMessage');
  const errorDiv = document.getElementById('errorMessage');
  
  if (!successDiv) {
    console.error('Success message div not found!');
    alert(message); // Fallback to browser alert
    return;
  }
  
  // Hide error message
  errorDiv.style.display = 'none';
  
  // Show success message with animation
  successDiv.textContent = message;
  successDiv.style.display = 'block';
  
  // Auto-hide after 6 seconds
  setTimeout(() => {
    successDiv.style.display = 'none';
  }, 6000);
}

// Show error message
function showError(message) {
  console.error('✗ Error notification:', message);
  const successDiv = document.getElementById('successMessage');
  const errorDiv = document.getElementById('errorMessage');
  
  if (!errorDiv) {
    console.error('Error message div not found!');
    alert('Error: ' + message); // Fallback to browser alert
    return;
  }
  
  // Hide success message
  successDiv.style.display = 'none';
  
  // Show error message with animation
  errorDiv.textContent = message;
  errorDiv.style.display = 'block';
  
  // Auto-hide after 10 seconds
  setTimeout(() => {
    errorDiv.style.display = 'none';
  }, 10000);
}

// Debug function - call from browser console: debugStorage()
window.debugStorage = async function() {
  console.log('=== STORAGE DEBUG ===');
  const data = await chrome.storage.local.get(null); // Get everything
  console.log('All storage data:', data);
  console.log('API Keys:', data.apiKeys);
  console.log('Options:', data.investigatorOptions);
  
  // Check quota
  const quota = await chrome.storage.local.getBytesInUse();
  console.log(`Storage used: ${quota} bytes / ${chrome.storage.local.QUOTA_BYTES} bytes`);
  
  return data;
};

console.log('Settings.js loaded. Type debugStorage() in console to inspect storage.');
