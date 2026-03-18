// Popup script for InvestigateR Chrome Extension

let apiKeys = {};
let investigatorOptions = {};

// Initialize popup
document.addEventListener('DOMContentLoaded', async () => {
  // Load API keys and options from storage
  const storage = await chrome.storage.local.get(['apiKeys', 'investigatorOptions', 'pendingInvestigation']);
  apiKeys = storage.apiKeys || {};
  investigatorOptions = storage.investigatorOptions || {};
  
  // Set passive mode toggle state
  const passiveToggle = document.getElementById('passiveModeToggle');
  passiveToggle.checked = investigatorOptions.passiveMode || false;
  
  // If there's a pending investigation from context menu, populate input
  if (storage.pendingInvestigation) {
    document.getElementById('observableInput').value = storage.pendingInvestigation;
    chrome.storage.local.remove('pendingInvestigation');
  }
  
  // Event listeners
  document.getElementById('investigateBtn').addEventListener('click', handleInvestigate);
  document.getElementById('settingsBtn').addEventListener('click', openSettings);
  document.getElementById('fullscreenBtn').addEventListener('click', toggleFullscreen);
  document.getElementById('selectAllBtn').addEventListener('click', selectAllTools);
  document.getElementById('clearAllBtn').addEventListener('click', clearAllTools);
  passiveToggle.addEventListener('change', handlePassiveModeToggle);
  
  // Enable Enter key in textarea (Ctrl+Enter to submit)
  document.getElementById('observableInput').addEventListener('keydown', (e) => {
    if (e.ctrlKey && e.key === 'Enter') {
      handleInvestigate();
    }
  });
  
  // Dynamic tool filtering based on input
  document.getElementById('observableInput').addEventListener('input', filterToolsByInput);
  
  // Update API tools visibility based on configured keys
  updateApiToolsVisibility();
});

// Select all visible tools
function selectAllTools() {
  document.querySelectorAll('.tool-checkbox').forEach(cb => {
    if (cb.closest('.tool-item').style.display !== 'none') {
      cb.checked = true;
    }
  });
}

// Clear all tool selections
function clearAllTools() {
  document.querySelectorAll('.tool-checkbox').forEach(cb => {
    cb.checked = false;
  });
}

// Auto-select only compatible tools based on detected types
function autoSelectCompatibleTools() {
  const input = document.getElementById('observableInput').value.trim();
  
  if (!input) {
    selectAllTools();
    return;
  }
  
  // Parse and detect types
  const observables = input
    .split('\n')
    .map(line => line.trim())
    .filter(line => line && !line.startsWith('#'));
  
  const detectedTypes = new Set();
  observables.forEach(obs => {
    const type = detectObservableType(obs);
    if (type !== 'unknown') {
      detectedTypes.add(type);
    }
  });
  
  // Select only compatible tools
  document.querySelectorAll('.tool-checkbox').forEach(cb => {
    const item = cb.closest('.tool-item');
    const supportedTypes = item.dataset.types.split(',');
    const isSupported = Array.from(detectedTypes).some(type => 
      supportedTypes.includes(type)
    );
    
    // Only select if visible and supported
    if (item.style.display !== 'none' && isSupported) {
      cb.checked = true;
    } else {
      cb.checked = false;
    }
  });
}

// Update API tools visibility based on configured API keys
function updateApiToolsVisibility() {
  const apiToolItems = document.querySelectorAll('[data-section="api"]');
  let hasAnyApiKey = false;
  let configuredCount = 0;
  let totalApiTools = apiToolItems.length;
  
  apiToolItems.forEach(item => {
    const toolName = item.dataset.tool;
    
    // abuse.ch tools use shared abusech key
    const abuseChTools = ['threatfox', 'malwarebazaar', 'urlhaus'];
    const keyName = abuseChTools.includes(toolName) ? 'abusech' : toolName;
    const hasKey = apiKeys[keyName];
    
    if (hasKey) {
      hasAnyApiKey = true;
      configuredCount++;
      item.style.display = '';
      item.style.opacity = '1';
    } else {
      item.style.display = 'none';
    }
  });
  
  // Update API status indicator
  const apiStatus = document.getElementById('apiStatus');
  const apiSection = document.getElementById('apiToolSection');
  
  if (!hasAnyApiKey) {
    apiStatus.innerHTML = '<span style="color: #f39c12;">⚠ No API keys configured - <a href="#" id="configureLink" style="color: #00d4ff; text-decoration: underline;">Configure now</a></span>';
    apiSection.style.opacity = '0.6';
    document.getElementById('configureLink')?.addEventListener('click', (e) => {
      e.preventDefault();
      openSettings();
    });
  } else {
    apiStatus.innerHTML = `<span style="color: #2ecc71;">✓ ${configuredCount}/${totalApiTools} tools configured</span>`;
    apiSection.style.opacity = '1';
  }
}

// Filter tools based on observable types in input
function filterToolsByInput() {
  const input = document.getElementById('observableInput').value.trim();
  const detectionBadge = document.getElementById('detectionBadge');
  
  if (!input) {
    // Show all tools if no input
    document.querySelectorAll('.tool-item').forEach(item => {
      const isApiTool = item.dataset.section === 'api';
      const toolName = item.dataset.tool;
      
      // abuse.ch tools use shared abusech key
      const abuseChTools = ['threatfox', 'malwarebazaar', 'urlhaus'];
      const keyName = abuseChTools.includes(toolName) ? 'abusech' : toolName;
      const hasKey = apiKeys[keyName];
      
      const isActiveTool = item.dataset.active === 'true';
      const checkbox = item.querySelector('.tool-checkbox');
      
      // Hide active tools in passive mode
      if (investigatorOptions.passiveMode && isActiveTool) {
        item.style.display = 'none';
        checkbox.checked = false;
      } else if (isApiTool && !hasKey) {
        item.style.display = 'none';
      } else {
        item.style.display = '';
      }
    });
    detectionBadge.classList.add('hidden');
    return;
  }
  
  // Parse observables
  const observables = input
    .split('\n')
    .map(line => line.trim())
    .filter(line => line && !line.startsWith('#'));
  
  if (observables.length === 0) {
    detectionBadge.classList.add('hidden');
    return;
  }
  
  // Detect types
  const detectedTypes = new Set();
  const typeCount = { ip: 0, domain: 0, url: 0, hash: 0, unknown: 0 };
  
  observables.forEach(obs => {
    const type = detectObservableType(obs);
    if (type !== 'unknown') {
      detectedTypes.add(type);
      typeCount[type]++;
      
      // If it's a URL, also check if we can extract IP or domain from it
      if (type === 'url') {
        try {
          const urlObj = new URL(obs.includes('://') ? obs : `http://${obs}`);
          const host = urlObj.hostname;
          
          // Check if extracted host is IP or domain
          if (/^(\d{1,3}\.){3}\d{1,3}$/.test(host)) {
            detectedTypes.add('ip');
            // Don't increment typeCount for extracted types
          } else if (/^([a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$/.test(host)) {
            detectedTypes.add('domain');
            // Don't increment typeCount for extracted types
          }
        } catch (e) {
          // Invalid URL, continue
        }
      }
    } else {
      typeCount.unknown++;
    }
  });
  
  // Show detection badge in header
  if (detectedTypes.size > 0) {
    const typeIcons = {
      ip: '🌐',
      domain: '🔗',
      url: '🔗',
      hash: '🔐'
    };
    
    const detectedList = Array.from(detectedTypes)
      .map(type => `${typeIcons[type]}${typeCount[type]}`)
      .join(' ');
    
    detectionBadge.textContent = detectedList;
    if (typeCount.unknown > 0) {
      detectionBadge.textContent += ` ⚠️${typeCount.unknown}`;
    }
    detectionBadge.classList.remove('hidden');
  } else {
    detectionBadge.classList.add('hidden');
  }
  
  // Show/hide and auto-select tools based on detected types
  document.querySelectorAll('.tool-item').forEach(item => {
    const supportedTypes = item.dataset.types.split(',');
    const isSupported = Array.from(detectedTypes).some(type => 
      supportedTypes.includes(type)
    );
    
    // For API tools, also check if key is configured
    const isApiTool = item.dataset.section === 'api';
    const toolName = item.dataset.tool;
    
    // abuse.ch tools use shared abusech key
    const abuseChTools = ['threatfox', 'malwarebazaar', 'urlhaus'];
    const keyName = abuseChTools.includes(toolName) ? 'abusech' : toolName;
    const hasKey = apiKeys[keyName];
    
    const checkbox = item.querySelector('.tool-checkbox');
    const isActiveTool = item.dataset.active === 'true';
    
    // Hide active tools in passive mode
    if (investigatorOptions.passiveMode && isActiveTool) {
      item.style.display = 'none';
      checkbox.checked = false;
    } else if (isApiTool && !hasKey) {
      item.style.display = 'none';
      checkbox.checked = false;
    } else if (isSupported || detectedTypes.size === 0) {
      item.style.display = '';
    } else {
      item.style.display = 'none';
      checkbox.checked = false;
    }
  });
}

// Open settings page
function openSettings() {
  chrome.runtime.openOptionsPage();
}

// Toggle fullscreen mode
function toggleFullscreen() {
  // Open extension popup in new tab for fullscreen experience
  chrome.tabs.create({
    url: chrome.runtime.getURL('popup.html')
  });
}

// Handle investigate button click
async function handleInvestigate() {
  const input = document.getElementById('observableInput').value.trim();
  
  if (!input) {
    showError('Please enter at least one observable (IP, domain, URL, or hash)');
    return;
  }
  
  // Parse observables (one per line)
  let observables = input
    .split('\n')
    .map(line => line.trim())
    .filter(line => line && !line.startsWith('#'))
    .map(line => refangObservable(line)); // Refang defanged IOCs
  
  if (observables.length === 0) {
    showError('No valid observables found');
    return;
  }
  
  // Auto-resolve IP addresses if option is enabled
  if (investigatorOptions.autoResolveIP) {
    const resolvedDomains = [];
    for (const obs of observables) {
      const type = detectObservableType(obs);
      if (type === 'ip') {
        const domain = await reverseDnsLookup(obs);
        if (domain && !observables.includes(domain) && !resolvedDomains.includes(domain)) {
          resolvedDomains.push(domain);
        }
      }
    }
    // Add resolved domains to the list
    if (resolvedDomains.length > 0) {
      observables = [...observables, ...resolvedDomains];
    }
  }
  
  // Get selected tools
  const selectedTools = Array.from(document.querySelectorAll('.tool-checkbox:checked'))
    .map(cb => cb.value);
  
  if (selectedTools.length === 0) {
    showError('Please select at least one tool');
    return;
  }
  
  // Sort tools: premium (API) tools first, then free tools
  selectedTools.sort((a, b) => {
    const aRequiresKey = TOOL_CONFIGS[a]?.requiresKey || false;
    const bRequiresKey = TOOL_CONFIGS[b]?.requiresKey || false;
    if (aRequiresKey && !bRequiresKey) return -1;
    if (!aRequiresKey && bRequiresKey) return 1;
    return 0;
  });
  
  // Show loading, hide previous results
  showLoading(true);
  clearResults();
  document.getElementById('noResults').classList.add('hidden');
  
  // Disable button during processing
  const btn = document.getElementById('investigateBtn');
  btn.disabled = true;
  btn.textContent = '🔄 Investigating...';
  
  try {
    // Process observables using optimized parallel queries
    await processObservablesOptimized(observables, selectedTools);
  } catch (error) {
    showError(`Investigation failed: ${error.message}`);
  } finally {
    showLoading(false);
    btn.disabled = false;
    btn.textContent = '🔍 Investigate';
  }
}

// Handle passive mode toggle
async function handlePassiveModeToggle(e) {
  investigatorOptions.passiveMode = e.target.checked;
  
  // Save to storage
  await chrome.storage.local.set({ investigatorOptions });
  
  // Refresh tool visibility
  filterToolsByInput();
  
  // Show notification
  if (investigatorOptions.passiveMode) {
    showSuccess('🕵️ Passive Mode enabled - VirusTotal hidden (avoids triggering new scans)');
  } else {
    showSuccess('✓ Active Mode enabled - All tools available');
  }
}

// Reverse DNS lookup for IPs
async function reverseDnsLookup(ip) {
  try {
    // Use Google DNS-over-HTTPS for reverse DNS lookup
    const arpa = ip.split('.').reverse().join('.') + '.in-addr.arpa';
    const response = await fetch(`https://dns.google/resolve?name=${arpa}&type=PTR`, {
      method: 'GET'
    });
    
    if (!response.ok) return null;
    
    const data = await response.json();
    if (data.Answer && data.Answer.length > 0) {
      // Return the first PTR record, remove trailing dot
      return data.Answer[0].data.replace(/\.$/, '');
    }
    return null;
  } catch (error) {
    return null;
  }
}

// Optimized processing - query all tools in parallel and display results as they arrive
async function processObservablesOptimized(observables, tools) {
  const resultsContainer = document.getElementById('results');
  
  // Create cards for all observables immediately
  const cards = {};
  observables.forEach(observable => {
    const card = createObservableCard(observable);
    resultsContainer.appendChild(card);
    cards[observable] = card;
  });
  
  // Process all observables in parallel
  const promises = observables.map(async (observable) => {
    const type = detectObservableType(observable);
    const card = cards[observable];
    
    // Extract IP or domain from URLs for additional tool queries
    let extractedHost = null;
    let extractedHostType = null;
    
    if (type === 'url') {
      try {
        const urlObj = new URL(observable.includes('://') ? observable : `http://${observable}`);
        const host = urlObj.hostname;
        
        // Determine if extracted host is IP or domain
        if (/^(\d{1,3}\.){3}\d{1,3}$/.test(host)) {
          extractedHost = host;
          extractedHostType = 'ip';
        } else if (/^([a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$/.test(host)) {
          extractedHost = host;
          extractedHostType = 'domain';
        }
      } catch (e) {
        // Invalid URL, continue with just URL type
      }
    }
    
    // Query all tools for this observable in parallel
    const queriedTools = new Set();
    const toolPromises = tools.map(async (tool) => {
      try {
        const result = await queryToolDirectly(tool, observable, type);
        queriedTools.add(tool);
        // Display result immediately as it arrives
        addToolResult(card, tool, result);
      } catch (error) {
        queriedTools.add(tool);
        addToolResult(card, tool, {
          status: 'error',
          error: error.message
        });
      }
    });
    
    // If we extracted a host from URL, also query IP/domain-specific tools
    if (extractedHost && extractedHostType) {
      const hostToolPromises = tools.map(async (tool) => {
        try {
          // Skip if already queried
          if (queriedTools.has(tool)) return;
          
          const toolConfig = TOOL_CONFIGS[tool];
          // Only query if tool supports the extracted host type but not URLs
          if (toolConfig && toolConfig.types.includes(extractedHostType) && !toolConfig.types.includes('url')) {
            const result = await queryToolDirectly(tool, extractedHost, extractedHostType);
            // Display result immediately as it arrives
            addToolResult(card, tool, result);
          }
        } catch (error) {
          // Silently ignore errors for extracted host queries
        }
      });
      toolPromises.push(...hostToolPromises);
    }
    
    await Promise.all(toolPromises);
    
    // Update risk assessment after all tools complete
    updateRiskBadge(card, observable);
  });
  
  await Promise.all(promises);
}

// Query tool directly (optimized for speed)
async function queryToolDirectly(toolName, observable, type) {
  const tool = TOOL_CONFIGS[toolName];
  
  if (!tool) {
    throw new Error('Unknown tool');
  }
  
  // Strip port number from IP or domain if present
  let cleanObservable = observable;
  if ((type === 'ip' || type === 'domain') && observable.includes(':')) {
    // Check if it's not a URL (URLs have :// not just :)
    if (!observable.includes('://')) {
      const lastColonIndex = observable.lastIndexOf(':');
      const portPart = observable.substring(lastColonIndex + 1);
      // Verify it's actually a port number
      if (/^\d+$/.test(portPart)) {
        cleanObservable = observable.substring(0, lastColonIndex);
      }
    }
  }
  
  // Skip active tools in passive mode (VirusTotal may trigger new scans)
  const activeTools = ['virustotal'];
  if (investigatorOptions.passiveMode && activeTools.includes(toolName)) {
    return {
      status: 'skipped',
      message: '⚠️ Disabled in Passive Mode (avoids alerting target)'
    };
  }
  
  // Check if tool supports this type
  if (!tool.types.includes(type)) {
    return {
      status: 'skipped',
      message: `Does not support ${type} lookups`
    };
  }
  
  // Check API key requirement
  if (tool.requiresKey) {
    // abuse.ch tools (ThreatFox, MalwareBazaar, URLhaus) use shared abusech key
    const abuseChTools = ['threatfox', 'malwarebazaar', 'urlhaus'];
    const keyName = abuseChTools.includes(toolName) ? 'abusech' : toolName;
    
    if (!apiKeys[keyName]) {
      return {
        status: 'skipped',
        message: 'API key required (configure in settings)'
      };
    }
    
    const result = await tool.query(cleanObservable, type, apiKeys[keyName]);
    return result;
  }
  
  const result = await tool.query(cleanObservable, type, apiKeys[toolName]);
  return result;
}

// Create observable card
function createObservableCard(observable) {
  const card = document.createElement('div');
  card.className = 'observable-card';
  card.dataset.observable = observable;
  
  card.innerHTML = `
    <div class="observable-header">
      <div class="observable-value">${escapeHtml(observable)}</div>
      <div class="risk-badge risk-unknown">Analyzing...</div>
    </div>
    <div class="tool-results"></div>
  `;
  
  return card;
}

// Check if result has no relevant data (clean/empty result)
function hasNoRelevantData(toolName, result) {
  if (result.status !== 'success') return false;
  if (!result.data) return false;
  
  const data = result.data;
  const text = JSON.stringify(data).toLowerCase();
  
  // Tool-specific clean checks
  switch(toolName) {
    case 'whois':
      // WHOIS errors or unable to fetch
      if (text.includes('error') || text.includes('unable to fetch')) return true;
      break;
      
    case 'sansisc':
      // SANS ISC with 0 attacks and no useful comment
      if ((data.attacks === 0 || data.count === 0) && 
          (!data.comment || data.comment === 'None' || data.comment === 'N/A')) return true;
      break;
      
    case 'greynoise':
      // GreyNoise showing benign + RIOT (trusted) is actually useful info, don't hide
      // But if it's unknown/not seen, hide it
      if (text.includes('classification: unknown') && text.includes('noise: no')) return true;
      break;
      
    case 'cloudflareip':
      // Cloudflare IPs are informational - only show when it IS Cloudflare
      if (text.includes('iscloudflare":false') || text.includes('"iscloudflare":false') || 
          text.includes('ip is not a cloudflare ip')) return true;
      break;
      
    case 'shodan':
      // Shodan with no data (404 or empty results) is clean
      if ((text.includes('"ports":"none"') || text.includes('ports: none')) && 
          (text.includes('"vulns":"none"') || text.includes('vulns: none')) && 
          (text.includes('"tags":"none"') || text.includes('tags: none'))) return true;
      break;
      
    case 'openphish':
      if (text.includes('not found in feed') || text.includes('message: not found')) return true;
      break;
      
    case 'phishtank':
      // Check if not in database (clean result)
      if (text.includes('not reported as phishing') || 
          (text.includes('indatabase:false') || text.includes('indatabase":false')) ||
          (text.includes('isphishing:false') || text.includes('isphishing":false'))) return true;
      break;
      
    case 'ipblocklists':
    case 'domainblocklists':
      if (text.includes('found: 0') || text.includes('not found in')) return true;
      break;
      
    case 'virustotal':
      if (text.includes('malicious: 0') && text.includes('suspicious: 0')) return true;
      break;
      
    case 'abuseipdb':
      if (text.includes('abuse score: 0%') || text.includes('total reports: 0')) return true;
      break;
      
    case 'alienvault':
      if (text.includes('pulsecount":0') || text.includes('pulsecount:0') || 
          text.includes('not found in feeds')) return true;
      break;
      
    case 'urlscan':
      if (text.includes('found: no') || text.includes('not found') || 
          text.includes('no results') || text.includes('found": false') ||
          text.includes('no previous scans found')) return true;
      break;
      
    case 'hybridanalysis':
      if (text.includes('found: no') || text.includes('found": "no"') ||
          text.includes('not found') || text.includes('no results') || 
          text.includes('found": false') || text.includes('"found":false') ||
          text.includes('verdict: undefined') || text.includes('verdict": undefined') ||
          text.includes('threat score: undefined') || text.includes('threatscore: undefined')) return true;
      break;
      
    case 'threatfox':
    case 'malwarebazaar':
    case 'urlhaus':
      if (text.includes('found: no') || text.includes('found in database: no') ||
          text.includes('not found') || text.includes('no results') || 
          text.includes('found": false') || text.includes('"found":false')) return true;
      break;
      
    case 'dnsrecords':
      // DNS resolution is always relevant info
      return false;
      
    case 'urlquery':
      // URLquery with no reports found is clean
      if (text.includes('found":false') || text.includes('found": false') ||
          text.includes('total_hits":0') || text.includes('total_hits": 0')) return true;
      break;
  }
  
  // General clean indicators
  if (text.includes('no certificates') || text.includes('certificates: 0')) return true;
  if (text.includes('threat score: 0') || text.includes('verdict: no verdict')) return true;
  if (text.includes('no threats detected') || text.includes('clean: yes')) return true;
  
  return false;
}

// Add tool result to card
function addToolResult(card, toolName, result) {
  const resultsContainer = card.querySelector('.tool-results');
  const resultDiv = document.createElement('div');
  resultDiv.className = 'tool-result';
  
  // Mark if this result has no relevant data
  const isEmpty = hasNoRelevantData(toolName, result);
  if (isEmpty) {
    resultDiv.classList.add('empty-result');
  }
  
  const toolDisplayName = toolName.charAt(0).toUpperCase() + toolName.slice(1);
  
  if (result.status === 'skipped') {
    resultDiv.innerHTML = `
      <div class="tool-name">
        ${toolDisplayName}
        <span class="tool-status" style="background: #95a5a6;">Skipped</span>
      </div>
      <div class="tool-data">${result.message}</div>
    `;
  } else if (result.status === 'error') {
    resultDiv.innerHTML = `
      <div class="tool-name">
        ${toolDisplayName}
        <span class="tool-status status-error">Error</span>
      </div>
      <div class="tool-data">Error: ${escapeHtml(result.error)}</div>
    `;
  } else {
    // Check if formatted data starts with a styled header div
    const formattedData = toolName === 'urlquery' ? formatToolData(toolName, result.data, result) : formatToolData(toolName, result.data);
    const hasStyledHeader = formattedData.includes('<div style="background:') && formattedData.includes('border-left:');
    
    if (hasStyledHeader) {
      // Tool has its own styled header, hide redundant tool name
      resultDiv.innerHTML = `
        <div class="tool-data">${formattedData}</div>
      `;
    } else {
      // Show tool name and success badge for tools without styled headers
      resultDiv.innerHTML = `
        <div class="tool-name">
          ${toolDisplayName}
          <span class="tool-status status-success">✓ Success</span>
        </div>
        <div class="tool-data">${formattedData}</div>
      `;
    }
  }
  
  // Add clean results to clean footer, errors to error footer, others to main container
  if (isEmpty) {
    addToCleanFooter(card, resultDiv, toolDisplayName);
  } else if (result.status === 'error') {
    // Only add actual errors to error footer (not type incompatibility skips)
    addToErrorFooter(card, resultDiv, toolDisplayName, result.status);
  } else if (result.status === 'skipped' && 
             !(result.message && (result.message.includes('Does not support') || 
                                  result.message.includes('Disabled in Passive Mode')))) {
    // Only add unexpected skips to error footer
    addToErrorFooter(card, resultDiv, toolDisplayName, result.status);
  } else if (result.status === 'skipped') {
    // Type incompatibility or passive mode skips - hide completely
    return;
  } else {
    // Insert before footers if they exist, otherwise append
    const resultsContainer = card.querySelector('.tool-results');
    const footer = resultsContainer.querySelector('.compact-results, .error-results');
    if (footer) {
      resultsContainer.insertBefore(resultDiv, footer);
    } else {
      resultsContainer.appendChild(resultDiv);
    }
  }
}

// Add error/skipped result to error footer section
function addToErrorFooter(card, resultDiv, toolName, status) {
  const resultsContainer = card.querySelector('.tool-results');
  
  // Find or create error footer
  let footer = resultsContainer.querySelector('.error-results');
  if (!footer) {
    footer = document.createElement('div');
    footer.className = 'error-results';
    footer.style.cssText = 'margin-top: 12px; padding: 8px 12px; background: rgba(149, 165, 166, 0.05); border: 1px solid rgba(149, 165, 166, 0.2); border-radius: 6px;';
    
    const headerDiv = document.createElement('div');
    headerDiv.className = 'footer-header';
    headerDiv.style.cssText = 'display: flex; align-items: center; gap: 8px; margin-bottom: 4px;';
    headerDiv.innerHTML = `
      <strong class="footer-count" style="color: #95a5a6; font-size: 12px;">⚠️ ERROR (0)</strong>
      <button class="toggle-error-btn" style="background: none; border: 1px solid rgba(149, 165, 166, 0.3); color: #95a5a6; padding: 2px 8px; border-radius: 3px; font-size: 10px; cursor: pointer;">Toggle</button>
    `;
    
    const toolNamesDiv = document.createElement('div');
    toolNamesDiv.className = 'footer-tools';
    toolNamesDiv.style.cssText = 'font-size: 11px; color: #95a5a6;';
    
    const hiddenSection = document.createElement('div');
    hiddenSection.className = 'error-details';
    hiddenSection.style.cssText = 'margin-top: 8px; display: none;';
    
    // Add toggle functionality
    const toggleBtn = headerDiv.querySelector('.toggle-error-btn');
    toggleBtn.addEventListener('click', () => {
      const isHidden = hiddenSection.style.display === 'none';
      hiddenSection.style.display = isHidden ? 'block' : 'none';
      toggleBtn.textContent = isHidden ? 'Hide' : 'Toggle';
    });
    
    footer.appendChild(headerDiv);
    footer.appendChild(toolNamesDiv);
    footer.appendChild(hiddenSection);
    
    // Insert before clean footer if it exists, otherwise append
    const cleanFooter = resultsContainer.querySelector('.compact-results');
    if (cleanFooter) {
      resultsContainer.insertBefore(footer, cleanFooter);
    } else {
      resultsContainer.appendChild(footer);
    }
  }
  
  // Update count
  const countEl = footer.querySelector('.footer-count');
  const hiddenSection = footer.querySelector('.error-details');
  const currentCount = hiddenSection.children.length;
  countEl.textContent = `⚠️ ERROR (${currentCount + 1})`;
  
  // Update tool names list
  const toolNamesDiv = footer.querySelector('.footer-tools');
  const currentTools = toolNamesDiv.textContent ? toolNamesDiv.textContent.split(' • ') : [];
  currentTools.push(toolName);
  toolNamesDiv.textContent = currentTools.join(' • ');
  
  // Add result to hidden section
  resultDiv.style.cssText = 'margin-bottom: 6px; padding: 6px; background: rgba(26, 35, 51, 0.3); border-radius: 4px; font-size: 11px;';
  hiddenSection.appendChild(resultDiv);
}

// Add clean result to footer section
function addToCleanFooter(card, resultDiv, toolName) {
  const resultsContainer = card.querySelector('.tool-results');
  
  // Find or create footer
  let footer = resultsContainer.querySelector('.compact-results');
  if (!footer) {
    footer = document.createElement('div');
    footer.className = 'compact-results';
    footer.style.cssText = 'margin-top: 12px; padding: 8px 12px; background: rgba(46, 204, 113, 0.05); border: 1px solid rgba(46, 204, 113, 0.2); border-radius: 6px;';
    
    const headerDiv = document.createElement('div');
    headerDiv.className = 'footer-header';
    headerDiv.style.cssText = 'display: flex; align-items: center; gap: 8px; margin-bottom: 4px;';
    headerDiv.innerHTML = `
      <strong class="footer-count" style="color: #2ecc71; font-size: 12px;">✓ CLEAN (0)</strong>
      <button class="toggle-empty-btn" style="background: none; border: 1px solid rgba(46, 204, 113, 0.3); color: #2ecc71; padding: 2px 8px; border-radius: 3px; font-size: 10px; cursor: pointer;">Toggle</button>
    `;
    
    const toolNamesDiv = document.createElement('div');
    toolNamesDiv.className = 'footer-tools';
    toolNamesDiv.style.cssText = 'font-size: 11px; color: #95a5a6;';
    
    const hiddenSection = document.createElement('div');
    hiddenSection.className = 'empty-details';
    hiddenSection.style.cssText = 'margin-top: 8px; display: none;';
    
    // Add toggle functionality
    const toggleBtn = headerDiv.querySelector('.toggle-empty-btn');
    toggleBtn.addEventListener('click', () => {
      const isHidden = hiddenSection.style.display === 'none';
      hiddenSection.style.display = isHidden ? 'block' : 'none';
      toggleBtn.textContent = isHidden ? 'Hide' : 'Toggle';
    });
    
    footer.appendChild(headerDiv);
    footer.appendChild(toolNamesDiv);
    footer.appendChild(hiddenSection);
    resultsContainer.appendChild(footer);
  }
  
  // Update count
  const countEl = footer.querySelector('.footer-count');
  const hiddenSection = footer.querySelector('.empty-details');
  const currentCount = hiddenSection.children.length;
  countEl.textContent = `✓ CLEAN (${currentCount + 1})`;
  
  // Update tool names list
  const toolNamesDiv = footer.querySelector('.footer-tools');
  const currentTools = toolNamesDiv.textContent ? toolNamesDiv.textContent.split(' • ') : [];
  currentTools.push(toolName);
  toolNamesDiv.textContent = currentTools.join(' • ');
  
  // Add result to hidden section
  resultDiv.style.cssText = 'margin-bottom: 6px; padding: 6px; background: rgba(26, 35, 51, 0.3); border-radius: 4px; font-size: 11px;';
  hiddenSection.appendChild(resultDiv);
}

// Format tool-specific data
function formatToolData(toolName, data) {
  let html = '';
  
  // Special case: pass full result object for urlquery debugging
  let resultObj = null;
  if (toolName === 'urlquery' && !data) {
    resultObj = arguments[2]; // Get the full result from the third argument
  }
  
  switch (toolName) {
    case 'ipinfo':
      html = `
        <div style="background: #1a2333; padding: 8px; border-radius: 4px; margin-bottom: 6px; border-left: 3px solid #3498db;">
          <strong style="font-size: 14px; color: #3498db;">📍 IPInfo</strong>
        </div>
        <strong>🏙️ City:</strong> ${data.city}<br>
        <strong>🗺️ Region:</strong> ${data.region}<br>
        <strong>🌍 Country:</strong> ${data.country}<br>
        <strong>📮 Postal:</strong> ${data.postal}<br>
        <strong>🏢 Organization:</strong> ${data.org}<br>
        <strong>🕐 Timezone:</strong> ${data.timezone}<br>
        <div style="margin-top: 6px;">
          <a href="${data.url}" target="_blank" style="background: #3498db; color: white; padding: 4px 12px; border-radius: 4px; text-decoration: none; display: inline-block;">🗺️ View Map</a>
        </div>
      `;
      break;
      
    case 'greynoise':
      const isNoise = data.noise === 'Yes';
      const isMalicious = data.classification === 'malicious';
      html = `
        <div style="background: ${isMalicious ? 'rgba(231, 76, 60, 0.1)' : 'rgba(149, 165, 166, 0.1)'}; padding: 8px; border-radius: 4px; margin-bottom: 6px; border-left: 3px solid ${isMalicious ? '#e74c3c' : '#95a5a6'};">
          <strong style="font-size: 14px; color: ${isMalicious ? '#e74c3c' : '#95a5a6'};">📊 GreyNoise</strong>
        </div>
        <strong>🔊 Internet Noise:</strong> ${data.noise} ${isNoise ? '📡' : '✓'}<br>
        <strong>🛡️ RIOT (Trusted):</strong> ${data.riot}<br>
        <strong>⚠️ Classification:</strong> ${data.classification.toUpperCase()}<br>
        <strong>🏷️ Name:</strong> ${data.name}<br>
        <strong>🕐 Last Seen:</strong> ${data.lastSeen}<br>
        <div style="margin-top: 6px;">
          <a href="${data.url}" target="_blank" style="background: #27ae60; color: white; padding: 4px 12px; border-radius: 4px; text-decoration: none; display: inline-block;">📊 GreyNoise Viz</a>
        </div>
      `;
      break;
      
    case 'cloudflareip':
      html = `
        <div style="background: ${data.isCloudflare ? 'rgba(241, 196, 15, 0.1)' : 'rgba(149, 165, 166, 0.1)'}; padding: 8px; border-radius: 4px; margin-bottom: 6px; border-left: 3px solid ${data.isCloudflare ? '#f1c40f' : '#95a5a6'};">
          <strong style="font-size: 14px; color: ${data.isCloudflare ? '#f39c12' : '#95a5a6'};">☁️ Cloudflare IP Check</strong>
        </div>
        <strong>🔍 Status:</strong> ${data.isCloudflare ? 'Cloudflare Network ☁️' : 'Not Cloudflare ✓'}<br>
        <strong>ℹ️ Info:</strong> ${data.message}<br>
        <strong>⚠️ Risk Level:</strong> ${data.isCloudflare ? '🟡 Low (Legitimate CDN)' : '⚪ N/A'}<br>
        <div style="margin-top: 6px;">
          <a href="${data.url}" target="_blank" style="background: #f39c12; color: white; padding: 4px 12px; border-radius: 4px; text-decoration: none; display: inline-block;">☁️ Cloudflare IPs</a>
        </div>
      `;
      break;
      
    case 'urlquery':
      const uqFound = data?.found && data?.total_hits > 0;
      const hasData = data && Object.keys(data).length > 0;
      const reports = data?.reports || [];
      
      // Analyze reports for summary stats
      let maliciousCount = 0;
      let suspiciousCount = 0;
      const relatedDomains = new Set();
      
      reports.forEach(r => {
        const detection = r.detection?.analyzer?.[0];
        const verdict = detection?.verdict;
        const tags = r.tags || [];
        
        // Check tags for malware indicators
        const hasMalwareTags = tags.some(tag => 
          tag.toLowerCase().includes('malware') || 
          tag.toLowerCase().includes('phishing') ||
          tag.toLowerCase().includes('botnet') ||
          tag.toLowerCase().includes('ransomware') ||
          tag.toLowerCase().includes('trojan') ||
          tag.toLowerCase().includes('backdoor')
        );
        
        // Get the report's domain to check if it matches searched domain
        const reportDomain = r.url?.fqdn || r.url?.domain || '';
        const searchedDomain = (data?.observable || '').toLowerCase()
          .replace(/^https?:\/\//, '')  // Remove protocol
          .replace(/^www\./, '')         // Remove www
          .replace(/\/.*$/, '')          // Remove path and trailing slash
          .trim();
        const reportDomainClean = reportDomain.toLowerCase()
          .replace(/^www\./, '')
          .replace(/\/$/, '')            // Remove trailing slash
          .trim();
        
        // Only count as malicious/suspicious if the report is actually about the searched domain
        const isSearchedDomain = reportDomainClean === searchedDomain || 
                                  reportDomainClean.endsWith('.' + searchedDomain) ||
                                  searchedDomain.endsWith('.' + reportDomainClean);
        
        if (isSearchedDomain) {
          if (verdict === 'malicious' || hasMalwareTags) {
            maliciousCount++;
          } else if (verdict === 'suspicious') {
            suspiciousCount++;
          }
        } else {
          // This is a different domain - add to related domains
          if (reportDomain) {
            relatedDomains.add(reportDomain);
          }
        }
        
        // Also collect from final URL if redirect occurred
        const finalDomain = r.final?.url?.fqdn || r.final?.url?.domain;
        if (finalDomain) {
          const finalDomainClean = finalDomain.toLowerCase()
            .replace(/^www\./, '')
            .replace(/\/$/, '')
            .trim();
          if (finalDomainClean !== searchedDomain && 
              !finalDomainClean.endsWith('.' + searchedDomain) &&
              !searchedDomain.endsWith('.' + finalDomainClean)) {
            relatedDomains.add(finalDomain);
          }
        }
      });
      
      html = `
        <div style="background: ${uqFound ? 'rgba(231, 76, 60, 0.1)' : 'rgba(149, 165, 166, 0.1)'}; padding: 8px; border-radius: 4px; margin-bottom: 6px; border-left: 3px solid ${uqFound ? '#e74c3c' : '#95a5a6'};">
          <strong style="font-size: 14px; color: ${uqFound ? '#e74c3c' : '#95a5a6'};">🔎 URLquery</strong>
        </div>
        ${data?.error_message ? `<strong style="color: #e74c3c;">⚠️ ERROR: ${data.error_message}</strong><br>` : ''}
        ${!hasData ? '<strong style="color: #e74c3c;">⚠️ ERROR: No data received</strong><br>' : ''}
        <strong>🔍 Database Status:</strong> ${uqFound ? 'FOUND ⚠️' : 'NOT FOUND ✓'}<br>
        <strong>📊 Total Reports:</strong> ${data?.total_hits || 0}<br>
        ${data?.query_string ? `<strong style="font-size: 11px; color: #999;">🔎 Search Query:</strong> <code style="background: rgba(0,0,0,0.3); padding: 2px 4px; border-radius: 2px;">${data.query_string}</code><br>` : ''}
        ${maliciousCount > 0 ? `<strong style="color: #e74c3c;">🚨 Malicious Reports:</strong> ${maliciousCount}<br>` : ''}
        ${suspiciousCount > 0 ? `<strong style="color: #f39c12;">⚠️ Suspicious Reports:</strong> ${suspiciousCount}<br>` : ''}
        ${relatedDomains.size > 0 ? `<strong style="color: #3498db;">🔀 Redirects Found:</strong> ${Array.from(relatedDomains).map(d => `<code style="background: rgba(52,152,219,0.3); padding: 2px 5px; border-radius: 3px; margin: 2px; display: inline-block; color: #fff; border: 1px solid rgba(52,152,219,0.5);">${d}</code>`).join(' ')}<br>` : ''}
        ${reports.length > 0 ? `<strong style="color: #999; font-size: 11px;">📊 Analyzed ${reports.length} most recent reports (showing first 5)</strong><br>` : ''}
        ${reports.length > 0 ? `
          <div style="margin-top: 8px; padding: 8px; background: rgba(0,0,0,0.2); border-radius: 4px;">
            <strong>Recent Analysis Reports (showing ${Math.min(5, reports.length)} of ${reports.length} analyzed):</strong>
            ${reports.slice(0, 5).map((r, idx) => {
              const alertCount = r.stats?.alert_count?.analyzer || 0;
              const detection = r.detection?.analyzer?.[0];
              const hasAlert = alertCount > 0;
              const tags = r.tags && r.tags.length > 0 ? r.tags : null;
              
              // Check tags for malware indicators
              const hasMalwareTags = tags && tags.some(tag => 
                tag.toLowerCase().includes('malware') || 
                tag.toLowerCase().includes('phishing') ||
                tag.toLowerCase().includes('botnet') ||
                tag.toLowerCase().includes('ransomware') ||
                tag.toLowerCase().includes('trojan') ||
                tag.toLowerCase().includes('backdoor')
              );
              
              // Override verdict if malware tags present
              let verdict = detection?.verdict || 'clean';
              if (hasMalwareTags && verdict === 'clean') {
                verdict = 'malicious';
              }
              
              const verdictColor = verdict === 'malicious' ? '#e74c3c' : verdict === 'suspicious' ? '#f39c12' : '#95a5a6';
              const analyzedUrl = r.url?.addr || 'N/A';
              
              return `
              <div style="margin-top: 6px; padding: 6px; background: rgba(0,0,0,0.3); border-radius: 3px; border-left: 3px solid ${verdictColor};">
                <div style="font-size: 11px;">
                  <strong>🌐 URL:</strong> ${analyzedUrl}<br>
                  <strong>📅 Date:</strong> ${r.date ? new Date(r.date).toLocaleDateString() : 'N/A'}<br>
                  ${(hasAlert || hasMalwareTags) ? `<strong style="color: ${verdictColor};">🔍 Verdict:</strong> ${verdict.toUpperCase()}<br>` : ''}
                  ${tags ? `<strong style="color: #e74c3c;">🏷️ Tags:</strong> ${tags.map(t => `<span style="background: rgba(231,76,60,0.3); padding: 2px 6px; border-radius: 2px; border: 1px solid rgba(231,76,60,0.5); margin: 0 2px; display: inline-block;">${t}</span>`).join('')}<br>` : ''}
                  ${detection?.sensor_name ? `<strong>🛡️ Sensor:</strong> ${detection.sensor_name} (${detection.alert})<br>` : ''}
                  <strong>🆔 Report:</strong> ${r.report_id || 'N/A'}
                </div>
              </div>
              `;
            }).join('')}
          </div>
        ` : ''}
        <div style="margin-top: 6px;">
          <a href="${data?.url || 'https://urlquery.net'}" target="_blank" style="background: #9b59b6; color: white; padding: 4px 12px; border-radius: 4px; text-decoration: none; display: inline-block;">🔎 View All ${data?.total_hits || 0} Reports</a>
        </div>
      `;
      break;
      
    case 'hybridanalysis':
      const haFound = data.found && data.found !== 'No';
      html = `
        <div style="background: ${haFound ? 'rgba(231, 76, 60, 0.1)' : 'rgba(149, 165, 166, 0.1)'}; padding: 8px; border-radius: 4px; margin-bottom: 6px; border-left: 3px solid ${haFound ? '#e74c3c' : '#95a5a6'};">
          <strong style="font-size: 14px; color: ${haFound ? '#e74c3c' : '#95a5a6'};">🔬 Hybrid Analysis</strong>
        </div>
        <strong>🔍 Found:</strong> ${data.found || 'No'}<br>
        ${data.verdict ? `<strong>⚖️ Verdict:</strong> ${data.verdict}<br>` : ''}
        ${data.threatScore !== undefined && data.threatScore !== 'undefined' ? `<strong>⚠️ Threat Score:</strong> ${data.threatScore}<br>` : ''}
        ${data.message ? `<strong>ℹ️ Status:</strong> ${data.message}<br>` : ''}
        <div style="margin-top: 6px;">
          <a href="${data.url}" target="_blank" style="background: #8e44ad; color: white; padding: 4px 12px; border-radius: 4px; text-decoration: none; display: inline-block;">🔬 View on Hybrid Analysis</a>
        </div>
      `;
      break;
      
    case 'urlhaus':
      html = `
        <div style="background: ${data.found ? 'rgba(231, 76, 60, 0.1)' : 'rgba(46, 204, 113, 0.1)'}; padding: 8px; border-radius: 4px; margin-bottom: 6px; border-left: 3px solid ${data.found ? '#e74c3c' : '#2ecc71'};">
          <strong style="font-size: 14px; color: ${data.found ? '#e74c3c' : '#2ecc71'};">🏠 URLhaus Database</strong>
        </div>
        <strong>🔍 Found in Database:</strong> ${data.found ? 'YES ⚠️' : 'NO ✓'}<br>
        ${data.found ? `${data.searchType === 'domain' || data.searchType === 'ip' ? `<strong>🔎 Search Type:</strong> ${data.searchType === 'ip' ? 'IP' : 'Domain'} Match (${data.urlCount} URLs found)<br>` : ''}
        <strong>⚠️ Threat Type:</strong> ${data.threat}<br>
        <strong>📅 Date Added:</strong> ${data.dateAdded}<br>
        <strong>👤 Reporter:</strong> ${data.reporter}<br>` : ''}
        <strong>ℹ️ Status:</strong> ${data.found ? (data.searchType === 'domain' || data.searchType === 'ip' ? `${data.searchType === 'ip' ? 'IP' : 'Domain'} has malicious URLs` : 'Listed as malware distribution URL') : 'Not in URLhaus database'}<br>
        <div style="margin-top: 6px;">
          <a href="${data.url}" target="_blank" style="background: #e67e22; color: white; padding: 4px 12px; border-radius: 4px; text-decoration: none; display: inline-block;">🏠 URLhaus Report</a>
        </div>
      `;
      break;
      
    case 'openphish':
      const isFoundInFeed = data.found;
      html = `
        <div style="background: ${isFoundInFeed ? 'rgba(231, 76, 60, 0.1)' : 'rgba(46, 204, 113, 0.1)'}; padding: 8px; border-radius: 4px; margin-bottom: 6px; border-left: 3px solid ${isFoundInFeed ? '#e74c3c' : '#2ecc71'};">
          <strong style="font-size: 14px; color: ${isFoundInFeed ? '#e74c3c' : '#2ecc71'};">🎣 OpenPhish</strong>
        </div>
        <strong>📊 Status:</strong> ${data.message}<br>
        <div style="margin-top: 6px;">
          <a href="${data.url}" target="_blank" style="background: #16a085; color: white; padding: 4px 12px; border-radius: 4px; text-decoration: none; display: inline-block;">🔍 View on OpenPhish</a>
        </div>
      `;
      break;
      
    case 'sansisc':
      const hasAttacks = data.attacks > 0;
      const hasUsefulComment = data.comment && data.comment !== 'N/A' && data.comment !== 'None';
      
      if (hasAttacks || hasUsefulComment) {
        // Show full details when there are attacks or useful comments
        html = `
          <div style="background: ${hasAttacks ? 'rgba(231, 76, 60, 0.1)' : 'rgba(46, 204, 113, 0.1)'}; padding: 8px; border-radius: 4px; margin-bottom: 6px; border-left: 3px solid ${hasAttacks ? '#e74c3c' : '#2ecc71'};">
            <strong style="font-size: 14px; color: ${hasAttacks ? '#e74c3c' : '#2ecc71'};">🛡️ SANS ISC</strong>
          </div>
          ${hasUsefulComment ? `<div style="background: rgba(52, 152, 219, 0.1); padding: 6px 8px; border-radius: 4px; margin-bottom: 8px; border-left: 2px solid #3498db;">
            <strong style="color: #3498db;">💬 Comment:</strong> ${data.comment}
          </div>` : ''}
          <strong>📊 Report Count:</strong> ${data.count}<br>
          <strong>⚔️ Attack Count:</strong> ${data.attacks} ${hasAttacks ? '⚠️' : '✓'}<br>
          ${data.mindate !== 'N/A' ? `<strong>📅 First Seen:</strong> ${data.mindate}<br>` : ''}
          ${data.maxdate !== 'N/A' ? `<strong>📅 Last Seen:</strong> ${data.maxdate}<br>` : ''}
          <strong>ℹ️ Status:</strong> ${hasAttacks ? 'Reported attack source' : 'No attack reports'}<br>
          <div style="margin-top: 6px;">
            <a href="${data.url}" target="_blank" style="background: #2980b9; color: white; padding: 4px 12px; border-radius: 4px; text-decoration: none; display: inline-block;">🛡️ SANS Details</a>
          </div>
        `;
      } else {
        // Compact view when no attacks and no useful info
        html = `
          <strong>🛡️ SANS ISC:</strong> No attack reports<br>
          <a href="${data.url}" target="_blank" style="color: #3498db; text-decoration: none;">View details →</a>
        `;
      }
      break;
      
    case 'whois':
      if (data.type === 'ip') {
        // IP Network information
        html = `
          <div style="background: rgba(52, 152, 219, 0.1); padding: 8px; border-radius: 4px; margin-bottom: 6px; border-left: 3px solid #3498db;">
            <strong style="font-size: 14px; color: #3498db;">🌐 WHOIS (IP)</strong>
          </div>
          <strong>🏢 Organization:</strong> ${data.organization}<br>
          <strong>🔢 ASN:</strong> ${data.asn}<br>
          <strong>🌍 Country:</strong> ${data.country}<br>
          <strong>📍 Region:</strong> ${data.region}<br>
          <strong>🏙️ City:</strong> ${data.city}<br>
          <strong>🔗 Network:</strong> ${data.network}<br>
          <div style="margin-top: 6px;">
            <a href="${data.url}" target="_blank" style="background: #3498db; color: white; padding: 4px 12px; border-radius: 4px; text-decoration: none; display: inline-block;">🔍 Full WHOIS</a>
          </div>
        `;
      } else if (data.type === 'domain') {
        // Domain WHOIS - check if we have RDAP data
        if (data.registrar && data.registrar !== 'N/A') {
          // We have RDAP data
          html = `
            <div style="background: rgba(52, 152, 219, 0.1); padding: 8px; border-radius: 4px; margin-bottom: 6px; border-left: 3px solid #3498db;">
              <strong style="font-size: 14px; color: #3498db;">📜 WHOIS (Domain)</strong>
            </div>
            <strong>🌐 Domain:</strong> ${data.domain}<br>
            <strong>🏢 Registrar:</strong> ${data.registrar}<br>
            ${data.registrarEmail && data.registrarEmail !== 'N/A' ? `<strong style="color: #3498db;">📧 Registrar Email:</strong> <a href="mailto:${data.registrarEmail}" style="color: #3498db; text-decoration: underline;">${data.registrarEmail}</a><br>` : ''}
            ${data.abuseEmail && data.abuseEmail !== 'N/A' ? `<strong style="color: #e74c3c;">🚨 Abuse Email:</strong> <a href="mailto:${data.abuseEmail}" style="color: #e74c3c; text-decoration: underline;">${data.abuseEmail}</a><br>` : ''}
            <strong>📅 Created:</strong> ${data.created.split('T')[0] || data.created}<br>
            <strong>🔄 Updated:</strong> ${data.updated.split('T')[0] || data.updated}<br>
            <strong>⏰ Expires:</strong> ${data.expires.split('T')[0] || data.expires}<br>
            <strong>🌐 Nameservers:</strong> ${data.nameservers}<br>
            <strong>📊 Status:</strong> ${data.status}<br>
            ${data.emails && data.emails !== 'N/A' && data.emails !== data.registrarEmail && data.emails !== data.abuseEmail ? `<strong>📧 Other Contact Emails:</strong> ${data.emails}<br>` : ''}
            <div style="margin-top: 6px;">
              <a href="${data.url}" target="_blank" style="background: linear-gradient(135deg, #667eea, #764ba2); color: white; padding: 6px 16px; border-radius: 4px; text-decoration: none; display: inline-block; font-weight: 600;">🔍 Full WHOIS Details</a>
            </div>
          `;
        } else {
          // No RDAP data, external link only
          html = `
            <div style="background: rgba(52, 152, 219, 0.1); padding: 8px; border-radius: 4px; margin-bottom: 6px; border-left: 3px solid #3498db;">
              <strong style="font-size: 14px; color: #3498db;">📜 WHOIS</strong>
            </div>
            <strong>🌐 Domain:</strong> ${data.domain}<br>
            ${data.message ? `<strong>ℹ️ Info:</strong> ${data.message}<br>` : ''}
            ${data.note ? `<strong>📝 Note:</strong> <span style="color: #95a5a6; font-size: 10px;">${data.note}</span><br>` : ''}
            <div style="margin-top: 8px;">
              <a href="${data.url}" target="_blank" style="background: linear-gradient(135deg, #667eea, #764ba2); color: white; padding: 6px 16px; border-radius: 4px; text-decoration: none; display: inline-block; font-weight: 600;">🔍 View WHOIS Registration Data</a>
            </div>
          `;
        }
      } else {
        // Error or fallback
        html = `
          <strong>⚠️ ${data.message || 'Unable to fetch WHOIS data'}</strong><br>
          <a href="${data.url}" target="_blank" style="background: #3498db; color: white; padding: 4px 12px; border-radius: 4px; text-decoration: none; display: inline-block; margin-top: 6px;">🔍 View WHOIS Online</a>
        `;
      }
      break;
      
    case 'dnsrecords':
      const hasRecords = data.hasRecords;
      let dnsHtml = '';
      
      if (data.A && data.A.length > 0) {
        dnsHtml += `<strong>🔹 A Records:</strong><br><div style="background: #1a2333; padding: 6px; border-radius: 3px; margin: 4px 0 8px 0; font-family: monospace; font-size: 11px;">${data.A.join('<br>')}</div>`;
      }
      if (data.AAAA && data.AAAA.length > 0) {
        dnsHtml += `<strong>🔹 AAAA Records (IPv6):</strong><br><div style="background: #1a2333; padding: 6px; border-radius: 3px; margin: 4px 0 8px 0; font-family: monospace; font-size: 11px;">${data.AAAA.join('<br>')}</div>`;
      }
      if (data.MX && data.MX.length > 0) {
        dnsHtml += `<strong>📧 MX Records:</strong><br><div style="background: #1a2333; padding: 6px; border-radius: 3px; margin: 4px 0 8px 0; font-family: monospace; font-size: 11px;">${data.MX.join('<br>')}</div>`;
      }
      if (data.NS && data.NS.length > 0) {
        dnsHtml += `<strong>🌐 NS Records:</strong><br><div style="background: #1a2333; padding: 6px; border-radius: 3px; margin: 4px 0 8px 0; font-family: monospace; font-size: 11px;">${data.NS.map(ns => ns.replace(/\.$/, '')).join('<br>')}</div>`;
      }
      if (data.CNAME && data.CNAME.length > 0) {
        dnsHtml += `<strong>🔗 CNAME Records:</strong><br><div style="background: #1a2333; padding: 6px; border-radius: 3px; margin: 4px 0 8px 0; font-family: monospace; font-size: 11px;">${data.CNAME.map(c => c.replace(/\.$/, '')).join('<br>')}</div>`;
      }
      if (data.TXT && data.TXT.length > 0) {
        dnsHtml += `<strong>📝 TXT Records:</strong><br><div style="background: #1a2333; padding: 6px; border-radius: 3px; margin: 4px 0 8px 0; font-family: monospace; font-size: 10px; word-break: break-all;">${data.TXT.join('<br><br>')}</div>`;
      }
      
      html = `
        <div style="background: ${hasRecords ? 'rgba(46, 204, 113, 0.1)' : 'rgba(149, 165, 166, 0.1)'}; padding: 8px; border-radius: 4px; margin-bottom: 6px; border-left: 3px solid ${hasRecords ? '#2ecc71' : '#95a5a6'};">
          <strong style="font-size: 14px; color: ${hasRecords ? '#2ecc71' : '#95a5a6'};">🌐 DNS Records</strong>
        </div>
        ${dnsHtml || '<strong>⚠️ No DNS records found</strong><br>'}
        <div style="margin-top: 6px;">
          <a href="${data.url}" target="_blank" style="background: #34495e; color: white; padding: 4px 12px; border-radius: 4px; text-decoration: none; display: inline-block;">🌐 Full DNS Query</a>
        </div>
      `;
      break;
      
    case 'crtsh':
      html = `
        <div style="background: rgba(52, 152, 219, 0.1); padding: 8px; border-radius: 4px; margin-bottom: 6px; border-left: 3px solid #3498db;">
          <strong style="font-size: 14px; color: #3498db;">🔐 Certificate Transparency (crt.sh)</strong>
        </div>
        <strong>📜 Total Certificates:</strong> ${data.certificates}<br>
        <strong>🏢 Certificate Issuers:</strong><br>
        <div style="background: #1a2333; padding: 6px; border-radius: 3px; margin: 4px 0; font-size: 11px;">${data.issuers || 'None'}</div>
        <strong>ℹ️ Status:</strong> ${data.certificates > 0 ? `Found ${data.certificates} SSL/TLS certificates` : 'No certificates found'}<br>
        <div style="margin-top: 6px;">
          <a href="${data.url}" target="_blank" style="background: #3498db; color: white; padding: 4px 12px; border-radius: 4px; text-decoration: none; display: inline-block;">🔐 View Certificates</a>
        </div>
      `;
      break;
      
    case 'wayback':
      html = `
        <strong>Archived:</strong> ${data.archived}<br>
        <strong>Snapshots:</strong> ${data.snapshots}<br>
        <a href="${data.url}" target="_blank">View archive →</a>
      `;
      break;
      
    case 'ipblocklists':
      const ipIsListed = data.found > 0;
      const ipEntityType = (data.entityType || 'IP').toUpperCase();
      html = `
        <div style="background: ${ipIsListed ? 'rgba(231, 76, 60, 0.1)' : 'rgba(46, 204, 113, 0.1)'}; padding: 8px; border-radius: 4px; margin-bottom: 6px; border-left: 3px solid ${ipIsListed ? '#e74c3c' : '#2ecc71'};">
          <strong style="font-size: 14px; color: ${ipIsListed ? '#e74c3c' : '#2ecc71'};">🛡️ IP Blocklists</strong>
        </div>
        <strong>📊 Lists Checked:</strong> ${data.checked}<br>
        <strong>${ipIsListed ? '🚨' : '✓'} Found In:</strong> ${data.found} ${data.found === 1 ? 'list' : 'lists'}<br>
        ${data.foundIn !== 'None' ? `<strong>📋 Sources:</strong> ${data.foundIn}<br>` : ''}
        <strong>ℹ️ Status:</strong> ${data.message}<br>
        <a href="${data.url}" target="_blank" style="background: ${ipIsListed ? '#e74c3c' : '#2ecc71'}; color: white; padding: 4px 12px; border-radius: 4px; text-decoration: none; display: inline-block; margin-top: 6px;">📋 More Info</a>
      `;
      break;
      
    case 'domainblocklists':
      const isListed = data.found > 0;
      const categories = data.categories || {};
      const hasMalware = categories.malware && categories.malware.length > 0;
      const hasPhishing = categories.phishing && categories.phishing.length > 0;
      const hasFraud = categories.fraud && categories.fraud.length > 0;
      const hasThreat = categories.threat && categories.threat.length > 0;
      
      html = `
        <div style="background: ${isListed ? 'rgba(231, 76, 60, 0.1)' : 'rgba(46, 204, 113, 0.1)'}; padding: 8px; border-radius: 4px; margin-bottom: 6px; border-left: 3px solid ${isListed ? '#e74c3c' : '#2ecc71'};">
          <strong style="font-size: 14px; color: ${isListed ? '#e74c3c' : '#2ecc71'};">🛡️ Domain Blocklists</strong>
        </div>
        ${data.domain ? `<strong>🌐 Checked Domain:</strong> ${data.domain}<br>` : ''}
        <strong>📊 Lists Checked:</strong> ${data.checked}${data.failed > 0 ? ` <span style="color: #95a5a6;">(${data.failed} unavailable)</span>` : ''}<br>
        <strong>${isListed ? '🚨' : '✓'} Found In:</strong> ${data.found} ${data.found === 1 ? 'list' : 'lists'}<br>
        ${hasMalware ? `<strong style="color: #e74c3c;">🦠 Malware Lists:</strong> ${categories.malware.length}<br><div style="background: rgba(231,76,60,0.1); padding: 4px 8px; border-radius: 3px; margin: 4px 0; font-size: 11px;">${categories.malware.join(', ')}</div>` : ''}
        ${hasPhishing ? `<strong style="color: #f39c12;">🎣 Phishing Lists:</strong> ${categories.phishing.length}<br><div style="background: rgba(243,156,18,0.1); padding: 4px 8px; border-radius: 3px; margin: 4px 0; font-size: 11px;">${categories.phishing.join(', ')}</div>` : ''}
        ${hasFraud ? `<strong style="color: #e67e22;">💳 Fraud Lists:</strong> ${categories.fraud.length}<br><div style="background: rgba(230,126,34,0.1); padding: 4px 8px; border-radius: 3px; margin: 4px 0; font-size: 11px;">${categories.fraud.join(', ')}</div>` : ''}
        ${hasThreat ? `<strong style="color: #9b59b6;">⚠️ Threat Lists:</strong> ${categories.threat.length}<br><div style="background: rgba(155,89,182,0.1); padding: 4px 8px; border-radius: 3px; margin: 4px 0; font-size: 11px;">${categories.threat.join(', ')}</div>` : ''}
        <strong>ℹ️ Status:</strong> ${data.message}<br>
        <a href="${data.url}" target="_blank" style="background: ${isListed ? '#e74c3c' : '#2ecc71'}; color: white; padding: 4px 12px; border-radius: 4px; text-decoration: none; display: inline-block; margin-top: 6px;">📋 Blocklist Info</a>
      `;
      break;
    
    case 'virustotal':
      const vtScore = data.total > 0 ? Math.round(((data.malicious + data.suspicious) / data.total) * 100) : 0;
      html = `
        <div style="background: rgba(231, 76, 60, ${vtScore/200}); padding: 8px; border-radius: 4px; margin-bottom: 6px;">
          <strong style="font-size: 16px; color: ${data.malicious > 0 ? '#e74c3c' : '#2ecc71'};">⚠️ ${data.malicious + data.suspicious}/${data.total} Detections (${vtScore}%)</strong>
        </div>
        <strong>🔴 Malicious:</strong> ${data.malicious} engines<br>
        <strong>🟡 Suspicious:</strong> ${data.suspicious} engines<br>
        <strong>🟢 Clean:</strong> ${data.clean} engines<br>
        <strong>📊 Total Scanned:</strong> ${data.total} engines<br>
        <div style="margin-top: 6px;">
          <a href="${data.url}" target="_blank" style="background: #667eea; color: white; padding: 4px 12px; border-radius: 4px; text-decoration: none; display: inline-block;">📄 Full Report</a>
        </div>
      `;
      break;
      
    case 'abuseipdb':
      const abuseColor = data.abuseScore > 75 ? '#e74c3c' : data.abuseScore > 25 ? '#f39c12' : '#2ecc71';
      html = `
        <div style="background: rgba(231, 76, 60, ${data.abuseScore/200}); padding: 8px; border-radius: 4px; margin-bottom: 6px;">
          <strong style="font-size: 16px; color: ${abuseColor};">🚨 Abuse Score: ${data.abuseScore}%</strong>
        </div>
        <strong>📊 Total Reports:</strong> ${data.totalReports}<br>
        <strong>🌍 Country:</strong> ${data.country}<br>
        <strong>🏢 ISP:</strong> ${data.isp}<br>
        <strong>🎯 Usage Type:</strong> ${data.usage}<br>
        <div style="margin-top: 6px;">
          <a href="${data.url}" target="_blank" style="background: #667eea; color: white; padding: 4px 12px; border-radius: 4px; text-decoration: none; display: inline-block;">📄 View Details</a>
        </div>
      `;
      break;
      
    case 'alienvault':
      const hasPulses = data.pulseCount > 0;
      html = `
        <div style="background: ${hasPulses ? 'rgba(243, 156, 18, 0.1)' : 'rgba(46, 204, 113, 0.1)'}; padding: 8px; border-radius: 4px; margin-bottom: 6px; border-left: 3px solid ${hasPulses ? '#f39c12' : '#2ecc71'};">
          <strong style="font-size: 14px; color: ${hasPulses ? '#f39c12' : '#2ecc71'};">🔔 AlienVault OTX</strong>
        </div>
        <strong>📡 Active Pulses:</strong> ${data.pulseCount} ${hasPulses ? '⚠️' : '✓'}<br>
        <strong>⭐ Reputation Score:</strong> ${data.reputation}<br>
        <strong>📊 Status:</strong> ${hasPulses ? 'Found in threat feeds' : 'Not found in feeds'}<br>
        <div style="margin-top: 6px;">
          <a href="${data.url}" target="_blank" style="background: #9b59b6; color: white; padding: 4px 12px; border-radius: 4px; text-decoration: none; display: inline-block;">🔔 View on OTX</a>
        </div>
      `;
      break;
      
    case 'urlscan':
      if (data.found) {
        // Has scan results
        const isMalicious = data.verdict === 'malicious';
        const isSuspicious = data.verdict === 'suspicious';
        
        // Create links to individual scans
        let scanLinks = '';
        if (data.scans && data.scans.length > 0) {
          scanLinks = '<div style="margin-top: 8px; padding: 8px; background: rgba(26, 35, 51, 0.5); border-radius: 4px;">';
          scanLinks += `<strong>📋 Recent Scans (${data.scans.length} of ${data.totalScans}):</strong><br>`;
          data.scans.forEach((scan, index) => {
            const scanDate = new Date(scan.scanTime).toLocaleString();
            const verdictIcon = scan.verdict === 'malicious' ? '🚨' : scan.verdict === 'suspicious' ? '⚡' : '✓';
            scanLinks += `<div style="margin: 4px 0; padding: 4px; background: rgba(255,255,255,0.05); border-radius: 3px;">
              ${verdictIcon} <strong>Scan ${index + 1}:</strong> ${scan.verdict.toUpperCase()} (Score: ${scan.score}) - ${scanDate}<br>
              <a href="${scan.url}" target="_blank" style="color: #3498db; font-size: 11px; margin-left: 20px;">🔗 View Report</a>
            </div>`;
          });
          scanLinks += `<div style="margin-top: 6px;">
            <a href="${data.searchUrl}" target="_blank" style="background: #34495e; color: white; padding: 4px 12px; border-radius: 4px; text-decoration: none; display: inline-block; font-size: 11px;">🔍 View All Scans</a>
          </div>`;
          scanLinks += '</div>';
        }
        
        html = `
          <div style="background: ${isMalicious ? 'rgba(231, 76, 60, 0.1)' : isSuspicious ? 'rgba(243, 156, 18, 0.1)' : 'rgba(46, 204, 113, 0.1)'}; padding: 8px; border-radius: 4px; margin-bottom: 6px; border-left: 3px solid ${isMalicious ? '#e74c3c' : isSuspicious ? '#f39c12' : '#2ecc71'};">
            <strong style="font-size: 14px; color: ${isMalicious ? '#e74c3c' : isSuspicious ? '#f39c12' : '#2ecc71'};">🔍 URLScan.io</strong>
          </div>
          <strong>⚖️ Latest Verdict:</strong> ${data.verdict.toUpperCase()} ${isMalicious ? '⚠️' : isSuspicious ? '⚡' : '✓'}<br>
          <strong>📊 Score:</strong> ${data.score}<br>
          <strong>🏷️ Brands:</strong> ${data.brands}<br>
          <strong>📁 Categories:</strong> ${data.categories}<br>
          <strong>🌍 Country:</strong> ${data.country}<br>
          <strong>🖥️ Server:</strong> ${data.server}<br>
          <strong>📅 Last Scanned:</strong> ${data.lastScanned}<br>
          ${scanLinks}
        `;
      } else {
        // No scan results or new scan
        html = `
          <strong>📊 Status:</strong> ${data.message}<br>
          <div style="margin-top: 6px;">
            <a href="${data.url}" target="_blank" style="background: #1abc9c; color: white; padding: 4px 12px; border-radius: 4px; text-decoration: none; display: inline-block;">🔍 Search on URLScan.io</a>
          </div>
        `;
      }
      break;
      
    case 'shodan':
      const hasVulns = data.vulns !== 'None' && data.vulns !== '';
      html = `
        <div style="background: ${hasVulns ? 'rgba(231, 76, 60, 0.1)' : 'rgba(46, 204, 113, 0.1)'}; padding: 8px; border-radius: 4px; margin-bottom: 6px; border-left: 3px solid ${hasVulns ? '#e74c3c' : '#2ecc71'};">
          <strong style="font-size: 14px; color: ${hasVulns ? '#e74c3c' : '#2ecc71'};">🔍 Shodan InternetDB</strong>
        </div>
        <strong>🔓 Open Ports:</strong> ${data.ports}<br>
        <strong>⚠️ Vulnerabilities:</strong> ${data.vulns}<br>
        <strong>🏷️ Tags:</strong> ${data.tags}<br>
        <strong>📦 CPE Count:</strong> ${data.cpes}<br>
        <div style="margin-top: 6px;">
          <a href="${data.url}" target="_blank" style="background: #c0392b; color: white; padding: 4px 12px; border-radius: 4px; text-decoration: none; display: inline-block;">🔍 View on Shodan</a>
        </div>
      `;
      break;
      
    case 'phishtank':
      if (data.message) {
        // API unavailable - show search link
        html = `
          <div style="background: rgba(149, 165, 166, 0.1); padding: 8px; border-radius: 4px; margin-bottom: 6px; border-left: 3px solid #95a5a6;">
            <strong style="font-size: 14px; color: #95a5a6;">🎣 PhishTank</strong>
          </div>
          <strong>ℹ️ Status:</strong> ${data.message}<br>
          <strong>📝 Note:</strong> <span style="color: #95a5a6; font-size: 11px;">API temporarily unavailable - use manual search</span><br>
          <div style="margin-top: 6px;">
            <a href="${data.url}" target="_blank" style="background: #16a085; color: white; padding: 4px 12px; border-radius: 4px; text-decoration: none; display: inline-block;">🔍 Search on PhishTank</a>
          </div>
        `;
      } else {
        // API worked - show results
        html = `
          <div style="background: ${data.isPhishing ? 'rgba(231, 76, 60, 0.1)' : 'rgba(46, 204, 113, 0.1)'}; padding: 8px; border-radius: 4px; margin-bottom: 6px; border-left: 3px solid ${data.isPhishing ? '#e74c3c' : '#2ecc71'};">
            <strong style="font-size: 14px; color: ${data.isPhishing ? '#e74c3c' : '#2ecc71'};">🎣 PhishTank</strong>
          </div>
          <strong>🔍 In Database:</strong> ${data.inDatabase ? 'YES' : 'NO'}<br>
          <strong>✓ Verified Phishing:</strong> ${data.isPhishing ? 'YES ⚠️ CONFIRMED' : 'NO ✓'}<br>
          <strong>ℹ️ Status:</strong> ${data.isPhishing ? 'Verified phishing site - AVOID!' : data.inDatabase ? 'In database but not verified as phishing' : 'Not reported as phishing'}<br>
          <div style="margin-top: 6px;">
            <a href="${data.url}" target="_blank" style="background: #16a085; color: white; padding: 4px 12px; border-radius: 4px; text-decoration: none; display: inline-block;">🎣 PhishTank Report</a>
          </div>
        `;
      }
      break;
      
    case 'threatfox':
      html = `
        <div style="background: ${data.found ? 'rgba(231, 76, 60, 0.1)' : 'rgba(46, 204, 113, 0.1)'}; padding: 8px; border-radius: 4px; margin-bottom: 6px; border-left: 3px solid ${data.found ? '#e74c3c' : '#2ecc71'};">
          <strong style="font-size: 14px; color: ${data.found ? '#e74c3c' : '#2ecc71'};">🦊 ThreatFox</strong>
        </div>
        <strong>🔍 Found in Database:</strong> ${data.found ? 'YES ⚠️' : 'NO ✓'}<br>
        ${data.found ? `<strong>📊 IOC Count:</strong> ${data.count}<br>
        <strong>🦠 Malware Family:</strong> ${data.malware}<br>
        <strong>📈 Confidence Level:</strong> ${data.confidence}<br>` : ''}
        <strong>ℹ️ Status:</strong> ${data.found ? 'Listed as threat indicator' : 'Not found in threat database'}<br>
        <div style="margin-top: 6px;">
          <a href="${data.url}" target="_blank" style="background: #e67e22; color: white; padding: 4px 12px; border-radius: 4px; text-decoration: none; display: inline-block;">🦊 View on ThreatFox</a>
        </div>
      `;
      break;
      
    case 'malwarebazaar':
      html = `
        <div style="background: ${data.found ? 'rgba(231, 76, 60, 0.1)' : 'rgba(46, 204, 113, 0.1)'}; padding: 8px; border-radius: 4px; margin-bottom: 6px; border-left: 3px solid ${data.found ? '#e74c3c' : '#2ecc71'};">
          <strong style="font-size: 14px; color: ${data.found ? '#e74c3c' : '#2ecc71'};">🏪 MalwareBazaar</strong>
        </div>
        <strong>🔍 Found in Database:</strong> ${data.found ? 'YES ⚠️' : 'NO ✓'}<br>
        ${data.found ? `<strong>🦠 Signature:</strong> ${data.signature}<br>
        <strong>📄 File Type:</strong> ${data.fileType}<br>
        <strong>📦 File Size:</strong> ${data.fileSize}<br>` : ''}
        <strong>ℹ️ Status:</strong> ${data.found ? 'Known malware sample' : 'Not in malware database'}<br>
        <div style="margin-top: 6px;">
          <a href="${data.url}" target="_blank" style="background: #c0392b; color: white; padding: 4px 12px; border-radius: 4px; text-decoration: none; display: inline-block;">🏪 Bazaar Details</a>
        </div>
      `;
      break;
      
    default:
      html = '<em>No data available</em>';
  }
  
  return html;
}

// Reorganize results to show findings first, empty results compactly at bottom
function reorganizeResults(card) {
  const resultsContainer = card.querySelector('.tool-results');
  const allResults = Array.from(resultsContainer.querySelectorAll('.tool-result'));
  
  const findings = allResults.filter(r => !r.classList.contains('empty-result'));
  const emptyResults = allResults.filter(r => r.classList.contains('empty-result'));
  
  // Clear container
  resultsContainer.innerHTML = '';
  
  // Add findings first
  findings.forEach(result => resultsContainer.appendChild(result));
  
  // Add compact summary of empty results if any
  if (emptyResults.length > 0) {
    const compactDiv = document.createElement('div');
    compactDiv.className = 'compact-results';
    compactDiv.style.cssText = 'margin-top: 12px; padding: 8px 12px; background: rgba(46, 204, 113, 0.05); border: 1px solid rgba(46, 204, 113, 0.2); border-radius: 6px;';
    
    const toolNames = emptyResults.map(r => {
      const nameEl = r.querySelector('.tool-name');
      return nameEl ? nameEl.textContent.split('\n')[0].trim() : '';
    }).filter(n => n);
    
    const headerDiv = document.createElement('div');
    headerDiv.style.cssText = 'display: flex; align-items: center; gap: 8px; margin-bottom: 4px;';
    headerDiv.innerHTML = `
      <strong style="color: #2ecc71; font-size: 12px;">✓ CLEAN (${emptyResults.length})</strong>
      <button class="toggle-empty-btn" style="background: none; border: 1px solid rgba(46, 204, 113, 0.3); color: #2ecc71; padding: 2px 8px; border-radius: 3px; font-size: 10px; cursor: pointer;">Toggle</button>
    `;
    
    const toolNamesDiv = document.createElement('div');
    toolNamesDiv.style.cssText = 'font-size: 11px; color: #95a5a6;';
    toolNamesDiv.textContent = toolNames.join(' • ');
    
    const hiddenSection = document.createElement('div');
    hiddenSection.className = 'empty-details';
    hiddenSection.style.cssText = 'margin-top: 8px; display: none;';
    
    // Add full results to the hidden section
    emptyResults.forEach(result => {
      // Make it more compact
      result.style.cssText = 'margin-bottom: 6px; padding: 6px; background: rgba(26, 35, 51, 0.3); border-radius: 4px; font-size: 11px;';
      hiddenSection.appendChild(result);
    });
    
    // Add toggle functionality
    const toggleBtn = headerDiv.querySelector('.toggle-empty-btn');
    toggleBtn.addEventListener('click', () => {
      if (hiddenSection.style.display === 'none') {
        hiddenSection.style.display = 'block';
        toggleBtn.textContent = 'Hide';
      } else {
        hiddenSection.style.display = 'none';
        toggleBtn.textContent = 'Toggle';
      }
    });
    
    compactDiv.appendChild(headerDiv);
    compactDiv.appendChild(toolNamesDiv);
    compactDiv.appendChild(hiddenSection);
    
    resultsContainer.appendChild(compactDiv);
  }
}

// Update risk badge based on results
function updateRiskBadge(card, observable) {
  const badge = card.querySelector('.risk-badge');
  const results = card.querySelectorAll('.tool-result');
  
  let riskScore = 0;
  let criticalFindings = 0;
  let totalChecks = 0;
  
  results.forEach(result => {
    const toolData = result.querySelector('.tool-data');
    if (!toolData) return;
    
    const html = toolData.innerHTML.toLowerCase();
    const text = toolData.textContent.toLowerCase();
    
    // Critical threat indicators
    if (text.includes('abuse score: 100%') || text.includes('abuse score: 99%')) {
      riskScore += 50;
      criticalFindings++;
    } else if (text.match(/abuse score: ([789]\d|100)%/)) {
      // AbuseIPDB score 70-100%
      riskScore += 30;
      criticalFindings++;
    } else if (text.match(/abuse score: ([56]\d)%/)) {
      // AbuseIPDB score 50-69%
      riskScore += 15;
    } else if (text.match(/abuse score: ([234]\d)%/)) {
      // AbuseIPDB score 20-49%
      riskScore += 8;
    }
    
    // VirusTotal detections
    const vtMatch = text.match(/(\d+)\/\d+ detections/);
    if (vtMatch) {
      const detections = parseInt(vtMatch[1]);
      if (detections > 10) {
        riskScore += 40;
        criticalFindings++;
      } else if (detections > 5) {
        riskScore += 20;
      } else if (detections > 0) {
        riskScore += 10;
      }
    }
    
    // Blocklist findings
    if (text.includes('listed') && !text.includes('not found')) {
      const foundMatch = text.match(/found in: (\d+)/i);
      if (foundMatch) {
        const found = parseInt(foundMatch[1]);
        if (found > 0) {
          riskScore += found * 8;
          criticalFindings++;
        }
      } else if (html.includes('listed') && html.includes('e74c3c')) {
        // Red colored "LISTED" indicator
        riskScore += 15;
        criticalFindings++;
      }
    }
    
    // Other threat indicators
    // Skip generic malicious/suspicious checks for URLquery when redirects are found
    const isUrlqueryWithRedirects = text.includes('urlquery') && text.includes('🔀 redirects found:');
    
    if (!isUrlqueryWithRedirects && text.includes('malicious') && !text.includes('malicious: 0')) {
      riskScore += 15;
      criticalFindings++;
    }
    if (!isUrlqueryWithRedirects && text.includes('suspicious') && !text.includes('suspicious: 0')) {
      riskScore += 8;
    }
    if ((text.includes('verified phishing: yes') || text.includes('phishing: yes')) && 
        !text.includes('verified phishing: no')) {
      riskScore += 40;
      criticalFindings++;
    }
    if (text.includes('classification: malicious') || text.includes('classification: phishing')) {
      riskScore += 25;
      criticalFindings++;
    }
    if (text.includes('threat pulses') || text.includes('active pulses')) {
      const pulsesMatch = text.match(/active pulses: (\d+)/);
      if (pulsesMatch && parseInt(pulsesMatch[1]) > 0) {
        riskScore += 10;
      }
    }
    
    // URLquery malicious/phishing detection
    if (text.includes('urlquery')) {
      // Check if we have malicious reports line AND no redirects found
      // (If redirects are present, the malicious reports are about OTHER domains)
      const hasMaliciousReports = text.includes('🚨 malicious reports:');
      const hasRedirects = text.includes('🔀 redirects found:');
      
      if (hasMaliciousReports && !hasRedirects) {
        // Malicious reports without redirects = the searched domain itself is malicious
        const maliciousMatch = text.match(/malicious reports:\s*(\d+)/i);
        if (maliciousMatch) {
          const maliciousCount = parseInt(maliciousMatch[1]);
          if (maliciousCount > 0) {
            riskScore += 40;
            criticalFindings++;
          }
        }
      }
      
      // Don't check for "verdict: malicious" in text if redirects are present
      // because those verdicts are for the redirect domains, not the searched observable
      
      // Check for suspicious reports (only if no redirects)
      if (!hasRedirects) {
        const suspiciousMatch = text.match(/suspicious reports:\s*(\d+)/i);
        if (suspiciousMatch) {
          const suspiciousCount = parseInt(suspiciousMatch[1]);
          if (suspiciousCount > 0) {
            riskScore += 15;
          }
        }
      }
    }
    
    // Cloudflare IP detection - apply LOW RISK
    if (text.includes('cloudflare network') || text.includes('cloudflare ip check')) {
      if (text.includes('status: cloudflare network')) {
        // Cloudflare IP detected - this is informational, reduces overall risk
        riskScore = Math.max(0, riskScore - 5); // Slightly reduce risk score
        // Set flag for LOW RISK if no other threats
      }
    }
    
    totalChecks++;
  });
  
  // Check if Cloudflare IP was detected
  const cloudflareDetected = Array.from(results).some(result => {
    const text = result.textContent.toLowerCase();
    return text.includes('cloudflare network') && text.includes('status: cloudflare network');
  });
  
  // Determine risk level based on score and critical findings
  if (criticalFindings >= 2 || riskScore >= 50) {
    badge.className = 'risk-badge risk-high';
    badge.textContent = '🚨 MALICIOUS';
  } else if (criticalFindings >= 1 || riskScore >= 30) {
    badge.className = 'risk-badge risk-high';
    badge.textContent = '⚠️ HIGH RISK';
  } else if (riskScore >= 15) {
    badge.className = 'risk-badge risk-medium';
    badge.textContent = '⚡ SUSPICIOUS';
  } else if (cloudflareDetected && riskScore < 15) {
    // Cloudflare IP with low/no risk - mark as LOW RISK
    badge.className = 'risk-badge risk-medium';
    badge.textContent = '⚡ LOW RISK';
  } else if (riskScore >= 5) {
    badge.className = 'risk-badge risk-medium';
    badge.textContent = '⚡ LOW RISK';
  } else if (totalChecks > 0) {
    badge.className = 'risk-badge risk-low';
    badge.textContent = '✓ CLEAN';
  } else {
    badge.className = 'risk-badge risk-unknown';
    badge.textContent = '⏳ Analyzing...';
  }
}

// Check if IP is in CIDR ranges
function checkIPInRanges(ip, cidrRanges) {
  // Convert IP to integer
  const ipToInt = (ip) => {
    if (ip.includes(':')) return null; // Skip IPv6 for now (simple implementation)
    const parts = ip.split('.');
    if (parts.length !== 4) return null;
    return parts.reduce((int, part) => (int << 8) + parseInt(part, 10), 0) >>> 0;
  };
  
  const ipInt = ipToInt(ip);
  if (ipInt === null) return false; // IPv6 or invalid
  
  // Check each CIDR range
  for (const cidr of cidrRanges) {
    if (!cidr || cidr.includes(':')) continue; // Skip empty or IPv6
    
    const [range, bits] = cidr.split('/');
    const maskBits = parseInt(bits, 10);
    const mask = (0xFFFFFFFF << (32 - maskBits)) >>> 0;
    
    const rangeInt = ipToInt(range);
    if (rangeInt === null) continue;
    
    if ((ipInt & mask) === (rangeInt & mask)) {
      return true;
    }
  }
  
  return false;
}

// Refang defanged IOCs (convert safe format back to original)
function refangObservable(observable) {
  if (!observable) return observable;
  
  observable = observable.trim();
  
  // Replace common defang patterns
  observable = observable
    // Protocol defanging - hxxp variations
    .replace(/hxxp:\/\//gi, 'http://')
    .replace(/hxxps:\/\//gi, 'https://')
    .replace(/hxxp\[:(\/\/|:\/\/)/gi, 'http://')
    .replace(/hxxps\[:(\/\/|:\/\/)/gi, 'https://')
    .replace(/hXXp:\/\//gi, 'http://')
    .replace(/hXXps:\/\//gi, 'https://')
    // Protocol with brackets
    .replace(/h\[tt\]p:\/\//gi, 'http://')
    .replace(/h\[tt\]ps:\/\//gi, 'https://')
    .replace(/ht\[tp\]:\/\//gi, 'http://')
    .replace(/ht\[tps\]:\/\//gi, 'https://')
    .replace(/h\(tt\)p:\/\//gi, 'http://')
    .replace(/h\(tt\)ps:\/\//gi, 'https://')
    
    // Dot defanging
    .replace(/\[\.\]/g, '.')
    .replace(/\(\.\)/g, '.')
    .replace(/\{.\}/g, '.')
    .replace(/\[dot\]/gi, '.')
    .replace(/\(dot\)/gi, '.')
    
    // At sign defanging
    .replace(/\[@\]/g, '@')
    .replace(/\(@\)/g, '@')
    .replace(/\[at\]/gi, '@')
    .replace(/\(at\)/gi, '@')
    
    // Protocol separator defanging
    .replace(/\[:\/\/\]/g, '://')
    .replace(/\(:\/\/\)/g, '://')
    
    // Slash defanging
    .replace(/\[\/\]/g, '/')
    .replace(/\(\/\)/g, '/')
    
    // Colon defanging
    .replace(/\[:\]/g, ':')
    .replace(/\(:\)/g, ':');
  
  return observable;
}

// Detect observable type
function detectObservableType(observable) {
  // Clean up the observable
  observable = observable.trim();
  
  // Check defanged URLs first (before refanging)
  if (/^hxxps?[:(\[]?:?\/\//i.test(observable)) return 'url';
  if (/^h\[tt\]ps?[:(\[]?:?\/\//i.test(observable)) return 'url';
  if (/^ht\[tps?\][:(\[]?:?\/\//i.test(observable)) return 'url';
  
  // Check for URL with protocol
  if (/^https?:\/\//i.test(observable)) return 'url';
  
  // Check for IP/path format (treat as URL)
  if (/^(\d{1,3}\.){3}\d{1,3}\//.test(observable)) return 'url';
  
  // Check for IP:port/path format (treat as URL)
  if (/^(\d{1,3}\.){3}\d{1,3}:\d+\//.test(observable)) return 'url';
  
  // Check for IP:port format (IPv4)
  if (/^(\d{1,3}\.){3}\d{1,3}:\d+$/.test(observable)) return 'ip';
  
  // Check for plain IPv4
  if (/^(\d{1,3}\.){3}\d{1,3}$/.test(observable)) return 'ip';
  
  // Check for IPv6 (with or without port - basic check)
  if (/^([0-9a-fA-F]{0,4}:){2,7}[0-9a-fA-F]{0,4}$/.test(observable)) return 'ip';
  
  // Check for hash
  if (/^[a-fA-F0-9]{32}$|^[a-fA-F0-9]{40}$|^[a-fA-F0-9]{64}$/.test(observable)) return 'hash';
  
  // Check for domain:port/path format (treat as URL)
  if (/^([a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}:\d+\//.test(observable)) {
    return 'url';
  }
  
  // Check for domain:port format
  if (/^([a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}:\d+$/.test(observable)) {
    return 'domain';
  }
  
  // Check for domain with trailing slash or path
  // If it has "/" anywhere, treat as URL
  if (/^([a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}\//.test(observable)) {
    return 'url';
  }
  
  // Pure domain (supports subdomains like sub.domain.com or multi.level.domain.co.uk)
  if (/^([a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$/.test(observable)) {
    return 'domain';
  }
  
  return 'unknown';
}

// Utility functions
function showLoading(show) {
  document.getElementById('loadingIndicator').classList.toggle('hidden', !show);
}

function clearResults() {
  document.getElementById('results').innerHTML = '';
  const existingError = document.querySelector('.error-message');
  if (existingError) existingError.remove();
}

function showError(message) {
  clearResults();
  const resultsSection = document.getElementById('results');
  const errorDiv = document.createElement('div');
  errorDiv.className = 'error-message';
  errorDiv.textContent = message;
  resultsSection.appendChild(errorDiv);
}

function escapeHtml(text) {
  const div = document.createElement('div');
  div.textContent = text;
  return div.innerHTML;
}

// Tool configurations (client-side queries for speed)
const TOOL_CONFIGS = {
  ipinfo: {
    types: ['ip'],
    requiresKey: true,
    query: async (observable, type, apiKey) => {
      const response = await fetch(`https://ipinfo.io/${observable}?token=${apiKey}`);
      if (!response.ok) throw new Error(`HTTP ${response.status}`);
      const data = await response.json();
      return {
        status: 'success',
        data: {
          city: data.city || 'N/A',
          region: data.region || 'N/A',
          country: data.country || 'N/A',
          org: data.org || 'N/A',
          postal: data.postal || 'N/A',
          timezone: data.timezone || 'N/A',
          url: `https://ipinfo.io/${observable}`
        }
      };
    }
  },
  
  greynoise: {
    types: ['ip'],
    requiresKey: false,
    query: async (observable, type, apiKey) => {
      const response = await fetch(`https://api.greynoise.io/v3/community/${observable}`);
      if (!response.ok) throw new Error(`HTTP ${response.status}`);
      const data = await response.json();
      return {
        status: 'success',
        data: {
          noise: data.noise ? 'Yes' : 'No',
          riot: data.riot ? 'Yes' : 'No',
          classification: data.classification || 'unknown',
          name: data.name || 'N/A',
          lastSeen: data.last_seen || 'N/A',
          url: `https://viz.greynoise.io/ip/${observable}`
        }
      };
    }
  },
  
  cloudflareip: {
    types: ['ip', 'domain', 'url'],
    requiresKey: false,
    query: async (observable, type, apiKey) => {
      // Extract IP from domain/URL or use IP directly
      let ipToCheck = observable;
      
      if (type === 'url' || type === 'domain') {
        // For URLs/domains, resolve to IP first
        try {
          // Use DNS over HTTPS to resolve domain to IP
          const hostname = type === 'url' 
            ? new URL(observable.startsWith('http') ? observable : 'http://' + observable).hostname
            : observable;
          
          const dnsResponse = await fetch(`https://dns.google/resolve?name=${hostname}&type=A`);
          const dnsData = await dnsResponse.json();
          
          if (dnsData.Answer && dnsData.Answer.length > 0) {
            ipToCheck = dnsData.Answer[0].data;
          } else {
            return {
              status: 'success',
              data: {
                isCloudflare: false,
                message: 'Could not resolve domain to IP',
                url: 'https://www.cloudflare.com/ips/'
              }
            };
          }
        } catch (error) {
          return {
            status: 'success',
            data: {
              isCloudflare: false,
              message: 'DNS resolution failed',
              url: 'https://www.cloudflare.com/ips/'
            }
          };
        }
      }
      
      // Fetch Cloudflare IP ranges
      const [v4Response, v6Response] = await Promise.all([
        fetch('https://www.cloudflare.com/ips-v4'),
        fetch('https://www.cloudflare.com/ips-v6')
      ]);
      
      if (!v4Response.ok || !v6Response.ok) {
        throw new Error('Failed to fetch Cloudflare IP ranges');
      }
      
      const v4Ranges = (await v4Response.text()).trim().split('\n');
      const v6Ranges = (await v6Response.text()).trim().split('\n');
      
      // Check if IP is in Cloudflare ranges
      const isCloudflare = checkIPInRanges(ipToCheck, [...v4Ranges, ...v6Ranges]);
      
      return {
        status: 'success',
        data: {
          isCloudflare: isCloudflare,
          message: isCloudflare ? `IP ${ipToCheck} belongs to Cloudflare network` : `IP ${ipToCheck} is not a Cloudflare IP`,
          url: 'https://www.cloudflare.com/ips/'
        }
      };
    }
  },
  
  hybridanalysis: {
    types: ['hash', 'url'],
    requiresKey: true,
    query: async (observable, type, apiKey) => {
      try {
        let searchUrl;
        if (type === 'hash') {
          searchUrl = `https://www.hybrid-analysis.com/sample/${observable}`;
        } else {
          searchUrl = `https://www.hybrid-analysis.com/search?query=${encodeURIComponent(observable)}`;
        }
        
        // If API key is provided, try to get actual results
        if (apiKey && type === 'hash') {
          try {
            const response = await fetch(`https://www.hybrid-analysis.com/api/v2/search/hash`, {
              method: 'POST',
              headers: {
                'api-key': apiKey,
                'User-Agent': 'InvestigateR-Extension/1.0',
                'Content-Type': 'application/x-www-form-urlencoded'
              },
              body: `hash=${observable}`
            });
            
            if (response.ok) {
              const results = await response.json();
              if (results && results.length > 0) {
                const report = results[0];
                return {
                  status: 'success',
                  data: {
                    found: 'Yes',
                    verdict: report.verdict || 'Unknown',
                    threatScore: report.threat_score || 0,
                    vxFamily: report.vx_family || 'N/A',
                    environment: report.environment_description || 'N/A',
                    url: searchUrl
                  }
                };
              }
            }
          } catch (apiError) {
            // API error - continue to fallback
          }
        }
        
        // No API key or not found - just provide search link
        return {
          status: 'success',
          data: {
            found: 'No',
            verdict: undefined,
            threatScore: undefined,
            message: apiKey ? 'Not found in database' : 'Check manually (API key recommended for auto-check)',
            url: searchUrl
          }
        };
      } catch (error) {
        return {
          status: 'error',
          error: error.message
        };
      }
    }
  },
  
  urlhaus: {
    types: ['url', 'domain', 'ip'],
    requiresKey: true,
    query: async (observable, type, apiKey) => {
      // Try exact URL match first
      let response = await fetch('https://urlhaus-api.abuse.ch/v1/url/', {
        method: 'POST',
        headers: { 
          'Content-Type': 'application/x-www-form-urlencoded',
          'Auth-Key': apiKey
        },
        body: `url=${encodeURIComponent(observable)}`
      });
      
      if (!response.ok) throw new Error(`HTTP ${response.status}`);
      let data = await response.json();
      
      // If exact URL not found, try host-based search (domain or IP)
      if (data.query_status !== 'ok' && (type === 'url' || type === 'domain' || type === 'ip')) {
        try {
          let host = observable;
          let searchType = type;
          
          // Extract hostname from URL if it's a URL type
          if (type === 'url') {
            const urlObj = new URL(observable.startsWith('http') ? observable : `http://${observable}`);
            host = urlObj.hostname;
            
            // Determine if extracted host is an IP or domain
            if (/^(\d{1,3}\.){3}\d{1,3}$/.test(host)) {
              searchType = 'ip';
            } else {
              searchType = 'domain';
            }
          }
          
          // Search by host (domain or IP)
          response = await fetch('https://urlhaus-api.abuse.ch/v1/host/', {
            method: 'POST',
            headers: { 
              'Content-Type': 'application/x-www-form-urlencoded',
              'Auth-Key': apiKey
            },
            body: `host=${encodeURIComponent(host)}`
          });
          
          if (response.ok) {
            const hostData = await response.json();
            if (hostData.query_status === 'ok' && hostData.urls && hostData.urls.length > 0) {
              // Found URLs for this host
              const latestUrl = hostData.urls[0];
              return {
                status: 'success',
                data: {
                  found: true,
                  threat: latestUrl.threat || 'N/A',
                  dateAdded: latestUrl.date_added || 'N/A',
                  reporter: latestUrl.reporter || 'N/A',
                  urlCount: hostData.url_count || hostData.urls.length,
                  searchType: searchType,
                  url: `https://urlhaus.abuse.ch/host/${host}/`
                }
              };
            }
          }
        } catch (urlError) {
          // Host extraction failed - continue
        }
      }
      
      // Return exact match result or not found
      return {
        status: 'success',
        data: {
          found: data.query_status === 'ok',
          threat: data.threat || 'N/A',
          dateAdded: data.date_added || 'N/A',
          reporter: data.reporter || 'N/A',
          searchType: 'url',
          url: 'https://urlhaus.abuse.ch/'
        }
      };
    }
  },
  
  openphish: {
    types: ['url', 'domain'],
    requiresKey: false,
    query: async (observable, type, apiKey) => {
      try {
        const response = await fetch('https://openphish.com/feed.txt');
        if (!response.ok) throw new Error(`HTTP ${response.status}`);
        const feed = await response.text();
        
        // Normalize observable - remove trailing slash for domains
        let searchTerm = observable;
        if (type === 'domain') {
          searchTerm = observable.replace(/\/$/, ''); // Remove trailing slash
          // Check if domain appears in any URL in the feed (case insensitive)
          const domainPattern = new RegExp(`://[^/]*${searchTerm.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')}`, 'i');
          const found = domainPattern.test(feed);
          return {
            status: 'success',
            data: {
              found: found,
              message: found ? 'Listed in OpenPhish feed' : 'Not found in feed',
              url: 'https://openphish.com/'
            }
          };
        } else {
          // For URLs, check for exact match
          const found = feed.includes(searchTerm);
          return {
            status: 'success',
            data: {
              found: found,
              message: found ? 'Listed in OpenPhish feed' : 'Not found in feed',
              url: 'https://openphish.com/'
            }
          };
        }
      } catch (error) {
        return {
          status: 'success',
          data: {
            found: false,
            message: 'Unable to check (feed may be large)',
            url: 'https://openphish.com/'
          }
        };
      }
    }
  },
  
  sansisc: {
    types: ['ip'],
    requiresKey: false,
    query: async (observable, type, apiKey) => {
      const response = await fetch(`https://isc.sans.edu/api/ip/${observable}?json`);
      if (!response.ok) throw new Error(`HTTP ${response.status}`);
      const data = await response.json();
      const ipData = data.ip || {};
      return {
        status: 'success',
        data: {
          count: ipData.count || 0,
          attacks: ipData.attacks || 0,
          mindate: ipData.mindate || 'N/A',
          maxdate: ipData.maxdate || 'N/A',
          comment: ipData.comment || 'None',
          url: `https://isc.sans.edu/ipinfo.html?ip=${observable}`
        }
      };
    }
  },
  
  urlquery: {
    types: ['url', 'domain', 'ip'],
    requiresKey: true,
    query: async (observable, type, apiKey) => {
      try {
        // Prepare query parameter - remove protocol from URLs
        let queryParam = observable;
        if (observable.startsWith('http://') || observable.startsWith('https://')) {
          const url = new URL(observable);
          queryParam = url.hostname + url.pathname + url.search + url.hash;
        }
        
        const apiUrl = `https://api.urlquery.net/public/v1/search/reports/`;
        const params = new URLSearchParams({
          query: queryParam,
          limit: '100',
          offset: '0'
        });
        
        const response = await fetch(`${apiUrl}?${params}`, {
          headers: {
            'x-apikey': apiKey,
            'accept': 'application/json'
          }
        });
        
        if (!response.ok) {
          if (response.status === 401) throw new Error('Invalid API key');
          if (response.status === 404) {
            return {
              status: 'success',
              data: {
                found: false,
                total_hits: 0,
                reports: [],
                observable: observable,
                url: `https://urlquery.net/search?q=${encodeURIComponent(queryParam)}&view=&type=reports`
              }
            };
          }
          throw new Error(`HTTP ${response.status}`);
        }
        
        const data = await response.json();
        const totalHits = data.total_hits || 0;
        const reports = data.reports || [];
        
        return {
          status: 'success',
          data: {
            found: totalHits > 0,
            total_hits: totalHits,
            reports_count: reports.length,
            reports: reports.slice(0, 5), // Show first 5 reports
            observable: observable,
            query_string: queryParam,
            url: `https://urlquery.net/search?q=${encodeURIComponent(queryParam)}&view=&type=reports`
          }
        };
      } catch (error) {
        return {
          status: 'success',
          data: {
            found: false,
            total_hits: 0,
            reports: [],
            observable: observable,
            error_message: error.message,
            url: `https://urlquery.net/search?q=${encodeURIComponent(observable)}&view=&type=reports`
          }
        };
      }
    }
  },
  
  whois: {
    types: ['ip', 'domain'],
    requiresKey: false,
    query: async (observable, type, apiKey) => {
      if (type === 'ip') {
        // Try multiple IP info APIs in order
        try {
          // Try ipapi.co first
          let response = await fetch(`https://ipapi.co/${observable}/json/`);
          
          if (!response.ok || response.status === 429) {
            // Rate limited, try ip-api.com as fallback (CORS-enabled)
            response = await fetch(`https://ipapi.com/json/${observable}?access_key=free`);
            if (!response.ok) {
              // Try freeipapi.com
              response = await fetch(`https://freeipapi.com/api/json/${observable}`);
            }
            if (!response.ok) throw new Error('All APIs failed');
          }
          
          const data = await response.json();
          
          // Check if ipapi.co returned an error
          if (data.error) {
            throw new Error(data.reason || 'API Error');
          }
          
          // Handle different API response formats
          return {
            status: 'success',
            data: {
              type: 'ip',
              organization: data.org || data.connection?.organization || data.organization || 'N/A',
              asn: data.asn || data.connection?.asn || data.as || 'N/A',
              country: data.country_name ? `${data.country_name} (${data.country || 'N/A'})` : (data.countryName || data.country || 'N/A'),
              region: data.region || data.regionName || 'N/A',
              city: data.city || data.cityName || 'N/A',
              network: data.network || 'N/A',
              isp: data.isp || 'N/A',
              url: `https://who.is/whois-ip/ip-address/${observable}`
            }
          };
        } catch (error) {
          return {
            status: 'success',
            data: {
              type: 'error',
              message: 'Unable to fetch IP information - API rate limited or blocked',
              url: `https://who.is/whois-ip/ip-address/${observable}`
            }
          };
        }
      } else {
        // For domains, try RDAP which sometimes allows CORS
        try {
          // Extract TLD to find RDAP server
          const tld = observable.split('.').pop();
          
          // Try common RDAP servers
          const rdapServers = [
            `https://rdap.org/domain/${observable}`,
            `https://rdap.verisign.com/com/v1/domain/${observable}`,
            `https://rdap.nic.${tld}/${observable}`
          ];
          
          for (const server of rdapServers) {
            try {
              const response = await fetch(server);
              if (response.ok) {
                const data = await response.json();
                
                // Extract emails from entities with categorization
                const allEmails = [];
                let registrarEmail = null;
                let abuseEmail = null;
                
                if (data.entities) {
                  data.entities.forEach(entity => {
                    if (entity.vcardArray && entity.vcardArray[1]) {
                      entity.vcardArray[1].forEach(field => {
                        if (field[0] === 'email' && field[3]) {
                          const email = field[3];
                          allEmails.push(email);
                          
                          // Identify abuse email
                          if (email.toLowerCase().includes('abuse') || 
                              entity.roles?.includes('abuse') ||
                              entity.role === 'abuse') {
                            abuseEmail = email;
                          }
                          
                          // Identify registrar email
                          if (entity.roles?.includes('registrar') || 
                              entity.role === 'registrar') {
                            registrarEmail = email;
                          }
                        }
                      });
                    }
                    
                    // Check entity-level email field (some RDAPs use this)
                    if (entity.emails && Array.isArray(entity.emails)) {
                      entity.emails.forEach(email => {
                        allEmails.push(email);
                        if (email.toLowerCase().includes('abuse') || entity.roles?.includes('abuse')) {
                          abuseEmail = email;
                        }
                        if (entity.roles?.includes('registrar')) {
                          registrarEmail = email;
                        }
                      });
                    }
                  });
                }
                
                // Deduplicate emails
                const uniqueEmails = [...new Set(allEmails)];
                
                // Get registrar name
                let registrar = 'N/A';
                if (data.entities && data.entities[0]) {
                  const regEntity = data.entities[0];
                  if (regEntity.vcardArray && regEntity.vcardArray[1]) {
                    const fnField = regEntity.vcardArray[1].find(f => f[0] === 'fn');
                    if (fnField) registrar = fnField[3];
                  }
                }
                
                return {
                  status: 'success',
                  data: {
                    type: 'domain',
                    domain: observable,
                    registrar: registrar,
                    created: data.events?.find(e => e.eventAction === 'registration')?.eventDate || 'N/A',
                    updated: data.events?.find(e => e.eventAction === 'last changed')?.eventDate || 'N/A',
                    expires: data.events?.find(e => e.eventAction === 'expiration')?.eventDate || 'N/A',
                    nameservers: data.nameservers?.map(ns => ns.ldhName).join(', ') || 'N/A',
                    status: data.status?.[0] || 'N/A',
                    emails: uniqueEmails.length > 0 ? uniqueEmails.join(', ') : 'N/A',
                    registrarEmail: registrarEmail || 'N/A',
                    abuseEmail: abuseEmail || 'N/A',
                    url: `https://who.is/whois/${observable}`
                  }
                };
              }
            } catch (e) {
              continue;
            }
          }
          
          // If all RDAP fails, return external link
          return {
            status: 'success',
            data: {
              type: 'domain',
              domain: observable,
              message: 'Full WHOIS registration data available online',
              note: 'Domain WHOIS requires external access due to CORS restrictions',
              url: `https://who.is/whois/${observable}`
            }
          };
        } catch (error) {
          return {
            status: 'success',
            data: {
              type: 'domain',
              domain: observable,
              message: 'Full WHOIS registration data available online',
              note: 'Domain WHOIS requires external access due to CORS restrictions',
              url: `https://who.is/whois/${observable}`
            }
          };
        }
      }
    }
  },
  
  dnsrecords: {
    types: ['domain'],
    requiresKey: false,
    query: async (observable, type, apiKey) => {
      // Query multiple DNS record types
      const recordTypes = ['A', 'AAAA', 'MX', 'TXT', 'NS', 'CNAME'];
      const results = {};
      
      try {
        const promises = recordTypes.map(async (recordType) => {
          try {
            const response = await fetch(`https://dns.google/resolve?name=${observable}&type=${recordType}`);
            if (response.ok) {
              const data = await response.json();
              if (data.Answer && data.Answer.length > 0) {
                results[recordType] = data.Answer.map(a => a.data);
              }
            }
          } catch (e) {}
        });
        
        await Promise.all(promises);
      } catch (error) {}
      
      return {
        status: 'success',
        data: {
          hasRecords: Object.keys(results).length > 0,
          A: results.A || [],
          AAAA: results.AAAA || [],
          MX: results.MX || [],
          TXT: results.TXT || [],
          NS: results.NS || [],
          CNAME: results.CNAME || [],
          url: `https://dns.google/query?name=${observable}`
        }
      };
    }
  },
  
  ipblocklists: {
    types: ['ip'],
    requiresKey: false,
    query: async (observable, type, apiKey) => {
      const blocklists = [
        { url: `https://reputation.alienvault.com/reputation.data`, name: 'AlienVault' },
        { url: `https://rules.emergingthreats.net/blockrules/compromised-ips.txt`, name: 'EmergingThreats' },
        { url: `https://www.binarydefense.com/banlist.txt`, name: 'BinaryDefense' },
        { url: `https://blocklist.de/lists/all.txt`, name: 'Blocklist.de All' },
        { url: `https://lists.blocklist.de/lists/ssh.txt`, name: 'SSH Attacks' },
        { url: `https://lists.blocklist.de/lists/bruteforcelogin.txt`, name: 'Bruteforce' },
        { url: `https://cinsscore.com/list/ci-badguys.txt`, name: 'CINS Army' },
        { url: `https://raw.githubusercontent.com/stamparm/ipsum/master/levels/3.txt`, name: 'IPsum L3' },
        { url: `https://raw.githubusercontent.com/firehol/blocklist-ipsets/master/firehol_level1.netset`, name: 'FireHOL L1' },
        { url: `https://raw.githubusercontent.com/duggytuxy/malicious_ip_addresses/main/botnets_zombies_scanner_spam_ips.txt`, name: 'Botnets' },
        { url: `https://lists.blocklist.de/lists/apache.txt`, name: 'Apache Attacks' },
        { url: `https://lists.blocklist.de/lists/mail.txt`, name: 'Mail Attacks' },
        { url: `https://lists.blocklist.de/lists/imap.txt`, name: 'IMAP Attacks' },
        { url: `https://lists.blocklist.de/lists/ftp.txt`, name: 'FTP Attacks' },
        { url: `https://raw.githubusercontent.com/stamparm/ipsum/master/levels/2.txt`, name: 'IPsum L2' },
        { url: `https://raw.githubusercontent.com/firehol/blocklist-ipsets/master/firehol_level2.netset`, name: 'FireHOL L2' },
        { url: `https://raw.githubusercontent.com/firehol/blocklist-ipsets/master/firehol_level3.netset`, name: 'FireHOL L3' },
        { url: `https://raw.githubusercontent.com/firehol/blocklist-ipsets/master/stopforumspam_7d.ipset`, name: 'StopForumSpam' },
        { url: `https://raw.githubusercontent.com/firehol/blocklist-ipsets/master/cybercrime.ipset`, name: 'Cybercrime' },
        { url: `https://raw.githubusercontent.com/firehol/blocklist-ipsets/master/dshield_top_1000.netset`, name: 'DShield Top1K' }
      ];
      
      let found = 0;
      let foundIn = [];
      
      try {
        const checkPromises = blocklists.map(async (list) => {
          try {
            const response = await fetch(list.url, { signal: AbortSignal.timeout(5000) });
            if (response.ok) {
              const text = await response.text();
              if (text.includes(observable)) {
                found++;
                foundIn.push(list.name);
              }
            }
          } catch (e) {
            // Timeout or error - skip this list
          }
        });
        
        await Promise.all(checkPromises);
      } catch (error) {}
      
      return {
        status: 'success',
        data: {
          checked: blocklists.length,
          found: found,
          foundIn: foundIn.join(', ') || 'None',
          message: found > 0 ? `⚠️ Listed in ${found} blocklist(s)` : '✓ Not found in checked lists',
          url: 'https://blocklist.de/',
          entityType: type
        }
      };
    }
  },
  
  domainblocklists: {
    types: ['domain', 'url'],
    requiresKey: false,
    query: async (observable, type, apiKey) => {
      // Extract domain from URL if needed
      let domain = observable;
      if (type === 'url') {
        try {
          const url = new URL(observable.startsWith('http') ? observable : 'http://' + observable);
          domain = url.hostname;
        } catch (e) {
          domain = observable;
        }
      }
      
      const blocklists = [
        { url: `https://urlhaus.abuse.ch/downloads/text/`, name: 'URLhaus (Malware)', category: 'malware' },
        { url: `https://phishing.army/download/phishing_army_blocklist.txt`, name: 'Phishing Army', category: 'phishing' },
        { url: `https://openphish.com/feed.txt`, name: 'OpenPhish', category: 'phishing' },
        { url: `https://raw.githubusercontent.com/mitchellkrogza/Phishing.Database/master/phishing-domains-ACTIVE.txt`, name: 'Phishing Database', category: 'phishing' },
        { url: `https://blocklistproject.github.io/Lists/malware.txt`, name: 'Blocklist Project Malware', category: 'malware' },
        { url: `https://blocklistproject.github.io/Lists/phishing.txt`, name: 'Blocklist Project Phishing', category: 'phishing' },
        { url: `https://blocklistproject.github.io/Lists/fraud.txt`, name: 'Blocklist Project Fraud', category: 'fraud' },
        { url: `https://raw.githubusercontent.com/hagezi/dns-blocklists/main/domains/pro.txt`, name: 'HaGeZi Pro', category: 'threat' }
      ];
      
      let found = 0;
      let foundDetails = [];
      let checked = 0;
      let failed = 0;
      
      try {
        const checkPromises = blocklists.map(async (list) => {
          try {
            const response = await fetch(list.url, { 
              signal: AbortSignal.timeout(8000),
              headers: { 'User-Agent': 'InvestigateR-Extension/1.0' }
            });
            if (response.ok) {
              checked++;
              const text = await response.text();
              const domainLower = domain.toLowerCase();
              
              // Check for exact domain match or subdomain match
              const lines = text.toLowerCase().split('\n');
              const isListed = lines.some(line => {
                const cleanLine = line.trim().replace(/^#.*/, '').trim();
                return cleanLine === domainLower || 
                       cleanLine === `www.${domainLower}` ||
                       domainLower.endsWith(`.${cleanLine}`);
              });
              
              if (isListed) {
                found++;
                foundDetails.push({
                  name: list.name,
                  category: list.category
                });
              }
            } else {
              failed++;
            }
          } catch (e) {
            failed++;
          }
        });
        
        await Promise.all(checkPromises);
      } catch (error) {}
      
      // Categorize findings
      const categories = {
        malware: foundDetails.filter(d => d.category === 'malware').map(d => d.name),
        phishing: foundDetails.filter(d => d.category === 'phishing').map(d => d.name),
        fraud: foundDetails.filter(d => d.category === 'fraud').map(d => d.name),
        threat: foundDetails.filter(d => d.category === 'threat').map(d => d.name)
      };
      
      return {
        status: 'success',
        data: {
          domain: domain,
          checked: checked,
          failed: failed,
          found: found,
          foundIn: foundDetails.map(d => d.name).join(', ') || 'None',
          categories: categories,
          message: found > 0 ? `⚠️ Listed in ${found} blocklist(s)` : '✓ Not found in any blocklists',
          url: `https://phishing.army/`,
          entityType: 'domain'
        }
      };
    }
  },
  
  virustotal: {
    types: ['ip', 'domain', 'url', 'hash'],
    requiresKey: true,
    query: async (observable, type, apiKey) => {
      let endpoint;
      
      if (type === 'hash') {
        endpoint = `https://www.virustotal.com/api/v3/files/${observable}`;
      } else if (type === 'url') {
        // Properly encode URL for VirusTotal API
        const urlId = btoa(observable).replace(/\+/g, '-').replace(/\//g, '_').replace(/=/g, '');
        endpoint = `https://www.virustotal.com/api/v3/urls/${urlId}`;
      } else {
        endpoint = `https://www.virustotal.com/api/v3/${type === 'ip' ? 'ip_addresses' : 'domains'}/${observable}`;
      }
      
      const response = await fetch(endpoint, {
        headers: { 'x-apikey': apiKey }
      });
      
      if (!response.ok) throw new Error(`HTTP ${response.status}`);
      
      const data = await response.json();
      const stats = data.data.attributes.last_analysis_stats;
      
      return {
        status: 'success',
        data: {
          malicious: stats.malicious || 0,
          suspicious: stats.suspicious || 0,
          clean: stats.undetected || 0,
          total: Object.values(stats).reduce((a, b) => a + b, 0),
          url: `https://www.virustotal.com/gui/${type === 'ip' ? 'ip-address' : type}/${observable}`
        }
      };
    }
  },
  
  abuseipdb: {
    types: ['ip'],
    requiresKey: true,
    query: async (observable, type, apiKey) => {
      const response = await fetch(`https://api.abuseipdb.com/api/v2/check?ipAddress=${observable}&maxAgeInDays=90`, {
        headers: { 'Key': apiKey, 'Accept': 'application/json' }
      });
      
      if (!response.ok) throw new Error(`HTTP ${response.status}`);
      
      const result = await response.json();
      const data = result.data;
      
      return {
        status: 'success',
        data: {
          abuseScore: data.abuseConfidenceScore,
          totalReports: data.totalReports,
          country: data.countryCode,
          isp: data.isp,
          usage: data.usageType,
          url: `https://www.abuseipdb.com/check/${observable}`
        }
      };
    }
  },
  
  alienvault: {
    types: ['ip', 'domain', 'hash'],
    requiresKey: true,
    query: async (observable, type, apiKey) => {
      const endpoint = type === 'ip' 
        ? `https://otx.alienvault.com/api/v1/indicators/IPv4/${observable}/general`
        : type === 'domain'
        ? `https://otx.alienvault.com/api/v1/indicators/domain/${observable}/general`
        : `https://otx.alienvault.com/api/v1/indicators/file/${observable}/general`;
      
      const response = await fetch(endpoint, {
        headers: { 'X-OTX-API-KEY': apiKey }
      });
      
      if (!response.ok) throw new Error(`HTTP ${response.status}`);
      
      const data = await response.json();
      
      return {
        status: 'success',
        data: {
          pulseCount: data.pulse_info?.count || 0,
          reputation: data.reputation || 0,
          url: `https://otx.alienvault.com/indicator/${type}/${observable}`
        }
      };
    }
  },
  
  urlscan: {
    types: ['url', 'domain'],
    requiresKey: false,
    query: async (observable, type, apiKey) => {
      // Use public search API first, falls back to scan with API key if provided
      try {
        // Search for existing scans - get last 5
        const searchResponse = await fetch(`https://urlscan.io/api/v1/search/?q=${encodeURIComponent(type === 'domain' ? `domain:${observable}` : `page.url:${observable}`)}&size=5`);
        
        if (searchResponse.ok) {
          const searchData = await searchResponse.json();
          
          if (searchData.results && searchData.results.length > 0) {
            // Process all results
            const scans = searchData.results.map(result => ({
              verdict: result.verdicts?.overall?.malicious ? 'malicious' : (result.verdicts?.overall?.suspicious ? 'suspicious' : 'clean'),
              score: result.verdicts?.overall?.score || 0,
              malicious: result.verdicts?.overall?.malicious || false,
              brands: result.verdicts?.overall?.brands?.join(', ') || 'None',
              categories: result.verdicts?.overall?.categories?.join(', ') || 'None',
              country: result.page?.country || 'N/A',
              server: result.page?.server || 'N/A',
              scanTime: result.task?.time || 'N/A',
              url: result.result || `https://urlscan.io/result/${result.task?.uuid}/`
            }));
            
            // Use first (most recent) scan for summary
            const latestScan = scans[0];
            
            return {
              status: 'success',
              data: {
                found: true,
                totalScans: searchData.total || scans.length,
                scans: scans,
                verdict: latestScan.verdict,
                score: latestScan.score,
                malicious: latestScan.malicious,
                brands: latestScan.brands,
                categories: latestScan.categories,
                country: latestScan.country,
                server: latestScan.server,
                lastScanned: latestScan.scanTime,
                searchUrl: `https://urlscan.io/search/#${encodeURIComponent(observable)}`
              }
            };
          }
        }
        
        // If API key provided and no results found, submit new scan
        if (apiKey) {
          const submitResponse = await fetch('https://urlscan.io/api/v1/scan/', {
            method: 'POST',
            headers: {
              'Content-Type': 'application/json',
              'API-Key': apiKey
            },
            body: JSON.stringify({ url: observable, visibility: 'unlisted' })
          });
          
          if (submitResponse.ok) {
            const submitData = await submitResponse.json();
            return {
              status: 'success',
              data: {
                found: false,
                message: 'New scan submitted',
                url: submitData.result,
                uuid: submitData.uuid
              }
            };
          }
        }
        
        // No results and no API key
        return {
          status: 'success',
          data: {
            found: false,
            message: 'No previous scans found',
            url: `https://urlscan.io/search/#${encodeURIComponent(observable)}`
          }
        };
      } catch (error) {
        return {
          status: 'success',
          data: {
            found: false,
            message: 'Search failed',
            url: `https://urlscan.io/search/#${encodeURIComponent(observable)}`
          }
        };
      }
    }
  },
  
  shodan: {
    types: ['ip'],
    requiresKey: false,
    query: async (observable, type, apiKey) => {
      const response = await fetch(`https://internetdb.shodan.io/${observable}`);
      
      if (!response.ok) {
        if (response.status === 404) {
          return {
            status: 'success',
            data: { 
              ports: 'None',
              vulns: 'None',
              tags: 'None',
              cpes: 0,
              url: `https://www.shodan.io/host/${observable}`
            }
          };
        }
        throw new Error(`HTTP ${response.status}`);
      }
      
      const data = await response.json();
      
      return {
        status: 'success',
        data: {
          ports: data.ports?.join(', ') || 'None',
          vulns: data.vulns?.join(', ') || 'None',
          tags: data.tags?.join(', ') || 'None',
          cpes: data.cpes?.length || 0,
          url: `https://www.shodan.io/host/${observable}`
        }
      };
    }
  },
  
  phishtank: {
    types: ['url', 'domain'],
    requiresKey: false,
    query: async (observable, type, apiKey) => {
      // PhishTank implementation using CSV blacklist download (robinzor method)
      try {
        const PHISHTANK_CSV_URL = 'https://data.phishtank.com/data/online-valid.csv';
        
        // Normalize observable
        let host, url, searchUrl;
        if (type === 'domain') {
          host = observable.replace(/\/$/, '').toLowerCase();
          url = observable;
          searchUrl = observable;
        } else {
          // URL - extract host
          url = observable;
          searchUrl = observable;
          try {
            const urlObj = new URL(observable.startsWith('http') ? observable : 'http://' + observable);
            host = urlObj.hostname.toLowerCase();
          } catch {
            host = observable.toLowerCase();
          }
        }
        
        // Download PhishTank CSV blacklist
        const response = await fetch(PHISHTANK_CSV_URL, {
          signal: AbortSignal.timeout(15000),
          headers: { 'User-Agent': 'InvestigateR-Extension/1.0' }
        });
        
        if (!response.ok) {
          // Fallback to search link
          const encodedUrl = encodeURIComponent(type === 'domain' ? `http://${host}` : searchUrl);
          return {
            status: 'success',
            data: {
              inDatabase: null,
              isPhishing: null,
              message: 'CSV download failed - search manually',
              url: `https://www.phishtank.com/search.php?verified=u&active=u&Search=Search&url=${encodedUrl}`
            }
          };
        }
        
        const csvContent = await response.text();
        const lines = csvContent.split('\n');
        
        // Parse CSV and search for matches
        // CSV format: phish_id,url,phish_detail_url,submission_time,verified,verification_time,online,target
        for (let i = 1; i < lines.length; i++) { // Skip header
          const line = lines[i].trim();
          if (!line || line.startsWith('#')) continue;
          
          // Handle CSV with quoted fields (URLs may contain commas)
          const parts = [];
          let current = '';
          let inQuotes = false;
          
          for (let j = 0; j < line.length; j++) {
            const char = line[j];
            if (char === '"') {
              inQuotes = !inQuotes;
            } else if (char === ',' && !inQuotes) {
              parts.push(current.trim().replace(/^"|"$/g, ''));
              current = '';
            } else {
              current += char;
            }
          }
          parts.push(current.trim().replace(/^"|"$/g, ''));
          
          if (parts.length < 2) continue;
          
          const phishId = parts[0];
          const phishUrl = parts[1].toLowerCase();
          
          if (!phishUrl) continue;
          
          // Extract host from phish URL (SpiderFoot method: split on / and take index 2)
          let phishHost;
          try {
            if (phishUrl.startsWith('http://') || phishUrl.startsWith('https://')) {
              const urlParts = phishUrl.split('/');
              phishHost = urlParts.length > 2 ? urlParts[2] : '';
            } else {
              const urlParts = phishUrl.split('/');
              phishHost = urlParts[0];
            }
            
            // Remove port
            if (phishHost.includes(':')) {
              phishHost = phishHost.split(':')[0];
            }
            
            phishHost = phishHost.toLowerCase();
          } catch {
            continue;
          }
          
          if (!phishHost) continue;
          
          // Match logic: exact match or substring match (both directions)
          const hostMatch = phishHost === host || phishHost.includes(host) || host.includes(phishHost);
          
          // For URLs, also try exact URL matching
          let urlMatch = false;
          if (type === 'url') {
            const normalizedSearch = searchUrl.toLowerCase().replace(/^https?:\/\//, '');
            const normalizedPhish = phishUrl.replace(/^https?:\/\//, '');
            urlMatch = normalizedPhish === normalizedSearch || 
                      normalizedPhish.includes(normalizedSearch) ||
                      normalizedSearch.includes(normalizedPhish);
          }
          
          if (hostMatch || urlMatch) {
            return {
              status: 'success',
              data: {
                inDatabase: true,
                isPhishing: true, // All entries in online-valid.csv are verified
                phishId: phishId,
                matchedUrl: phishUrl,
                url: `https://www.phishtank.com/phish_detail.php?phish_id=${phishId}`
              }
            };
          }
        }
        
        // Not found
        return {
          status: 'success',
          data: {
            inDatabase: false,
            isPhishing: false,
            url: 'https://www.phishtank.com/'
          }
        };
        
      } catch (error) {
        // Fallback to search link
        const encodedUrl = encodeURIComponent(type === 'domain' ? `http://${observable.replace(/\/$/, '')}` : observable);
        return {
          status: 'success',
          data: {
            inDatabase: null,
            isPhishing: null,
            message: `Error: ${error.message}`,
            url: `https://www.phishtank.com/search.php?verified=u&active=u&Search=Search&url=${encodedUrl}`
          }
        };
      }
    }
  },
  
  threatfox: {
    types: ['ip', 'domain', 'hash'],
    requiresKey: true,
    query: async (observable, type, apiKey) => {
      const response = await fetch('https://threatfox-api.abuse.ch/api/v1/', {
        method: 'POST',
        headers: { 
          'Content-Type': 'application/json',
          'Auth-Key': apiKey
        },
        body: JSON.stringify({ query: 'search_ioc', search_term: observable })
      });
      
      if (!response.ok) throw new Error(`HTTP ${response.status}`);
      
      const data = await response.json();
      
      return {
        status: 'success',
        data: {
          found: data.query_status === 'ok',
          count: data.data?.length || 0,
          malware: data.data?.[0]?.malware || 'N/A',
          confidence: data.data?.[0]?.confidence_level || 'N/A',
          url: 'https://threatfox.abuse.ch/'
        }
      };
    }
  },
  
  malwarebazaar: {
    types: ['hash'],
    requiresKey: true,
    query: async (observable, type, apiKey) => {
      const response = await fetch('https://mb-api.abuse.ch/api/v1/', {
        method: 'POST',
        headers: { 
          'Content-Type': 'application/x-www-form-urlencoded',
          'Auth-Key': apiKey
        },
        body: `query=get_info&hash=${observable}`
      });
      
      if (!response.ok) throw new Error(`HTTP ${response.status}`);
      
      const data = await response.json();
      
      return {
        status: 'success',
        data: {
          found: data.query_status === 'ok',
          signature: data.data?.[0]?.signature || 'N/A',
          fileType: data.data?.[0]?.file_type || 'N/A',
          fileSize: data.data?.[0]?.file_size || 'N/A',
          url: 'https://bazaar.abuse.ch/'
        }
      };
    }
  }
};
