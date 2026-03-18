// Background service worker for InvestigateR Chrome Extension

// Create context menu on installation
chrome.runtime.onInstalled.addListener(() => {
  chrome.contextMenus.create({
    id: 'investigate-selection',
    title: 'Investigate with InvestigateR',
    contexts: ['selection']
  });
});

// Handle context menu clicks
chrome.contextMenus.onClicked.addListener((info, tab) => {
  if (info.menuItemId === 'investigate-selection' && info.selectionText) {
    // Store selected text for popup to retrieve
    chrome.storage.local.set({ 
      pendingInvestigation: info.selectionText.trim() 
    });
    
    // Open extension popup
    chrome.action.openPopup();
  }
});

// Handle messages from popup
chrome.runtime.onMessage.addListener((request, sender, sendResponse) => {
  if (request.action === 'investigate') {
    // Process investigation in background for better performance
    performInvestigation(request.observables, request.tools, request.apiKeys)
      .then(results => sendResponse({ success: true, results }))
      .catch(error => sendResponse({ success: false, error: error.message }));
    
    return true; // Keep message channel open for async response
  }
});

// Main investigation function - queries all tools in parallel
async function performInvestigation(observables, selectedTools, apiKeys) {
  const results = {};
  
  // Process all observables in parallel
  const promises = observables.map(async (observable) => {
    const observableResults = await queryAllTools(observable, selectedTools, apiKeys);
    results[observable] = observableResults;
  });
  
  await Promise.all(promises);
  return results;
}

// Query all selected tools for a single observable
async function queryAllTools(observable, tools, apiKeys) {
  const type = detectObservableType(observable);
  const results = [];
  
  // Query all tools in parallel for maximum speed
  const promises = tools.map(async (toolName) => {
    try {
      const result = await queryTool(toolName, observable, type, apiKeys);
      return { tool: toolName, ...result };
    } catch (error) {
      return {
        tool: toolName,
        status: 'error',
        error: error.message
      };
    }
  });
  
  const toolResults = await Promise.all(promises);
  return { type, results: toolResults };
}

// Detect observable type
function detectObservableType(observable) {
  // IPv4
  if (/^(\d{1,3}\.){3}\d{1,3}$/.test(observable)) {
    return 'ip';
  }
  // IPv6
  if (/^([0-9a-fA-F]{0,4}:){2,7}[0-9a-fA-F]{0,4}$/.test(observable)) {
    return 'ip';
  }
  // URL
  if (/^https?:\/\//i.test(observable)) {
    return 'url';
  }
  // MD5, SHA1, SHA256 hash
  if (/^[a-fA-F0-9]{32}$|^[a-fA-F0-9]{40}$|^[a-fA-F0-9]{64}$/.test(observable)) {
    return 'hash';
  }
  // Domain
  if (/^[a-zA-Z0-9][a-zA-Z0-9-]{0,61}[a-zA-Z0-9]?\.[a-zA-Z]{2,}$/.test(observable)) {
    return 'domain';
  }
  
  return 'unknown';
}

// Query individual tool
async function queryTool(toolName, observable, type, apiKeys) {
  const tool = TOOLS[toolName];
  
  if (!tool) {
    throw new Error('Unknown tool');
  }
  
  // Check if tool supports this observable type
  if (!tool.types.includes(type)) {
    return {
      status: 'skipped',
      message: `${toolName} does not support ${type} lookups`
    };
  }
  
  // Check if API key is required and available
  if (tool.requiresKey && !apiKeys[toolName]) {
    return {
      status: 'skipped',
      message: 'API key required. Configure in settings.'
    };
  }
  
  return await tool.query(observable, type, apiKeys[toolName]);
}

// Tool definitions with query functions
const TOOLS = {
  virustotal: {
    types: ['ip', 'domain', 'url', 'hash'],
    requiresKey: true,
    query: async (observable, type, apiKey) => {
      const endpoint = type === 'hash' 
        ? `https://www.virustotal.com/api/v3/files/${observable}`
        : type === 'url'
        ? `https://www.virustotal.com/api/v3/urls/${btoa(observable).replace(/=/g, '')}`
        : `https://www.virustotal.com/api/v3/${type === 'ip' ? 'ip_addresses' : 'domains'}/${observable}`;
      
      const response = await fetch(endpoint, {
        headers: { 'x-apikey': apiKey }
      });
      
      if (!response.ok) {
        throw new Error(`HTTP ${response.status}`);
      }
      
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
      
      if (!response.ok) {
        throw new Error(`HTTP ${response.status}`);
      }
      
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
      
      if (!response.ok) {
        throw new Error(`HTTP ${response.status}`);
      }
      
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
    requiresKey: true,
    query: async (observable, type, apiKey) => {
      // Submit for scanning
      const submitResponse = await fetch('https://urlscan.io/api/v1/scan/', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'API-Key': apiKey
        },
        body: JSON.stringify({ url: observable, visibility: 'unlisted' })
      });
      
      if (!submitResponse.ok) {
        throw new Error(`HTTP ${submitResponse.status}`);
      }
      
      const submitData = await submitResponse.json();
      
      return {
        status: 'success',
        data: {
          message: 'Scan submitted',
          url: submitData.result,
          uuid: submitData.uuid
        }
      };
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
            data: { message: 'No information available' }
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
    types: ['url'],
    requiresKey: false,
    query: async (observable, type, apiKey) => {
      const encodedUrl = encodeURIComponent(observable);
      const response = await fetch(`https://checkurl.phishtank.com/checkurl/`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
        body: `url=${encodedUrl}&format=json`
      });
      
      if (!response.ok) {
        throw new Error(`HTTP ${response.status}`);
      }
      
      const data = await response.json();
      
      return {
        status: 'success',
        data: {
          inDatabase: data.results.in_database,
          isPhishing: data.results.verified,
          url: data.results.phish_detail_url || 'https://www.phishtank.com/'
        }
      };
    }
  },
  
  threatfox: {
    types: ['ip', 'domain', 'hash'],
    requiresKey: false,
    query: async (observable, type, apiKey) => {
      const response = await fetch('https://threatfox-api.abuse.ch/api/v1/', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ query: 'search_ioc', search_term: observable })
      });
      
      if (!response.ok) {
        throw new Error(`HTTP ${response.status}`);
      }
      
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
    requiresKey: false,
    query: async (observable, type, apiKey) => {
      const response = await fetch('https://mb-api.abuse.ch/api/v1/', {
        method: 'POST',
        headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
        body: `query=get_info&hash=${observable}`
      });
      
      if (!response.ok) {
        throw new Error(`HTTP ${response.status}`);
      }
      
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
