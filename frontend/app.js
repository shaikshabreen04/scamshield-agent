/**
 * Spam Buster — AI Powered Scam Detector
 * Client Application Logic & Full-Stack AI Integration (Dark Cyber UI)
 */

const API_BASE = "http://localhost:5000";

// Preset Quick Threat Samples
const SAMPLE_PRESETS = {
  'bank-kyc': {
    title: 'Bank KYC Urgent Freeze SMS',
    text: 'URGENT: Your State Bank account 4921 has been restricted due to incomplete PAN / KYC records. Tap http://bit.ly/sbi-verify-kyc within 24 hours to prevent permanent account suspension. Call 98234-XXXXX.',
    type: 'SMS / Text'
  },
  'lottery-prize': {
    title: 'WhatsApp 25 Lakh Lottery',
    text: 'Dear customer, congratulations! Your mobile number has won a cash prize of Rs 25,00,000 from KBC WhatsApp Lucky Draw. To claim your prize money, send your bank account details and pay Rs 1,500 government processing fee to WhatsApp number +91-9876543210.',
    type: 'WhatsApp'
  },
  'fake-job': {
    title: 'Telegram Part-Time Job Offer',
    text: 'Earn 3000 to 5000 INR daily working 30 minutes from home! Simple online task: like YouTube videos and rate hotel listings on Google Maps. No experience required. Daily instant payouts. Contact HR Manager on Telegram: @JobOfferOfficial2026.',
    type: 'Telegram'
  },
  'delivery-reschedule': {
    title: 'DHL / Postal Package Address Failure',
    text: 'DHL Express: We were unable to deliver parcel #DH9812403 due to an incomplete street address. Please update your delivery address and pay $1.49 redelivery fee at http://dhl-express-redelivery-center.online/update within 12 hours.',
    type: 'Email / SMS'
  },
  'legit-otp': {
    title: 'Standard Login Code',
    text: '384912 is your verification code for secure login. Valid for 10 minutes. Advisory: Never share this code with anyone, including bank or customer support staff.',
    type: 'SMS / Text'
  }
};

let currentResult = null;
let currentScanHistory = [];
let isAnalyzing = false;
let activeFilter = 'all';

// ==========================================================================
// Initialization
// ==========================================================================
document.addEventListener('DOMContentLoaded', () => {
  initNavigation();
  initInputHandlers();
  initPresetChips();
  initAnalysisEngine();
  initHistoryControls();
  initDetailModal();
  
  // Load state from backend
  checkBackendStatus();
  fetchDashboardStats();
  fetchHistoryFromBackend();

  // Periodic heartbeat
  setInterval(checkBackendStatus, 15000);
});

// ==========================================================================
// 1. Backend Connectivity & Statistics
// ==========================================================================
async function checkBackendStatus() {
  const pill = document.getElementById('aiStatusPill');
  try {
    const res = await fetch(`${API_BASE}/api/status`);
    if (res.ok) {
      const data = await res.json();
      if (pill) {
        pill.innerHTML = `
          <span class="engine-dot-pulse"></span>
          <span class="engine-text">AI Engine: Online (${data.model || 'OpenRouter / Free'})</span>
          <span class="engine-arrow">→</span>
        `;
        pill.title = "Connected to LangChain OpenRouter Agent and SQLite storage";
      }
    }
  } catch (e) {
    if (pill) {
      pill.innerHTML = `
        <span class="engine-dot-pulse" style="background:#f59e0b; box-shadow:0 0 8px #f59e0b;"></span>
        <span class="engine-text" style="color:#fbbf24;">AI Engine: Connecting...</span>
      `;
    }
  }
}

async function fetchDashboardStats() {
  try {
    const res = await fetch(`${API_BASE}/api/stats`);
    if (res.ok) {
      const data = await res.json();
      if (data && data.stats) {
        updateStatisticsCards(data.stats);
      }
    }
  } catch (e) {
    console.log('[Spam Buster] Using local stats calculation:', e.message);
  }
}

function updateStatisticsCards(stats) {
  const totalEl = document.getElementById('statTotalScans');
  const spamEl = document.getElementById('statSpamDetected');
  const safeEl = document.getElementById('statSafeMessages');
  const rateEl = document.getElementById('statSpamRate');
  const sideBadge = document.getElementById('sidebarHistoryBadge');
  const filterAllCount = document.getElementById('filterAllCount');

  // Home Page Stat Counters
  const homeTotal = document.getElementById('homeTotalCount');
  const homeThreat = document.getElementById('homeThreatCount');
  const homeSafe = document.getElementById('homeSafeCount');

  if (stats) {
    const total = stats.total || 0;
    const spam = (stats.high || 0) + (stats.medium || 0);
    const safe = stats.low || 0;
    const rate = total > 0 ? ((spam / total) * 100).toFixed(1) : 0;

    if (totalEl) totalEl.textContent = total;
    if (spamEl) spamEl.textContent = spam;
    if (safeEl) safeEl.textContent = safe;
    if (rateEl) rateEl.textContent = `${rate}%`;
    if (sideBadge) sideBadge.textContent = total;
    if (filterAllCount) filterAllCount.textContent = total;

    if (homeTotal) homeTotal.textContent = total;
    if (homeThreat) homeThreat.textContent = spam;
    if (homeSafe) homeSafe.textContent = safe;
  }
}

// ==========================================================================
// 2. Navigation Controller
// ==========================================================================
function initNavigation() {
  const navLinks = document.querySelectorAll('.sidebar-nav-menu .nav-btn, .sb-brand-logo, #viewAllRecentLink');
  const viewPanes = document.querySelectorAll('.view-pane');
  const sidebar = document.getElementById('sidebar');
  const mobileToggle = document.getElementById('mobileToggleBtn');
  const mobileClose = document.getElementById('mobileCloseBtn');

  function switchView(targetViewId) {
    if (!targetViewId) targetViewId = 'dashboard';
    
    viewPanes.forEach(pane => {
      pane.classList.remove('active');
      if (pane.id === `view-${targetViewId}`) {
        pane.classList.add('active');
      }
    });

    document.querySelectorAll('.sidebar-nav-menu .nav-btn').forEach(btn => {
      btn.classList.toggle('active', btn.getAttribute('data-view') === targetViewId);
    });

    // Update Top Greeting Bar per View
    const greetingHeader = document.getElementById('greetingHeader');
    const greetingSub = document.getElementById('greetingSub');
    if (targetViewId === 'dashboard') {
      if (greetingHeader) greetingHeader.innerHTML = 'Welcome to Spam Buster! 🛡️';
      if (greetingSub) greetingSub.textContent = 'Next-Gen AI Fraud Defense & Real-Time Scam Detection.';
    } else if (targetViewId === 'analyze') {
      if (greetingHeader) greetingHeader.innerHTML = 'Hello, there! 👋';
      if (greetingSub) greetingSub.textContent = 'Paste a message, email, or WhatsApp text to check if it\'s spam.';
    } else if (targetViewId === 'history') {
      if (greetingHeader) greetingHeader.innerHTML = 'Scan History 🗂️';
      if (greetingSub) greetingSub.textContent = 'All analyzed messages stored securely in local SQLite database.';
    } else if (targetViewId === 'safety') {
      if (greetingHeader) greetingHeader.innerHTML = 'Security Best Practices 💡';
      if (greetingSub) greetingSub.textContent = 'Stay protected against phishing, fake jobs, and OTP theft.';
    } else if (targetViewId === 'settings') {
      if (greetingHeader) greetingHeader.innerHTML = 'System Settings ⚙️';
      if (greetingSub) greetingSub.textContent = 'Configure OpenRouter AI engine and fraud thresholds.';
    }

    if (sidebar) sidebar.classList.remove('mobile-open');
    window.scrollTo({ top: 0, behavior: 'smooth' });

    if (targetViewId === 'history') {
      fetchHistoryFromBackend();
    } else if (targetViewId === 'analyze' || targetViewId === 'dashboard') {
      fetchDashboardStats();
    }
  }

  navLinks.forEach(link => {
    link.addEventListener('click', (e) => {
      const href = link.getAttribute('href');
      if (href && href.startsWith('#')) {
        e.preventDefault();
        const viewId = href.substring(1);
        switchView(viewId);
        history.pushState(null, '', href);
      }
    });
  });

  // Global handler for all intra-page view switches (hero buttons, vector test links)
  document.addEventListener('click', (e) => {
    const vectorLink = e.target.closest('.vector-test-link');
    if (vectorLink) {
      e.preventDefault();
      const sampleKey = vectorLink.getAttribute('data-sample');
      switchView('analyze');
      history.pushState(null, '', '#analyze');
      if (sampleKey && SAMPLE_PRESETS[sampleKey]) {
        const messageInput = document.getElementById('messageInput');
        if (messageInput) {
          messageInput.value = SAMPLE_PRESETS[sampleKey].text;
          messageInput.dispatchEvent(new Event('input'));
        }
      }
      return;
    }

    const homePrimaryBtn = e.target.closest('.btn-home-primary');
    if (homePrimaryBtn) {
      e.preventDefault();
      switchView('analyze');
      history.pushState(null, '', '#analyze');
      const messageInput = document.getElementById('messageInput');
      if (messageInput) messageInput.focus();
      return;
    }

    const homeSecondaryBtn = e.target.closest('.btn-home-secondary');
    if (homeSecondaryBtn) {
      e.preventDefault();
      switchView('safety');
      history.pushState(null, '', '#safety');
      return;
    }
  });

  window.addEventListener('popstate', () => {
    const hash = window.location.hash.substring(1) || 'dashboard';
    switchView(hash);
  });

  // Initialize view from URL hash on load
  const initialHash = window.location.hash.substring(1) || 'dashboard';
  switchView(initialHash);

  if (mobileToggle && sidebar) {
    mobileToggle.addEventListener('click', () => sidebar.classList.add('mobile-open'));
  }
  if (mobileClose && sidebar) {
    mobileClose.addEventListener('click', () => sidebar.classList.remove('mobile-open'));
  }
}

// ==========================================================================
// 3. Input Handlers & Character Counter
// ==========================================================================
function initInputHandlers() {
  const messageInput = document.getElementById('messageInput');
  const charCount = document.getElementById('charCount');
  const clearBtn = document.getElementById('clearInputBtn');

  if (!messageInput) return;

  function updateCharCount() {
    const len = messageInput.value.length;
    if (charCount) charCount.textContent = len;
  }

  messageInput.addEventListener('input', updateCharCount);

  if (clearBtn) {
    clearBtn.addEventListener('click', () => {
      messageInput.value = '';
      updateCharCount();
      messageInput.focus();
    });
  }
}

// ==========================================================================
// 4. Quick Examples Chips
// ==========================================================================
function initPresetChips() {
  const chipsGroup = document.getElementById('sampleChipsGroup');
  const messageInput = document.getElementById('messageInput');
  if (!chipsGroup || !messageInput) return;

  chipsGroup.addEventListener('click', (e) => {
    const chip = e.target.closest('.dark-chip-item');
    if (!chip) return;

    const sampleKey = chip.getAttribute('data-sample');
    const sample = SAMPLE_PRESETS[sampleKey];
    if (sample) {
      messageInput.value = sample.text;
      messageInput.dispatchEvent(new Event('input'));
      showToast(`Loaded: "${sample.title}"`, 'info');
    }
  });
}

// ==========================================================================
// 5. Analysis Engine (Trigger & Render Target UI)
// ==========================================================================
function initAnalysisEngine() {
  const analyzeBtn = document.getElementById('analyzeBtn');
  const btnSpinner = document.getElementById('btnSpinner');
  const btnIcon = document.getElementById('btnIcon');
  const btnText = document.getElementById('btnText');
  const messageInput = document.getElementById('messageInput');

  async function executeAnalysis() {
    if (isAnalyzing) return;

    const text = messageInput.value.trim();
    if (!text) {
      showToast('Please enter or paste a message to analyze', 'warning');
      messageInput.focus();
      return;
    }

    isAnalyzing = true;
    analyzeBtn.disabled = true;
    if (btnSpinner) btnSpinner.style.display = 'inline-block';
    if (btnIcon) btnIcon.style.display = 'none';
    if (btnText) btnText.textContent = 'Detecting Spam...';

    const startTime = performance.now();

    try {
      let analysisData = null;

      // 1. Call Backend REST API
      try {
        const controller = new AbortController();
        const timeoutId = setTimeout(() => controller.abort(), 60000); // 60s max

        const res = await fetch(`${API_BASE}/api/analyze`, {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ message: text }),
          signal: controller.signal
        });
        clearTimeout(timeoutId);

        if (res.ok) {
          const json = await res.json();
          if (json && json.data) {
            analysisData = json.data;
          }
        }
      } catch (netErr) {
        console.warn('[Spam Buster] Backend fetch error:', netErr.message);
      }

      // 2. Intelligent local fallback if server unreachable
      if (!analysisData) {
        analysisData = synthesizeLocalAnalysis(text);
      }

      analysisData.raw_message = text;
      currentResult = analysisData;

      const durationSec = ((performance.now() - startTime) / 1000).toFixed(1);
      
      // Render results in the right column
      renderAnalysisResultCard(analysisData);
      showToast(`Analysis complete in ${durationSec}s`, 'success');

      // Refresh recent scans table & stats from SQLite
      fetchHistoryFromBackend();
      fetchDashboardStats();

    } catch (err) {
      console.error('[Spam Buster] Fatal analysis error:', err);
      showToast('An error occurred during analysis.', 'warning');
    } finally {
      isAnalyzing = false;
      analyzeBtn.disabled = false;
      if (btnSpinner) btnSpinner.style.display = 'none';
      if (btnIcon) btnIcon.style.display = 'inline';
      if (btnText) btnText.textContent = 'Detect Spam →';
    }
  }

  analyzeBtn.addEventListener('click', executeAnalysis);

  const copyReportBtn = document.getElementById('copyReportBtn');
  const downloadJsonBtn = document.getElementById('downloadJsonBtn');

  if (copyReportBtn) {
    copyReportBtn.addEventListener('click', () => {
      if (!currentResult) {
        showToast('No active analysis to copy', 'warning');
        return;
      }
      const md = generateMarkdownReport(currentResult);
      navigator.clipboard.writeText(md).then(() => {
        showToast('Analysis report copied to clipboard!', 'success');
      });
    });
  }

  if (downloadJsonBtn) {
    downloadJsonBtn.addEventListener('click', () => {
      if (!currentResult) {
        showToast('No active analysis to export', 'warning');
        return;
      }
      const dataStr = "data:text/json;charset=utf-8," + encodeURIComponent(JSON.stringify(currentResult, null, 2));
      const downloadAnchor = document.createElement('a');
      downloadAnchor.setAttribute("href", dataStr);
      downloadAnchor.setAttribute("download", `scam_buster_analysis_${Date.now()}.json`);
      document.body.appendChild(downloadAnchor);
      downloadAnchor.click();
      downloadAnchor.remove();
      showToast('Exported analysis JSON', 'success');
    });
  }
}

// ==========================================================================
// 6. Render Target Result UI (Circular Gauge & Deep Forensic Breakdown)
// ==========================================================================
function renderAnalysisResultCard(data) {
  currentResult = data;
  const ringFill = document.getElementById('verdictRingFill');
  const gaugeVerdictStatus = document.getElementById('gaugeVerdictStatus');
  const gaugePercentVal = document.getElementById('gaugePercentVal');
  const gaugeConfSub = document.getElementById('gaugeConfSub');

  const verdictBadgePill = document.getElementById('verdictBadgePill');
  const verdictBadgeIcon = document.getElementById('verdictBadgeIcon');
  const verdictBadgeText = document.getElementById('verdictBadgeText');
  const verdictSummaryLine = document.getElementById('verdictSummaryLine');

  const lastScanTime = document.getElementById('lastScanTime');
  const riskScoreVal = document.getElementById('riskScoreVal');
  const engineMetaText = document.getElementById('engineMetaText');
  const messageTypeMetaText = document.getElementById('messageTypeMetaText');

  // Forensic Deep Analysis Elements
  const intentTitleText = document.getElementById('intentTitleText');
  const assessmentBox = document.getElementById('assessmentBox');
  const warningSignsCount = document.getElementById('warningSignsCount');
  const warningSignsList = document.getElementById('warningSignsList');
  const positiveIndicatorsGrid = document.getElementById('positiveIndicatorsGrid');
  const analysisChecksList = document.getElementById('analysisChecksList');

  const riskLevel = (data.risk_level || 'low').toLowerCase();
  const riskScore = parseInt(data.risk_score != null ? data.risk_score : (riskLevel === 'high' ? 92 : (riskLevel === 'medium' ? 55 : 8)), 10);
  const isSpam = riskLevel === 'high' || riskScore >= 70;
  const isMedium = !isSpam && (riskLevel === 'medium' || (riskScore >= 35 && riskScore < 70));

  // Update Last Scan Timestamp
  if (lastScanTime) {
    const now = new Date();
    const timeStr = now.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' });
    lastScanTime.textContent = `Last scan: Just now (${timeStr})`;
  }

  // Circular Gauge (Circumference = 2 * PI * 48 = 301.6)
  const circumference = 301.6;
  let confidencePercent = 96;

  if (isSpam) {
    // 🚨 HIGH RISK / SPAM (Crimson Red #ef4444)
    confidencePercent = Math.min(99, Math.max(88, riskScore));
    if (ringFill) {
      ringFill.className = 'ring-fill spam';
    }
    if (gaugeVerdictStatus) {
      gaugeVerdictStatus.textContent = 'SPAM';
      gaugeVerdictStatus.className = 'gauge-verdict-status spam';
    }
    if (gaugePercentVal) {
      gaugePercentVal.textContent = `${confidencePercent}%`;
      gaugePercentVal.className = 'gauge-percent-val spam';
    }
    if (verdictBadgePill && verdictBadgeText) {
      verdictBadgePill.className = 'verdict-badge-pill spam';
      if (verdictBadgeIcon) verdictBadgeIcon.textContent = '🚨';
      verdictBadgeText.textContent = 'High-Risk Scam';
    }
    if (verdictSummaryLine) {
      verdictSummaryLine.textContent = data.summary || 'This message contains deceptive links, urgent threats, or advance-fee coercion tactics.';
    }
    if (riskScoreVal) {
      riskScoreVal.className = 'meta-item-right score-val spam';
      riskScoreVal.textContent = `${riskScore} / 100`;
    }

  } else if (isMedium) {
    // ⚠️ MEDIUM RISK / SUSPICIOUS (Amber / Orange #f59e0b)
    confidencePercent = Math.min(85, Math.max(68, riskScore > 50 ? riskScore : 100 - riskScore));
    if (ringFill) {
      ringFill.className = 'ring-fill warning';
    }
    if (gaugeVerdictStatus) {
      gaugeVerdictStatus.textContent = 'SUSPICIOUS';
      gaugeVerdictStatus.className = 'gauge-verdict-status warning';
    }
    if (gaugePercentVal) {
      gaugePercentVal.textContent = `${confidencePercent}%`;
      gaugePercentVal.className = 'gauge-percent-val warning';
    }
    if (verdictBadgePill && verdictBadgeText) {
      verdictBadgePill.className = 'verdict-badge-pill medium';
      if (verdictBadgeIcon) verdictBadgeIcon.textContent = '⚠️';
      verdictBadgeText.textContent = 'Potential Risk';
    }
    if (verdictSummaryLine) {
      verdictSummaryLine.textContent = data.summary || 'This message contains unverified promotional links or unusual patterns. Exercise caution.';
    }
    if (riskScoreVal) {
      riskScoreVal.className = 'meta-item-right score-val warning';
      riskScoreVal.textContent = `${riskScore} / 100`;
    }

  } else {
    // 🛡️ LOW RISK / NOT SPAM (Emerald Green #10b981)
    confidencePercent = Math.min(99, Math.max(92, 100 - riskScore));
    if (ringFill) {
      ringFill.className = 'ring-fill';
    }
    if (gaugeVerdictStatus) {
      gaugeVerdictStatus.textContent = 'NOT SPAM';
      gaugeVerdictStatus.className = 'gauge-verdict-status';
    }
    if (gaugePercentVal) {
      gaugePercentVal.textContent = `${confidencePercent}%`;
      gaugePercentVal.className = 'gauge-percent-val';
    }
    if (verdictBadgePill && verdictBadgeText) {
      verdictBadgePill.className = 'verdict-badge-pill safe';
      if (verdictBadgeIcon) verdictBadgeIcon.textContent = '✔';
      verdictBadgeText.textContent = 'Safe & Legitimate';
    }
    if (verdictSummaryLine) {
      verdictSummaryLine.textContent = data.summary || 'This message appears to be genuine and does not show typical signs of spam or scam.';
    }
    if (riskScoreVal) {
      riskScoreVal.className = 'meta-item-right score-val safe';
      riskScoreVal.textContent = `${riskScore} / 100`;
    }
  }

  // Set animated stroke offset for gauge
  if (ringFill) {
    const offset = circumference - (circumference * (confidencePercent / 100));
    ringFill.style.strokeDashoffset = offset;
  }

  // Metadata: AI Analysis Engine & Message Type
  if (engineMetaText) {
    engineMetaText.textContent = data.source === 'openrouter_agent' ? 'Scam Buster Neural AI' : 'Scam Buster Security Engine';
  }

  if (messageTypeMetaText) {
    const raw = (data.raw_message || data.message || '').toLowerCase();
    if (raw.includes('whatsapp') || raw.includes('kbc')) messageTypeMetaText.textContent = 'WhatsApp Message';
    else if (raw.includes('telegram') || raw.includes('@')) messageTypeMetaText.textContent = 'Telegram Offer';
    else if (raw.includes('parcel') || raw.includes('delivery')) messageTypeMetaText.textContent = 'Courier / Delivery Notice';
    else if (raw.includes('recharge') || raw.includes('otp')) messageTypeMetaText.textContent = 'SMS / Carrier Text';
    else messageTypeMetaText.textContent = 'SMS / Text';
  }

  // 1. Detected Message Intent
  if (intentTitleText) {
    intentTitleText.textContent = data.message_intent || (
      isSpam 
        ? 'High-Risk Phishing / Fraud Attack' 
        : (isMedium ? 'Unverified Promotional / Outreach Text' : 'Legitimate Transaction Alert')
    );
  }

  // 2. AI Fraud Assessment Summary
  if (assessmentBox) {
    assessmentBox.textContent = data.summary || (
      isSpam
        ? 'AI analysis flagged severe deception vectors including coercive urgency, credential theft, or unauthorized payment requests.'
        : 'The content matches typical legitimate patterns with no indicators of fraud, phishing, or financial manipulation.'
    );
  }

  // 3. Detected Warning Signs & Quoted Evidence
  const flags = Array.isArray(data.identified_flags) ? data.identified_flags : [];
  if (warningSignsCount) {
    warningSignsCount.textContent = `${flags.length} Flags Found`;
    warningSignsCount.className = `flags-badge-chip ${flags.length > 0 ? 'has-flags' : ''}`;
  }

  if (warningSignsList) {
    if (flags.length > 0) {
      warningSignsList.innerHTML = flags.map(f => {
        const title = typeof f === 'object' ? (f.flag || f.title || 'Security Warning') : f;
        const quote = typeof f === 'object' && f.evidence ? f.evidence : '';
        const reason = typeof f === 'object' && f.reason ? f.reason : '';

        return `
          <div class="warning-evidence-card">
            <span class="flag-title">⚠️ ${escapeHTML(title)}</span>
            ${quote ? `<div class="flag-quote">"${escapeHTML(quote)}"</div>` : ''}
            ${reason ? `<span class="flag-reason">${escapeHTML(reason)}</span>` : ''}
          </div>
        `;
      }).join('');
    } else {
      warningSignsList.innerHTML = `
        <div class="clean-state-box">
          <div class="clean-header">
            <strong>No High-Risk Patterns Detected</strong>
            <span class="clean-pill">CLEAN</span>
          </div>
          <p>No deceptive hyperlinks, urgent freeze threats, or advance-fee requests were identified.</p>
        </div>
      `;
    }
  }

  // 4. Positive / Neutral Indicators
  if (positiveIndicatorsGrid) {
    let indicators = Array.isArray(data.positive_indicators) ? data.positive_indicators : [];
    if (indicators.length === 0 && !isSpam) {
      indicators = [
        'No URLs or link shorteners present',
        'No requests for money, payments, or financial credentials',
        'Standard notification format with no coercive threats'
      ];
    }

    if (indicators.length > 0) {
      positiveIndicatorsGrid.innerHTML = indicators.map(ind => `
        <div class="positive-chip-card">
          <span>✓</span>
          <span>${escapeHTML(ind)}</span>
        </div>
      `).join('');
    } else {
      positiveIndicatorsGrid.innerHTML = `
        <div class="positive-chip-card" style="background: rgba(239, 68, 68, 0.05); border-color: rgba(239, 68, 68, 0.2); color: #fca5a5;">
          <span>✗</span>
          <span>No protective or legitimate verification signals detected</span>
        </div>
      `;
    }
  }

  // 5. Message Technical Signals (4 Points)
  if (analysisChecksList) {
    const raw = (data.raw_message || data.message || '').toLowerCase();
    const hasLink = /https?:\/\/|bit\.ly|tinyurl|\.online|\.top/i.test(raw);
    const hasMoneyDemand = /(?:pay|send|deposit|transfer|claim\s+prize|release\s+parcel).*(?:fee|money|inr|usd|\$|₹|rs|tax)/i.test(raw) || /(?:redelivery|processing|registration)\s+fee/i.test(raw);
    const hasUrgency = /urgent|immediately|within\s+24\s+hours|within\s+12\s+hours|restricted|freeze|block/i.test(raw);
    const hasUnusualSender = (/telegram|@|unverified/i.test(raw) && isSpam) || flags.some(f => (typeof f === 'string' ? f : (f.flag || '')).toLowerCase().includes('sender'));

    analysisChecksList.innerHTML = `
      <div class="check-item-row ${hasLink ? 'fail' : 'pass'}">
        <span class="check-state-icon">${hasLink ? '✗' : '✔'}</span>
        <span class="check-state-text">${hasLink ? 'Suspicious or shortened links detected' : 'No suspicious links detected'}</span>
      </div>
      <div class="check-item-row ${hasMoneyDemand ? 'fail' : 'pass'}">
        <span class="check-state-icon">${hasMoneyDemand ? '✗' : '✔'}</span>
        <span class="check-state-text">${hasMoneyDemand ? 'Financial demand or advance-fee keywords flagged' : 'No financial risk keywords'}</span>
      </div>
      <div class="check-item-row ${hasUrgency ? 'fail' : 'pass'}">
        <span class="check-state-icon">${hasUrgency ? '✗' : '✔'}</span>
        <span class="check-state-text">${hasUrgency ? 'High-pressure urgency or threat language detected' : 'No urgent or threatening language'}</span>
      </div>
      <div class="check-item-row ${hasUnusualSender ? 'fail' : 'pass'}">
        <span class="check-state-icon">${hasUnusualSender ? '✗' : '✔'}</span>
        <span class="check-state-text">${hasUnusualSender ? 'Unusual anonymous sender handle identified' : 'No unusual sender pattern'}</span>
      </div>
    `;
  }
}

// ==========================================================================
// 7. Recent Scans Table (SQLite Loaded)
// ==========================================================================
async function fetchHistoryFromBackend() {
  try {
    const res = await fetch(`${API_BASE}/api/history`);
    if (res.ok) {
      const data = await res.json();
      if (data && data.history) {
        currentScanHistory = data.history;
        renderRecentScansTable(currentScanHistory.slice(0, 5));
        renderFullHistoryTable();
      }
    }
  } catch (e) {
    console.log('[Spam Buster] Using local recent scans fallback:', e.message);
  }
}

function renderRecentScansTable(recentList) {
  const tbody = document.getElementById('recentTableBody');
  if (!tbody) return;

  if (recentList.length === 0) {
    tbody.innerHTML = `
      <tr>
        <td colspan="5" style="text-align: center; padding: 20px; color: #64748b;">
          No recent scans recorded. Paste a message above to start.
        </td>
      </tr>
    `;
    return;
  }

  tbody.innerHTML = recentList.map(item => {
    const risk = (item.risk_level || 'low').toLowerCase();
    const score = item.risk_score || 0;
    const isSpam = risk === 'high' || score >= 70;
    const isMedium = risk === 'medium' || (score >= 40 && score < 70);

    let badgeClass = isSpam ? 'spam' : (isMedium ? 'medium' : 'not-spam');
    let badgeText = isSpam ? 'Spam' : (isMedium ? 'Potential' : 'Not Spam');
    let confText = `${Math.min(99, Math.max(88, score > 50 ? score : 100 - score))}%`;
    let timeFormatted = formatTimeToday(item.created_at);

    return `
      <tr style="cursor: pointer;" data-scan-id="${escapeHTML(item.id)}">
        <td>
          <div class="recent-preview-cell">
            <span class="recent-envelope-icon">
              <svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                <path d="M4 4h16c1.1 0 2 .9 2 2v12c0 1.1-.9 2-2 2H4c-1.1 0-2-.9-2-2V6c0-1.1.9-2 2-2z"/>
                <polyline points="22,6 12,13 2,6"/>
              </svg>
            </span>
            <span class="recent-snippet-text" title="${escapeHTML(item.message)}">
              ${escapeHTML(item.snippet || item.message)}
            </span>
          </div>
        </td>
        <td>
          <span class="pill-badge ${badgeClass}">${badgeText}</span>
        </td>
        <td style="font-family: var(--font-mono); font-size: 12px; color: #cbd5e1;">
          ${confText}
        </td>
        <td style="color: #64748b; font-size: 11.5px; white-space: nowrap;">
          ${timeFormatted}
        </td>
        <td class="recent-arrow-cell">›</td>
      </tr>
    `;
  }).join('');

  // Attach click to open detail modal
  tbody.querySelectorAll('tr').forEach(row => {
    row.addEventListener('click', () => {
      const scanId = row.getAttribute('data-scan-id');
      const scan = currentScanHistory.find(s => s.id === scanId);
      if (scan) openDetailModal(scan);
    });
  });
}

function renderFullHistoryTable() {
  const tbody = document.getElementById('historyTableBody');
  const searchInput = document.getElementById('historySearchInput');
  const query = searchInput ? searchInput.value.trim().toLowerCase() : '';

  if (!tbody) return;

  let filtered = currentScanHistory.filter(item => {
    if (activeFilter !== 'all') {
      if (item.risk_level.toLowerCase() !== activeFilter.toLowerCase()) return false;
    }
    if (query) {
      const textMatch = (item.message || '').toLowerCase().includes(query);
      const intentMatch = (item.message_intent || '').toLowerCase().includes(query);
      const idMatch = (item.id || '').toLowerCase().includes(query);
      if (!textMatch && !intentMatch && !idMatch) return false;
    }
    return true;
  });

  if (filtered.length === 0) {
    tbody.innerHTML = `
      <tr>
        <td colspan="6" style="text-align: center; padding: 28px; color: #64748b;">
          No matching scan records found.
        </td>
      </tr>
    `;
    return;
  }

  tbody.innerHTML = filtered.map(item => {
    const risk = (item.risk_level || 'low').toLowerCase();
    const score = item.risk_score || 0;
    const isSpam = risk === 'high' || score >= 70;
    const isMedium = risk === 'medium' || (score >= 40 && score < 70);
    const flags = (item.warning_signs || []).map(w => w.title || w).slice(0, 2);

    return `
      <tr>
        <td><span class="modal-id-badge">${escapeHTML(item.id || 'SB-SCAN')}</span></td>
        <td style="color: #64748b; font-size: 11.5px; white-space: nowrap;">${formatTimeToday(item.created_at)}</td>
        <td>
          <div style="font-weight: 700; color: #f1f5f9; font-size: 12.5px; margin-bottom: 2px;">
            ${escapeHTML(item.message_intent || 'Analyzed Text')}
          </div>
          <div style="max-width: 260px; white-space: nowrap; overflow: hidden; text-overflow: ellipsis; color: #94a3b8; font-size: 12px;">
            ${escapeHTML(item.snippet || item.message)}
          </div>
        </td>
        <td>
          <span class="pill-badge ${isSpam ? 'spam' : (isMedium ? 'medium' : 'not-spam')}">
            ${isSpam ? 'Spam' : (isMedium ? 'Potential' : 'Not Spam')} (${score}/100)
          </span>
        </td>
        <td>
          <span style="font-size: 11.5px; color: #cbd5e1;">${flags.join(', ') || 'Clean'}</span>
        </td>
        <td>
          <button type="button" class="btn-table-action" data-scan-id="${escapeHTML(item.id)}">
            View
          </button>
        </td>
      </tr>
    `;
  }).join('');

  tbody.querySelectorAll('.btn-table-action').forEach(btn => {
    btn.addEventListener('click', () => {
      const scanId = btn.getAttribute('data-scan-id');
      const scan = currentScanHistory.find(s => s.id === scanId);
      if (scan) openDetailModal(scan);
    });
  });
}

// ==========================================================================
// 8. History Controls (Search & Reset)
// ==========================================================================
function initHistoryControls() {
  const filterGroup = document.getElementById('historyFilterGroup');
  const searchInput = document.getElementById('historySearchInput');
  const clearBtn = document.getElementById('clearHistoryBtn');

  if (filterGroup) {
    filterGroup.addEventListener('click', (e) => {
      const chip = e.target.closest('.history-chip');
      if (!chip) return;

      filterGroup.querySelectorAll('.history-chip').forEach(c => c.classList.remove('active'));
      chip.classList.add('active');
      activeFilter = chip.getAttribute('data-filter') || 'all';
      renderFullHistoryTable();
    });
  }

  if (searchInput) {
    searchInput.addEventListener('input', () => {
      renderFullHistoryTable();
    });
  }

  if (clearBtn) {
    clearBtn.addEventListener('click', async () => {
      if (confirm('Reset scan history in SQLite to default records?')) {
        try {
          await fetch(`${API_BASE}/api/history/clear`, { method: "POST" });
          showToast('History reset to defaults', 'info');
          fetchHistoryFromBackend();
          fetchDashboardStats();
        } catch (e) {
          showToast('Failed to reset history', 'warning');
        }
      }
    });
  }
}

// ==========================================================================
// 9. Detail Modal Dialog
// ==========================================================================
function initDetailModal() {
  const modal = document.getElementById('scanDetailModal');
  const closeBtn = document.getElementById('modalCloseBtn');
  const doneBtn = document.getElementById('modalDoneBtn');
  const copyBtn = document.getElementById('modalCopyBtn');

  function closeModal() {
    if (modal) modal.style.display = 'none';
  }

  if (closeBtn) closeBtn.addEventListener('click', closeModal);
  if (doneBtn) doneBtn.addEventListener('click', closeModal);

  if (modal) {
    modal.addEventListener('click', (e) => {
      if (e.target === modal) closeModal();
    });
  }

  if (copyBtn) {
    copyBtn.addEventListener('click', () => {
      const activeScanId = copyBtn.getAttribute('data-active-id');
      const scan = currentScanHistory.find(s => s.id === activeScanId);
      if (scan) {
        const md = generateMarkdownReport(scan);
        navigator.clipboard.writeText(md).then(() => {
          showToast('Report copied to clipboard!', 'success');
        });
      }
    });
  }
}

function openDetailModal(scan) {
  const modal = document.getElementById('scanDetailModal');
  const idBadge = document.getElementById('modalScanId');
  const riskBadge = document.getElementById('modalRiskBadge');
  const timeSpan = document.getElementById('modalTimestamp');
  const modalBody = document.getElementById('modalBody');
  const copyBtn = document.getElementById('modalCopyBtn');

  if (!modal) return;

  const risk = (scan.risk_level || 'low').toLowerCase();
  const isSpam = risk === 'high';
  if (idBadge) idBadge.textContent = scan.id;
  if (riskBadge) {
    riskBadge.className = `modal-status-badge ${isSpam ? 'spam' : 'safe'}`;
    riskBadge.textContent = isSpam ? `SPAM DETECTED (${scan.risk_score}/100)` : `SAFE & LEGITIMATE (${scan.risk_score}/100)`;
  }
  if (timeSpan) timeSpan.textContent = formatTimeToday(scan.created_at);
  if (copyBtn) copyBtn.setAttribute('data-active-id', scan.id);

  if (modalBody) {
    modalBody.innerHTML = `
      <div style="background: #131c31; border: 1px solid #1e293b; border-radius: 8px; padding: 12px 14px;">
        <span style="font-size: 10px; font-weight: 800; color: #a855f7; letter-spacing: 0.5px;">MESSAGE INTENT</span>
        <div style="font-size: 14px; font-weight: 700; color: #ffffff; margin-top: 2px;">
          ${escapeHTML(scan.message_intent || 'General Evaluation')}
        </div>
      </div>

      <div>
        <h4 style="font-size: 12.5px; font-weight: 700; color: #cbd5e1; margin-bottom: 6px;">AI Assessment</h4>
        <div style="font-size: 12.5px; color: #94a3b8; line-height: 1.5; background: #0b1120; padding: 12px; border-radius: 8px; border: 1px solid #1e293b;">
          ${escapeHTML(scan.summary || '')}
        </div>
      </div>

      <div>
        <h4 style="font-size: 12.5px; font-weight: 700; color: #cbd5e1; margin-bottom: 6px;">Original Message</h4>
        <div style="background: #0b1120; border: 1px solid #1e293b; padding: 10px; border-radius: 6px; font-size: 11.5px; color: #64748b; font-family: var(--font-mono); white-space: pre-wrap; max-height: 120px; overflow-y: auto;">
          ${escapeHTML(scan.message)}
        </div>
      </div>
    `;
  }

  modal.style.display = 'flex';
}

// ==========================================================================
// 10. Intelligent Heuristic Synthesizer (Fallback)
// ==========================================================================
function synthesizeLocalAnalysis(text) {
  const lower = text.toLowerCase();
  
  // 1. Transaction receipts or recharge notices
  const isReceipt = /recharge.*(?:successful|active)|(?:was\s+successful|payment\s+received|transaction\s+successful|debited\s+by|credited\s+with|plan\s+benefits|recharge\s+of)/i.test(lower);
  const hasLink = /https?:\/\/|bit\.ly|tinyurl|\.online|\.top|t\.me/i.test(lower);
  const hasUrgency = /urgent|immediately|within\s+24\s+hours|within\s+12\s+hours|restricted|freeze|block|account\s+suspended/i.test(lower);
  const hasTelegram = /@[a-z0-9_]{3,}|telegram/i.test(lower);
  const hasThreat = /police|arrest|lawsuit|penalty|fine|suffer/i.test(lower);

  if (isReceipt && !hasLink && !hasUrgency && !hasTelegram && !hasThreat) {
    return {
      source: 'deterministic_engine',
      risk_level: 'low',
      risk_score: 8,
      confidence: 'high',
      message_intent: 'Legitimate Transaction / Mobile Recharge Alert',
      summary: 'This message is a standard transactional confirmation receipt for a mobile recharge. It contains no hyperlinks, no demands for money, and no requests for banking passwords or OTPs.',
      warning_signs: [],
      positive_indicators: [
        'Confirms a completed service transaction with no external links',
        'Does not ask for sensitive credentials, PINs, or OTPs'
      ],
      limitations: ['If you did not initiate this recharge, verify your mobile carrier account.'],
      recommended_actions: ['No action required if you initiated this recharge. Enjoy your plan benefits.']
    };
  }

  const hasFeeDemand = /(?:pay|send|deposit|transfer|claim\s+prize|release\s+parcel).*(?:fee|money|inr|usd|\$|₹|rs|tax)/i.test(lower) ||
                       /(?:redelivery|processing|registration|verification)\s+fee/i.test(lower);

  const isHigh = (hasUrgency && hasLink) || (hasFeeDemand && hasTelegram) || (hasFeeDemand && hasUrgency) || (hasLink && hasUrgency);
  const risk = isHigh ? 'high' : (hasFeeDemand || hasLink || hasUrgency ? 'medium' : 'low');
  const score = isHigh ? 92 : (risk === 'medium' ? 55 : 10);

  return {
    source: 'deterministic_engine',
    risk_level: risk,
    risk_score: score,
    confidence: 'medium',
    message_intent: isHigh ? 'Advance-Fee or Urgent Phishing Solicitations' : 'General Communication',
    summary: isHigh
      ? 'This message demonstrates high-risk fraud characteristics, including manufactured urgency and financial or link redirection tactics.'
      : 'Standard communication cues detected. Always exercise caution before disclosing sensitive credentials.',
    warning_signs: [],
    positive_indicators: ['No unverified executable attachment detected'],
    limitations: ['Evaluated via local heuristics because server was temporarily busy.'],
    recommended_actions: ['Verify the request via independent corporate or personal channels.']
  };
}

// ==========================================================================
// 11. Utilities & Date Formatting
// ==========================================================================
function formatTimeToday(isoString) {
  if (!isoString) return 'Today, 12:00';
  try {
    const date = new Date(isoString);
    const hours = String(date.getHours()).padStart(2, '0');
    const mins = String(date.getMinutes()).padStart(2, '0');
    const diffHours = (Date.now() - date.getTime()) / (1000 * 3600);
    if (diffHours < 24) return `Today, ${hours}:${mins}`;
    return `Yesterday, ${hours}:${mins}`;
  } catch (e) {
    return 'Recently';
  }
}

function generateMarkdownReport(data) {
  const risk = (data.risk_level || 'low').toUpperCase();
  const score = data.risk_score || 0;
  return `# 🛡️ Spam Buster AI Report\n\n**Risk:** ${risk} (${score}/100)\n**Intent:** ${data.message_intent}\n\n## Summary\n${data.summary}\n\n## Message Payload\n\`\`\`text\n${data.raw_message || data.message || ''}\n\`\`\`\n`;
}

function escapeHTML(str) {
  if (typeof str !== 'string') return '';
  return str
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#039;');
}

function showToast(message, type = 'info') {
  const container = document.getElementById('toastContainer');
  if (!container) return;

  const toast = document.createElement('div');
  toast.className = `toast ${type}`;
  toast.textContent = message;
  container.appendChild(toast);

  setTimeout(() => {
    toast.style.opacity = '0';
    toast.style.transform = 'translateY(10px)';
    toast.style.transition = 'all 0.3s ease';
    setTimeout(() => toast.remove(), 300);
  }, 3200);
}
