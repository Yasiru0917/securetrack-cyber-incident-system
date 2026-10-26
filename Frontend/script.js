const API = 'http://localhost:5000';

let allIncidents = [];
let selectedIncident = null;
let editingIncident = false;
let editingIncidentStatus = false;

function getToken() {
  return localStorage.getItem('securetrack_token');
}

function setToken(token) {
  if (token) {
    localStorage.setItem('securetrack_token', token);
  } else {
    localStorage.removeItem('securetrack_token');
  }
}

function getUser() {
  try {
    return JSON.parse(localStorage.getItem('securetrack_user') || 'null');
  } catch (error) {
    return null;
  }
}

function setUser(user) {
  if (user) {
    localStorage.setItem('securetrack_user', JSON.stringify(user));
  } else {
    localStorage.removeItem('securetrack_user');
  }
}

function clearAuth() {
  setToken(null);
  setUser(null);
}

function redirectToLogin() {
  if (window.location.pathname.endsWith('login.html') || window.location.pathname.endsWith('register.html')) {
    return;
  }
  window.location.href = 'login.html';
}

function redirectToDashboard() {
  if (window.location.pathname.endsWith('dashboard.html')) {
    return;
  }
  window.location.href = 'dashboard.html';
}

function parseStatusColor(status) {
  const normalized = (status || '').toLowerCase();
  if (normalized === 'resolved') return 'success';
  if (normalized === 'investigating') return 'warning';
  if (normalized === 'pending') return 'neutral';
  return 'neutral';
}

function parseSeverityColor(severity) {
  const normalized = (severity || '').toLowerCase();
  if (normalized === 'critical') return 'critical';
  if (normalized === 'high') return 'high';
  if (normalized === 'medium') return 'medium';
  return 'low';
}

function escapeHtml(value) {
  return String(value ?? '').replace(/[&<>"']/g, (character) => ({
    '&': '&amp;',
    '<': '&lt;',
    '>': '&gt;',
    '"': '&quot;',
    "'": '&#39;',
  })[character]);
}

function showToast(message, type = 'info') {
  const container = document.getElementById('toastContainer');
  if (!container) {
    window.alert(message);
    return;
  }

  const toast = document.createElement('div');
  toast.className = `toast ${type}`;
  toast.textContent = message;
  container.appendChild(toast);

  setTimeout(() => {
    toast.classList.add('show');
  }, 10);

  setTimeout(() => {
    toast.classList.remove('show');
    setTimeout(() => toast.remove(), 300);
  }, 3500);
}

async function apiRequest(endpoint, options = {}) {
  const token = getToken();
  const headers = { ...(options.headers || {}) };

  if (!(options.headers && options.headers['Content-Type']) && options.body) {
    headers['Content-Type'] = 'application/json';
  }

  if (token) {
    headers.Authorization = `Bearer ${token}`;
  }

  const controller = new AbortController();
  const timeoutId = setTimeout(() => controller.abort(), 15000);
  let response;
  try {
    response = await fetch(`${API}${endpoint}`, {
      ...options,
      headers,
      signal: controller.signal,
    });
  } catch (error) {
    if (error.name === 'AbortError') {
      throw new Error('Request timed out. Please try again.');
    }
    throw new Error('Unable to connect to SecureTrack. Check your connection and try again.');
  } finally {
    clearTimeout(timeoutId);
  }

  let data = {};
  try {
    data = await response.json();
  } catch (error) {
    data = {};
  }

  if (response.status === 401) {
    clearAuth();
    if (!window.location.pathname.endsWith('login.html') && !window.location.pathname.endsWith('register.html')) {
      redirectToLogin();
    }
    throw new Error(data.message || 'Authentication required');
  }

  if (!response.ok) {
    throw new Error(data.message || 'Request failed');
  }

  return data;
}

async function loginUser(event) {
  if (event && typeof event.preventDefault === 'function') {
    event.preventDefault();
  }

  const emailInput = document.getElementById('email');
  const passwordInput = document.getElementById('password');
  const submitButton = document.querySelector('[data-auth-submit="login"]') || document.querySelector('#loginButton');

  const email = (emailInput ? emailInput.value : '').trim();
  const password = passwordInput ? passwordInput.value : '';

  if (!email || !password) {
    showToast('Email and password are required', 'error');
    return;
  }

  if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) {
    showToast('Please enter a valid email address', 'error');
    return;
  }

  if (submitButton) {
    submitButton.disabled = true;
    submitButton.dataset.originalText = submitButton.textContent;
    submitButton.textContent = 'Signing in...';
  }

  try {
    const data = await apiRequest('/login', {
      method: 'POST',
      body: JSON.stringify({ email, password }),
    });

    setToken(data.token);
    setUser(data.user);
    redirectToDashboard();
  } catch (error) {
    showToast(error.message || 'Unable to log in', 'error');
  } finally {
    if (submitButton) {
      submitButton.disabled = false;
      submitButton.textContent = submitButton.dataset.originalText || 'Sign in';
    }
  }
}

async function registerUser(event) {
  if (event && typeof event.preventDefault === 'function') {
    event.preventDefault();
  }

  const nameInput = document.getElementById('name');
  const emailInput = document.getElementById('email');
  const passwordInput = document.getElementById('password');
  const confirmInput = document.getElementById('confirmPassword');
  const submitButton = document.querySelector('[data-auth-submit="register"]') || document.querySelector('#registerButton');

  const name = (nameInput ? nameInput.value : '').trim();
  const email = (emailInput ? emailInput.value : '').trim();
  const password = passwordInput ? passwordInput.value : '';
  const confirmPassword = confirmInput ? confirmInput.value : '';

  if (!name || !email || !password) {
    showToast('All fields are required', 'error');
    return;
  }

  if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) {
    showToast('Please enter a valid email address', 'error');
    return;
  }

  if (password.length < 8) {
    showToast('Password must be at least 8 characters long', 'error');
    return;
  }

  if (password !== confirmPassword) {
    showToast('Passwords do not match', 'error');
    return;
  }

  if (submitButton) {
    submitButton.disabled = true;
    submitButton.dataset.originalText = submitButton.textContent;
    submitButton.textContent = 'Creating account...';
  }

  try {
    const data = await apiRequest('/register', {
      method: 'POST',
      body: JSON.stringify({ name, email, password, confirmPassword }),
    });

    setTimeout(() => {
      window.location.href = 'login.html';
    }, 500);
  } catch (error) {
    showToast(error.message || 'Unable to create account', 'error');
  } finally {
    if (submitButton) {
      submitButton.disabled = false;
      submitButton.textContent = submitButton.dataset.originalText || 'Create account';
    }
  }
}

function setupPasswordToggle(triggerSelector) {
  const trigger = document.querySelector(triggerSelector);
  if (!trigger) return;

  trigger.addEventListener('click', () => {
    const target = document.getElementById(trigger.dataset.targetId);
    if (!target) return;
    const isPassword = target.type === 'password';
    target.type = isPassword ? 'text' : 'password';
    trigger.textContent = isPassword ? 'Hide' : 'Show';
  });
}

function initializeAuthPage() {
  const currentPath = window.location.pathname.split('/').pop();
  const user = getUser();
  const token = getToken();

  if (token && user && (currentPath === 'login.html' || currentPath === 'register.html')) {
    redirectToDashboard();
    return;
  }

  if (currentPath === 'login.html') {
    document.body.classList.add('auth-page');
    const form = document.getElementById('loginForm');
    if (form) {
      form.addEventListener('submit', loginUser);
    }
    const loginButton = document.querySelector('#loginButton');
    if (loginButton) {
      loginButton.addEventListener('click', loginUser);
    }
    setupPasswordToggle('[data-toggle-password="login"]');
  }

  if (currentPath === 'register.html') {
    document.body.classList.add('auth-page');
    const form = document.getElementById('registerForm');
    if (form) {
      form.addEventListener('submit', registerUser);
    }
    const registerButton = document.querySelector('#registerButton');
    if (registerButton) {
      registerButton.addEventListener('click', registerUser);
    }
    setupPasswordToggle('[data-toggle-password="register"]');
    setupPasswordToggle('[data-toggle-password="confirm"]');
  }
}

function loadUserUI() {
  const user = getUser();
  if (!user) {
    redirectToLogin();
    return;
  }

  const profileName = user.name || 'User';
  const initial = profileName.charAt(0).toUpperCase();

  const welcomeName = document.getElementById('welcomeName');
  if (welcomeName) {
    welcomeName.textContent = profileName.split(' ')[0];
  }

  const topUserName = document.getElementById('topUserName');
  if (topUserName) {
    topUserName.textContent = profileName;
  }

  const topUserRole = document.getElementById('topUserRole');
  if (topUserRole) {
    topUserRole.textContent = user.role === 'admin' ? 'Security Administrator' : 'Security User';
  }

  const userAvatar = document.getElementById('userAvatar');
  if (userAvatar) userAvatar.textContent = initial;

  const dropdownAvatar = document.getElementById('dropdownAvatar');
  if (dropdownAvatar) dropdownAvatar.textContent = initial;

  const dropdownName = document.getElementById('dropdownName');
  if (dropdownName) dropdownName.textContent = profileName;

  const dropdownEmail = document.getElementById('dropdownEmail');
  if (dropdownEmail) dropdownEmail.textContent = user.email || '';

  document.body.classList.toggle('is-admin', user.role === 'admin');
}

function setupUserMenu() {
  const userMenuButton = document.getElementById('userMenuButton');
  const userDropdown = document.getElementById('userDropdown');

  if (!userMenuButton || !userDropdown) return;

  userMenuButton.addEventListener('click', () => {
    userDropdown.classList.toggle('show');
  });

  document.addEventListener('click', (event) => {
    if (!userMenuButton.contains(event.target) && !userDropdown.contains(event.target)) {
      userDropdown.classList.remove('show');
    }
  });
}

function setupMobileMenu() {
  const mobileMenu = document.getElementById('mobileMenu');
  const sidebar = document.getElementById('sidebar');
  if (!mobileMenu || !sidebar) return;

  mobileMenu.addEventListener('click', () => {
    sidebar.classList.toggle('mobile-open');
  });
}

async function loadIncidents() {
  const tableBody = document.getElementById('incidentTableBody');
  if (tableBody) {
    tableBody.innerHTML = `
      <tr>
        <td colspan="6" class="loading-cell">
          <div class="loading-spinner"></div>
          Loading incidents...
        </td>
      </tr>
    `;
  }

  try {
    const incidents = await apiRequest('/incidents');
    allIncidents = Array.isArray(incidents) ? incidents : [];
    updateDashboardStats();
    updateDashboardAnalytics();
    applyFilters();
  } catch (error) {
    console.error(error);
    if (tableBody) {
      tableBody.innerHTML = `
        <tr>
          <td colspan="6" class="loading-cell">
            We couldn't load incidents. Please refresh the page and try again.
          </td>
        </tr>
      `;
    }
    const resultsCount = document.getElementById('resultsCount');
    if (resultsCount) resultsCount.textContent = 'Incidents unavailable';
    for (const id of ['totalIncidents', 'pendingIncidents', 'investigatingIncidents', 'resolvedIncidents']) {
      const element = document.getElementById(id);
      if (element) element.textContent = '—';
    }
    for (const id of ['dashboardStatusBars', 'dashboardAnalyticsSeverity']) {
      const element = document.getElementById(id);
      if (element) element.textContent = 'Unable to load analytics.';
    }
    const analyticsTypes = document.getElementById('dashboardAnalyticsTypes');
    if (analyticsTypes) {
      analyticsTypes.innerHTML = '<tr><td colspan="2" class="empty-table-cell">Unable to load analytics.</td></tr>';
    }
    showToast(error.message || 'Could not load incidents', 'error');
  }
}

async function loadUsers() {
  const tableBody = document.getElementById('usersTableBody');
  if (!tableBody) return;

  const totalCount = document.getElementById('usersTotalCount');
  const adminCount = document.getElementById('usersAdminCount');
  const memberCount = document.getElementById('usersMemberCount');
  const directoryCount = document.getElementById('usersDirectoryCount');

  tableBody.innerHTML = `
    <tr>
      <td colspan="3" class="loading-cell">
        <div class="loading-spinner"></div>
        Loading registered users...
      </td>
    </tr>
  `;
  if (directoryCount) directoryCount.textContent = 'Loading accounts…';

  try {
    const users = await apiRequest('/users');
    const userList = Array.isArray(users) ? users : [];
    const admins = userList.filter((user) => user.role === 'admin').length;
    const members = userList.length - admins;

    if (totalCount) totalCount.textContent = String(userList.length);
    if (adminCount) adminCount.textContent = String(admins);
    if (memberCount) memberCount.textContent = String(members);
    if (directoryCount) {
      directoryCount.textContent = `${userList.length} ${userList.length === 1 ? 'account' : 'accounts'}`;
    }

    if (userList.length === 0) {
      tableBody.innerHTML = '<tr><td colspan="3" class="empty-table-cell">No user accounts have been registered yet.</td></tr>';
      return;
    }

    tableBody.innerHTML = userList.map((user) => {
      const name = user.name || 'Unknown user';
      const initials = name.trim().split(/\s+/).slice(0, 2).map((part) => part.charAt(0)).join('').toUpperCase() || 'U';
      const isAdmin = user.role === 'admin';
      return `
      <tr>
        <td>
          <div class="user-account-cell">
            <span class="user-row-avatar ${isAdmin ? 'admin-avatar' : ''}" aria-hidden="true">${escapeHtml(initials)}</span>
            <span class="user-account-details">
              <strong>${escapeHtml(name)}</strong>
              <span>${escapeHtml(user.email || 'No email provided')}</span>
            </span>
          </div>
        </td>
        <td><span class="user-role-pill ${isAdmin ? 'admin-role' : 'member-role'}"><span aria-hidden="true">${isAdmin ? '✦' : '●'}</span>${isAdmin ? 'Administrator' : 'Standard user'}</span></td>
        <td><span class="user-joined-date">${escapeHtml(user.createdAt ? new Date(user.createdAt).toLocaleDateString() : 'Date unavailable')}</span></td>
      </tr>
    `;
    }).join('');
  } catch (error) {
    tableBody.innerHTML = '<tr><td colspan="3" class="empty-table-cell">We couldn\'t load user accounts. Please try again.</td></tr>';
    if (directoryCount) directoryCount.textContent = 'Accounts unavailable';
    showToast(error.message || 'Could not load user accounts', 'error');
  }
}

function getFilteredIncidents() {
  const searchValue = (document.getElementById('searchIncident')?.value || '').trim().toLowerCase();
  const severityValue = document.getElementById('filterSeverity')?.value || '';
  const statusValue = document.getElementById('filterStatus')?.value || '';

  return allIncidents.filter((incident) => {
    const status = incident.status || 'Pending';
    const severity = incident.severity || 'Medium';
    const type = incident.type || 'Security Event';
    const incidentId = incident.incidentId || '';
    const description = incident.description || '';

    const matchesSearch = !searchValue || [status, severity, type, incidentId, description].join(' ').toLowerCase().includes(searchValue);
    const matchesSeverity = !severityValue || severity === severityValue;
    const matchesStatus = !statusValue || status === statusValue;

    return matchesSearch && matchesSeverity && matchesStatus;
  });
}

function applyFilters() {
  const filteredIncidents = getFilteredIncidents();
  const resultsCount = document.getElementById('resultsCount');
  if (resultsCount) {
    const count = filteredIncidents.length;
    resultsCount.textContent = `${count} ${count === 1 ? 'incident' : 'incidents'}`;
  }

  renderIncidentTable(filteredIncidents);
}

function renderIncidentTable(filteredIncidents = allIncidents) {
  const tableBody = document.getElementById('incidentTableBody');
  const tableContainer = tableBody?.closest('.table-container');
  const emptyState = document.getElementById('emptyState');

  if (!tableBody) return;

  if (!filteredIncidents.length) {
    if (tableContainer) tableContainer.hidden = true;
    const isEmpty = allIncidents.length === 0;
    const emptyStateTitle = document.getElementById('emptyStateTitle');
    const emptyStateMessage = document.getElementById('emptyStateMessage');
    const reportLink = document.getElementById('emptyStateReportLink');
    if (emptyStateTitle) emptyStateTitle.textContent = isEmpty ? 'No incidents yet' : 'No matching incidents';
    if (emptyStateMessage) {
      emptyStateMessage.textContent = isEmpty
        ? 'No security incidents have been reported. Submit a report to start tracking activity.'
        : 'Try a different search term or adjust your filters.';
    }
    if (reportLink) reportLink.hidden = !isEmpty;
    if (emptyState) emptyState.classList.remove('hidden');
    return;
  }

  if (tableContainer) tableContainer.hidden = false;
  if (emptyState) emptyState.classList.add('hidden');

  tableBody.innerHTML = filteredIncidents.map((incident) => {
    const isAdmin = getUser()?.role === 'admin';
    const status = incident.status || 'Pending';
    const severity = incident.severity || 'Medium';
    const type = incident.type || 'Security Event';
    const reportedDate = incident.date || incident.createdAt || new Date().toISOString();
    const reporter = incident.reportedBy && typeof incident.reportedBy === 'object' ? incident.reportedBy.name : 'Unknown';
    const incidentId = incident.incidentId || incident._id || 'N/A';
    const dateLabel = new Date(reportedDate).toLocaleDateString();

    return `
      <tr>
        <td>
          <div class="incident-title-block">
            <strong>${escapeHtml(incidentId)}</strong>
            <span>${escapeHtml(type)}</span>
            <small>Reported by ${escapeHtml(reporter)}</small>
          </div>
        </td>
        <td>${escapeHtml(type)}</td>
        <td>
          <span class="status-badge ${parseSeverityColor(severity)}">${escapeHtml(severity)}</span>
        </td>
        <td>
          ${isAdmin
            ? `<button class="status-badge status-badge-button ${parseStatusColor(status)}" type="button" data-edit-status="${escapeHtml(incident._id)}" aria-label="Change status, current status: ${escapeHtml(status)}" title="Click to change status">
                <span>${escapeHtml(status)}</span>
                <span class="status-change-indicator" aria-hidden="true">▾</span>
              </button>
              <select class="table-status-select" data-incident-status="${escapeHtml(incident._id)}" aria-label="Select incident status" hidden>
                <option value="Pending" ${status === 'Pending' ? 'selected' : ''}>Pending</option>
                <option value="Investigating" ${status === 'Investigating' ? 'selected' : ''}>Investigating</option>
                <option value="Resolved" ${status === 'Resolved' ? 'selected' : ''}>Resolved</option>
              </select>`
            : `<span class="status-badge ${parseStatusColor(status)}">${escapeHtml(status)}</span>`}
        </td>
        <td>${escapeHtml(dateLabel)}</td>
        <td>
          <button class="tiny-btn" type="button" data-view-incident="${escapeHtml(incident._id)}">View</button>
        </td>
      </tr>
    `;
  }).join('');

  tableBody.querySelectorAll('[data-view-incident]').forEach((button) => {
    button.addEventListener('click', () => openIncidentModal(button.dataset.viewIncident));
  });

  tableBody.querySelectorAll('[data-edit-status]').forEach((button) => {
    button.addEventListener('click', () => {
      const select = tableBody.querySelector(`[data-incident-status="${CSS.escape(button.dataset.editStatus)}"]`);
      if (!select) return;
      button.hidden = true;
      select.hidden = false;
      select.focus();
    });
  });

  tableBody.querySelectorAll('[data-incident-status]').forEach((select) => {
    const cancelEdit = () => {
      const button = tableBody.querySelector(`[data-edit-status="${CSS.escape(select.dataset.incidentStatus)}"]`);
      if (button) button.hidden = false;
      select.hidden = true;
    };

    select.addEventListener('change', async () => {
      select.disabled = true;
      try {
        const result = await apiRequest(`/incidents/${select.dataset.incidentStatus}/status`, {
          method: 'PATCH',
          body: JSON.stringify({ status: select.value }),
        });
        allIncidents = allIncidents.map((incident) => (
          incident._id === result.incident._id ? result.incident : incident
        ));
        updateDashboardStats();
        updateDashboardAnalytics();
        applyFilters();
        showToast('Incident status updated successfully', 'success');
      } catch (error) {
        applyFilters();
        showToast(error.message || 'Unable to update incident status', 'error');
      }
    });

    select.addEventListener('blur', cancelEdit);
    select.addEventListener('keydown', (event) => {
      if (event.key === 'Escape') {
        cancelEdit();
      }
    });
  });
}

function updateDashboardStats() {
  const totalEl = document.getElementById('totalIncidents');
  const pendingEl = document.getElementById('pendingIncidents');
  const investigatingEl = document.getElementById('investigatingIncidents');
  const resolvedEl = document.getElementById('resolvedIncidents');

  if (totalEl) totalEl.textContent = String(allIncidents.length);
  if (pendingEl) pendingEl.textContent = String(allIncidents.filter((incident) => (incident.status || 'Pending') === 'Pending').length);
  if (investigatingEl) investigatingEl.textContent = String(allIncidents.filter((incident) => (incident.status || 'Pending') === 'Investigating').length);
  if (resolvedEl) resolvedEl.textContent = String(allIncidents.filter((incident) => (incident.status || 'Pending') === 'Resolved').length);
}

function updateDashboardAnalytics() {
  const statusContainer = document.getElementById('dashboardStatusBars');
  const severityContainer = document.getElementById('dashboardAnalyticsSeverity');
  const typesContainer = document.getElementById('dashboardAnalyticsTypes');
  if (!statusContainer || !severityContainer || !typesContainer) return;

  const statusValues = [
    { label: 'Pending', count: allIncidents.filter((incident) => (incident.status || 'Pending') === 'Pending').length, color: 'pending-bar' },
    { label: 'Investigating', count: allIncidents.filter((incident) => (incident.status || 'Pending') === 'Investigating').length, color: 'investigating-bar' },
    { label: 'Resolved', count: allIncidents.filter((incident) => (incident.status || 'Pending') === 'Resolved').length, color: 'resolved-bar' },
  ];
  const maxStatusCount = Math.max(...statusValues.map(({ count }) => count), 1);
  statusContainer.innerHTML = statusValues.map(({ label, count, color }) => `
    <div class="bar-group status-bar-group" aria-label="${escapeHtml(label)}: ${count} ${count === 1 ? 'incident' : 'incidents'}">
      <strong class="status-chart-value">${count}</strong>
      <div class="bar ${color}" style="height:${(count / maxStatusCount) * 120}px" aria-hidden="true"></div>
      <span>${escapeHtml(label)}</span>
    </div>
  `).join('');

  const severityValues = [
    { label: 'Critical', color: 'critical', progress: 'critical-progress' },
    { label: 'High', color: 'high', progress: 'high-progress' },
    { label: 'Medium', color: 'medium', progress: 'medium-progress' },
    { label: 'Low', color: 'low', progress: 'low-progress' },
  ].map((item) => ({
    ...item,
    count: allIncidents.filter((incident) => (incident.severity || '').toLowerCase() === item.label.toLowerCase()).length,
  }));
  const total = Math.max(allIncidents.length, 1);
  severityContainer.innerHTML = severityValues.map(({ label, count, color, progress }) => `
    <div class="severity-row">
      <div class="severity-name"><span class="severity-dot ${color}"></span>${label}</div>
      <strong>${count}</strong>
      <div class="severity-progress"><span class="${progress}" style="width:${(count / total) * 100}%"></span></div>
    </div>
  `).join('');

  const types = new Map();
  allIncidents.forEach((incident) => {
    const type = incident.type || 'Uncategorized';
    types.set(type, (types.get(type) || 0) + 1);
  });
  const sortedTypes = [...types].sort((left, right) => right[1] - left[1] || left[0].localeCompare(right[0]));
  typesContainer.innerHTML = sortedTypes.length
    ? sortedTypes.map(([type, count]) => `<tr><td>${escapeHtml(type)}</td><td>${count}</td></tr>`).join('')
    : '<tr><td colspan="2" class="empty-table-cell">No incident types to display.</td></tr>';
}

function setupFilters() {
  const searchInput = document.getElementById('searchIncident');
  const severitySelect = document.getElementById('filterSeverity');
  const statusSelect = document.getElementById('filterStatus');
  const clearButton = document.getElementById('clearFiltersButton');

  if (searchInput) {
    searchInput.addEventListener('input', applyFilters);
  }

  if (severitySelect) {
    severitySelect.addEventListener('change', applyFilters);
  }

  if (statusSelect) {
    statusSelect.addEventListener('change', applyFilters);
  }

  if (clearButton) {
    clearButton.addEventListener('click', () => {
      if (searchInput) searchInput.value = '';
      if (severitySelect) severitySelect.value = '';
      if (statusSelect) statusSelect.value = '';
      applyFilters();
    });
  }
}

function setupStatCards() {
  document.querySelectorAll('.stat-card').forEach((card) => {
    card.addEventListener('click', () => {
      const stat = card.dataset.stat;
      const statusSelect = document.getElementById('filterStatus');
      const severitySelect = document.getElementById('filterSeverity');
      const searchInput = document.getElementById('searchIncident');

      if (!statusSelect) {
        const status = stat === 'pending' ? 'Pending' : stat === 'investigating' ? 'Investigating' : stat === 'resolved' ? 'Resolved' : '';
        window.location.href = `incidents.html${status ? `?status=${encodeURIComponent(status)}` : ''}`;
        return;
      }

      if (searchInput) searchInput.value = '';
      if (severitySelect) severitySelect.value = '';

      if (statusSelect) {
        statusSelect.value = stat === 'pending' ? 'Pending' : stat === 'investigating' ? 'Investigating' : stat === 'resolved' ? 'Resolved' : '';
      }

      applyFilters();
    });
  });
}

function setupNavigation() {
  const user = getUser();
  const isAdmin = user && user.role === 'admin';

  document.querySelectorAll('.admin-only').forEach((element) => {
    element.style.display = isAdmin ? '' : 'none';
  });
}

async function openIncidentModal(id) {
  try {
    const incident = await apiRequest(`/incidents/${id}`);
    selectedIncident = incident;

    const modal = document.getElementById('incidentModal');
    if (!modal) return;

    renderIncidentModal(incident);
    modal.classList.add('show');
  } catch (error) {
    showToast(error.message || 'Unable to open incident', 'error');
  }
}

function incidentTypeValue(type) {
  const normalized = String(type || '').trim().toLowerCase().replace(/[_-]/g, ' ');
  const types = {
    phishing: 'phishing',
    'phishing attack': 'phishing',
    malware: 'malware',
    'malware infection': 'malware',
    unauthorized: 'unauthorized',
    'unauthorized access': 'unauthorized',
    'data breach': 'data_breach',
    suspicious: 'suspicious',
    'suspicious activity': 'suspicious',
  };
  return types[normalized] || '';
}

function renderIncidentModal(incident) {
  const user = getUser();
  const isAdmin = user?.role === 'admin';
  const ownerId = incident.reportedBy && typeof incident.reportedBy === 'object'
    ? incident.reportedBy._id
    : incident.reportedBy;
  const canEdit = isAdmin || String(ownerId || '') === String(user?.id || '');
  const canDelete = isAdmin || String(ownerId || '') === String(user?.id || '');
  const status = incident.status || 'Pending';

  document.getElementById('modalIncidentId').textContent = incident.incidentId || 'Incident';
  document.getElementById('modalType').textContent = incident.type || '-';
  document.getElementById('modalSeverity').textContent = incident.severity || '-';
  document.getElementById('modalStatus').textContent = status;
  document.getElementById('modalDate').textContent = new Date(incident.date || incident.createdAt).toLocaleString();
  document.getElementById('modalDescription').textContent = incident.description || '-';
  document.getElementById('modalNotes').value = incident.investigationNotes || '';
  document.getElementById('modalTypeInput').value = incidentTypeValue(incident.type);
  document.getElementById('modalSeverityInput').value = incident.severity || '';
  document.getElementById('modalDescriptionInput').value = incident.description || '';
  document.getElementById('modalStatusInput').value = status;
  document.getElementById('modalChangeStatusButton').hidden = !isAdmin;
  document.getElementById('modalEditButton').hidden = !canEdit;
  document.getElementById('modalDeleteButton').hidden = !canDelete;
  editingIncidentStatus = false;
  document.getElementById('modalStatusInput').hidden = true;
  document.getElementById('modalSaveStatusButton').hidden = true;
  document.getElementById('modalCancelStatusButton').hidden = true;
  setIncidentEditMode(false, isAdmin);
}

function setIncidentEditMode(isEditing, isAdmin = getUser()?.role === 'admin') {
  editingIncident = isEditing;
  document.getElementById('modalType').hidden = isEditing;
  document.getElementById('modalTypeInput').hidden = !isEditing;
  document.getElementById('modalSeverity').hidden = isEditing;
  document.getElementById('modalSeverityInput').hidden = !isEditing;
  document.getElementById('modalDescription').hidden = isEditing;
  document.getElementById('modalDescriptionInput').hidden = !isEditing;
  document.getElementById('modalNotes').readOnly = !isEditing || !isAdmin;
  document.getElementById('modalEditButton').hidden = isEditing;
  document.getElementById('modalChangeStatusButton').hidden = isEditing || !isAdmin;
  document.getElementById('modalSaveButton').hidden = !isEditing;
  document.getElementById('modalCancelEditButton').hidden = !isEditing;
  document.getElementById('modalCloseSecondary').hidden = isEditing;
}

function beginIncidentStatusEdit() {
  if (!selectedIncident || getUser()?.role !== 'admin') return;
  editingIncidentStatus = true;
  document.getElementById('modalStatusInput').value = selectedIncident.status || 'Pending';
  document.getElementById('modalStatusInput').hidden = false;
  document.getElementById('modalChangeStatusButton').hidden = true;
  document.getElementById('modalEditButton').hidden = true;
  document.getElementById('modalDeleteButton').hidden = true;
  document.getElementById('modalCloseSecondary').hidden = true;
  document.getElementById('modalSaveStatusButton').hidden = false;
  document.getElementById('modalCancelStatusButton').hidden = false;
}

function closeIncidentModal() {
  const modal = document.getElementById('incidentModal');
  if (modal) modal.classList.remove('show');
  editingIncident = false;
}

async function submitIncident(event) {
  if (event && typeof event.preventDefault === 'function') {
    event.preventDefault();
  }

  const type = document.getElementById('type')?.value || '';
  const severity = document.getElementById('severity')?.value || '';
  const description = document.getElementById('description')?.value || '';

  if (!type || !severity || !description.trim()) {
    showToast('Please complete all incident fields', 'error');
    return;
  }

  const submitButton = document.getElementById('submitIncidentButton');
  if (submitButton) {
    submitButton.disabled = true;
    submitButton.dataset.originalText = submitButton.textContent;
    submitButton.textContent = 'Submitting...';
  }

  try {
    await apiRequest('/incidents', {
      method: 'POST',
      body: JSON.stringify({ type, severity, description }),
    });

    showToast('Incident reported successfully', 'success');
    setTimeout(() => {
      window.location.href = 'dashboard.html';
    }, 300);
  } catch (error) {
    showToast(error.message || 'Unable to submit incident', 'error');
  } finally {
    if (submitButton) {
      submitButton.disabled = false;
      submitButton.textContent = submitButton.dataset.originalText || 'Submit Incident Report';
    }
  }
}

function goToReport() {
  window.location.href = 'report.html';
}

function scrollToIncidents() {
  window.location.href = 'incidents.html';
}

async function initializeDashboard() {
  const token = getToken();
  const user = getUser();

  if (!token || !user) {
    redirectToLogin();
    return;
  }

  loadUserUI();
  setupUserMenu();
  setupMobileMenu();
  setupFilters();
  setupNavigation();
  setupStatCards();
  const statusFilter = document.getElementById('filterStatus');
  const initialStatus = new URLSearchParams(window.location.search).get('status');
  if (statusFilter && ['Pending', 'Investigating', 'Resolved'].includes(initialStatus)) {
    statusFilter.value = initialStatus;
  }

  const modalDeleteButton = document.getElementById('modalDeleteButton');
  const modalSaveButton = document.getElementById('modalSaveButton');
  const modalSaveStatusButton = document.getElementById('modalSaveStatusButton');
  const modalChangeStatusButton = document.getElementById('modalChangeStatusButton');
  const modalCancelStatusButton = document.getElementById('modalCancelStatusButton');

  await loadIncidents();

  const closeModalButton = document.getElementById('closeModalButton');
  if (closeModalButton) {
    closeModalButton.addEventListener('click', closeIncidentModal);
  }

  const modalCloseSecondary = document.getElementById('modalCloseSecondary');
  if (modalCloseSecondary) {
    modalCloseSecondary.addEventListener('click', closeIncidentModal);
  }

  const incidentModal = document.getElementById('incidentModal');
  if (incidentModal) {
    incidentModal.addEventListener('click', (event) => {
      if (event.target === incidentModal) closeIncidentModal();
    });
  }

  if (modalSaveButton) {
    modalSaveButton.addEventListener('click', async () => {
      if (!selectedIncident || !editingIncident) return;
      const updates = {
        type: document.getElementById('modalTypeInput').value,
        severity: document.getElementById('modalSeverityInput').value,
        description: document.getElementById('modalDescriptionInput').value.trim(),
      };

      if (!updates.type || !updates.severity || !updates.description) {
        showToast('Type, severity and description are required', 'error');
        return;
      }
      if (updates.description.length > 5000) {
        showToast('Description must be 5000 characters or fewer', 'error');
        return;
      }

      if (user.role === 'admin') {
        updates.investigationNotes = document.getElementById('modalNotes').value.trim();
      }

      modalSaveButton.disabled = true;
      modalSaveButton.textContent = 'Saving...';
      try {
        const result = await apiRequest(`/incidents/${selectedIncident._id}`, {
          method: 'PATCH',
          body: JSON.stringify(updates),
        });
        selectedIncident = result.incident;
        renderIncidentModal(selectedIncident);
        await loadIncidents();
        showToast('Incident updated successfully', 'success');
      } catch (error) {
        showToast(error.message || 'Unable to save changes', 'error');
      } finally {
        modalSaveButton.disabled = false;
        modalSaveButton.textContent = 'Save Changes';
      }
    });
  }

  const modalEditButton = document.getElementById('modalEditButton');
  if (modalEditButton) {
    modalEditButton.addEventListener('click', () => setIncidentEditMode(true, user.role === 'admin'));
  }

  if (modalChangeStatusButton && user.role === 'admin') {
    modalChangeStatusButton.addEventListener('click', beginIncidentStatusEdit);
  }

  if (modalSaveStatusButton && user.role === 'admin') {
    modalSaveStatusButton.addEventListener('click', async () => {
      if (!selectedIncident || !editingIncidentStatus) return;
      modalSaveStatusButton.disabled = true;
      modalSaveStatusButton.textContent = 'Saving...';
      try {
        const result = await apiRequest(`/incidents/${selectedIncident._id}/status`, {
          method: 'PATCH',
          body: JSON.stringify({ status: document.getElementById('modalStatusInput').value }),
        });
        selectedIncident = result.incident;
        renderIncidentModal(selectedIncident);
        await loadIncidents();
        showToast('Incident status updated successfully', 'success');
      } catch (error) {
        showToast(error.message || 'Unable to update incident status', 'error');
      } finally {
        modalSaveStatusButton.disabled = false;
        modalSaveStatusButton.textContent = 'Save Status';
      }
    });
  }

  if (modalCancelStatusButton) {
    modalCancelStatusButton.addEventListener('click', () => {
      if (selectedIncident) renderIncidentModal(selectedIncident);
    });
  }

  const modalCancelEditButton = document.getElementById('modalCancelEditButton');
  if (modalCancelEditButton) {
    modalCancelEditButton.addEventListener('click', () => {
      if (selectedIncident) renderIncidentModal(selectedIncident);
    });
  }

  if (modalDeleteButton) {
    modalDeleteButton.addEventListener('click', async () => {
      if (!selectedIncident) return;
      if (!window.confirm(`Delete incident ${selectedIncident.incidentId || ''}? This action cannot be undone.`)) return;

      modalDeleteButton.disabled = true;
      modalDeleteButton.textContent = 'Deleting...';

      try {
        await apiRequest(`/incidents/${selectedIncident._id}`, { method: 'DELETE' });
        selectedIncident = null;
        closeIncidentModal();
        await loadIncidents();
        showToast('Incident deleted successfully', 'success');
      } catch (error) {
        showToast(error.message || 'Unable to delete incident', 'error');
      } finally {
        modalDeleteButton.disabled = false;
        modalDeleteButton.textContent = 'Delete';
      }
    });
  }
}

async function initializeUsersPage() {
  const token = getToken();
  const user = getUser();

  if (!token || !user) {
    redirectToLogin();
    return;
  }
  if (user.role !== 'admin') {
    redirectToDashboard();
    return;
  }

  loadUserUI();
  setupUserMenu();
  setupMobileMenu();
  setupNavigation();
  await loadUsers();
}

function initializePage() {
  const page = window.location.pathname.split('/').pop();

  if (page === 'login.html' || page === 'register.html') {
    initializeAuthPage();
    return;
  }

  if (page === 'dashboard.html' || page === 'incidents.html' || page === 'report.html' || page === 'incident.html') {
    if (page !== 'report.html' && !getToken()) {
      redirectToLogin();
      return;
    }

    if (page === 'dashboard.html' || page === 'incidents.html') {
      initializeDashboard();
      return;
    }

    if (page === 'report.html') {
      if (!getToken()) {
        redirectToLogin();
        return;
      }
      const form = document.getElementById('reportForm');
      if (form) {
        form.addEventListener('submit', submitIncident);
      }
    }
    return;
  }

  if (page === 'users.html') {
    initializeUsersPage();
    return;
  }

}

window.addEventListener('DOMContentLoaded', initializePage);

window.logout = function logout() {
  clearAuth();
  window.location.href = 'login.html';
};
