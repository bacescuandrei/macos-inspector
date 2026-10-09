const state = {online: false, healthPoll: null};

const $ = (selector) => document.querySelector(selector);
const escapeHtml = (value) => String(value ?? '').replace(/[&<>"']/g, (character) => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[character]));
const writeOptions = (method, body) => ({method, headers:{'Content-Type':'application/json', 'X-MacOS-Inspector':'1'}, body:JSON.stringify(body)});

const api = async (url, options = {}) => {
  let response;
  try {
    if (new URL(url, window.location.href).origin !== window.location.origin) throw new Error('Only same-origin dashboard requests are allowed.');
    const headers = new Headers(options.headers || {});
    const credential = window.sessionStorage.getItem('macos-inspector-session');
    if (credential) headers.set('Authorization', `Bearer ${credential}`);
    options = {...options, headers};
    response = await fetch(url, options);
  } catch (error) {
    setConnection('offline');
    throw new Error('Dashboard server unavailable. Open macOS Inspector.command and keep its launcher window open.');
  }
  let payload;
  try {
    payload = await response.json();
  } catch (error) {
    throw new Error('Dashboard returned an invalid response. Open this page through http://127.0.0.1:8765, not as a file.');
  }
  if (!response.ok) throw new Error(payload.error || `Request failed (${response.status})`);
  return payload;
};

function setInline(selector, message, error = false) {
  const element = $(selector);
  if (!element) return;
  element.textContent = message || '';
  element.classList.toggle('error', error);
}

function setConnection(status, health = null) {
  const element = $('#connection');
  state.online = status === 'online';
  if (element) {
    element.className = `connection ${status}`;
    element.textContent = status === 'online' ? `Connected | v${health?.version || '?'}` : status === 'checking' ? 'Connecting...' : 'Offline | retrying';
    element.title = status === 'online' && health?.started_at ? `Server started ${health.started_at}` : 'The dashboard will reconnect automatically.';
  }
  if (typeof updateRunAvailability === 'function') updateRunAvailability();
  if (typeof updatePdfAvailability === 'function') updatePdfAvailability();
}

async function authorizeLaunchFragment() {
  const launchToken = new URLSearchParams(window.location.hash.slice(1)).get('launch');
  if (!launchToken) return;
  window.history.replaceState(null, '', window.location.pathname + window.location.search);
  try {
    const session = await api('/api/session', writeOptions('POST', {token: launchToken}));
    window.sessionStorage.setItem('macos-inspector-session', session.api_token);
    if (typeof pdfState !== 'undefined') pdfState.historyLoaded = false;
  } catch (error) { if (typeof setMessage === 'function') setMessage(error.message, true);
    else setInline('#pdf-message', error.message, true); }
}
