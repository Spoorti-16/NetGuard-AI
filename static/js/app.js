const CSRF = document.querySelector('meta[name=csrf]').content;
async function api(url, body, method) {
  const o = {method: method || (body === undefined ? 'GET' : 'POST'), headers: {'X-CSRF-Token': CSRF}};
  if (body instanceof FormData) o.body = body;
  else if (body !== undefined) { o.headers['Content-Type'] = 'application/json'; o.body = JSON.stringify(body); }
  try {
    const r = await fetch(url, o);
    const j = await r.json().catch(() => ({error: 'Server error (' + r.status + ')'}));
    if (!r.ok && !j.error) j.error = 'Request failed (' + r.status + ')';
    return j;
  } catch (e) { return {error: 'Network error'}; }
}
function toast(msg, isErr) {
  const t = document.createElement('div');
  t.className = 'toast' + (isErr ? ' err' : ''); t.textContent = msg;
  document.body.appendChild(t); setTimeout(() => t.remove(), 4200);
}
function res(j, okMsg) { if (j.error) toast(j.error, true); else toast(j.ok || okMsg || 'Done'); return !j.error; }
function esc(s) { return String(s ?? '').replace(/[&<>"']/g, c => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c])); }
function pill(v) { return `<span class="pill p-${esc(v)}">${esc(v)}</span>`; }
const charts = {};
function chart(id, cfg) {
  if (charts[id]) charts[id].destroy();
  cfg.options = Object.assign({responsive: true, maintainAspectRatio: false, animation: false,
    plugins: {legend: {labels: {color: '#8da0bf'}}}}, cfg.options || {});
  if (cfg.type !== 'doughnut') cfg.options.scales = {x: {ticks: {color: '#8da0bf', maxTicksLimit: 8}, grid: {color: '#1b2a47'}},
    y: {ticks: {color: '#8da0bf'}, grid: {color: '#1b2a47'}, beginAtZero: true}};
  charts[id] = new Chart(document.getElementById(id), cfg);
}
const PAL = ['#22d3ee', '#ef4444', '#f59e0b', '#22c55e', '#8b5cf6', '#ec4899', '#14b8a6', '#eab308', '#6366f1', '#f97316'];
function tabs(root) {
  const btns = root.querySelectorAll('.tabs button'), panes = root.querySelectorAll('[data-pane]');
  btns.forEach(b => b.onclick = () => {
    btns.forEach(x => x.classList.toggle('on', x === b));
    panes.forEach(p => p.classList.toggle('hide', p.dataset.pane !== b.dataset.tab));
  });
  if (btns[0]) btns[0].click();
}
document.querySelectorAll('[data-tabs]').forEach(tabs);
