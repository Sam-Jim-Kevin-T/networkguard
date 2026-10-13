(() => {
  "use strict";

  const $ = (selector) => document.querySelector(selector);
  const state = { csrf: null, page: "dashboard", dashboard: null, servers: [], alerts: [], events: [], selectedServerId: null };
  const pageTitles = { dashboard: "Overview", servers: "My servers", alerts: "Security alerts" };
  const escapeText = (value) => String(value ?? "").replace(/[&<>"']/g, (char) => ({
    "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;",
  })[char]);

  async function request(path, options = {}) {
    const headers = new Headers(options.headers || {});
    if (options.body && !headers.has("Content-Type")) headers.set("Content-Type", "application/json");
    const response = await fetch(path, { ...options, headers, credentials: "same-origin" });
    const payload = response.status === 204 ? null : await response.json().catch(() => ({}));
    if (!response.ok) {
      const message = payload?.error?.replaceAll("_", " ") || `Request failed (${response.status})`;
      throw new Error(message);
    }
    return payload;
  }

  async function mutate(path, method, body) {
    state.csrf = (await request("/api/csrf")).csrf_token;
    return request(path, {
      method,
      headers: { "X-CSRFToken": state.csrf },
      ...(body === undefined ? {} : { body: JSON.stringify(body) }),
    });
  }

  function showNotice(message, error = false) {
    const notice = $("#global-notice");
    notice.textContent = message;
    notice.className = error ? "notice error" : "notice";
    notice.hidden = false;
    if (!error) window.setTimeout(() => { notice.hidden = true; }, 5000);
  }

  function setAuthMode(mode) {
    const registering = mode === "register";
    $("#auth-heading").textContent = registering ? "Start monitoring your servers." : "Your infrastructure, in view.";
    $("#auth-submit").textContent = registering ? "Create account" : "Sign in";
    $("#auth-password").autocomplete = registering ? "new-password" : "current-password";
    $("#auth-password").minLength = registering ? 12 : 1;
    $("#password-hint").hidden = !registering;
    $("#login-tab").classList.toggle("selected", !registering);
    $("#register-tab").classList.toggle("selected", registering);
    $("#login-tab").setAttribute("aria-selected", String(!registering));
    $("#register-tab").setAttribute("aria-selected", String(registering));
    $("#auth-form").dataset.mode = mode;
    $("#auth-error").hidden = true;
  }

  function showAuth(error = "") {
    $("#app-view").hidden = true;
    $("#auth-view").hidden = false;
    if (error) {
      $("#auth-error").textContent = error;
      $("#auth-error").hidden = false;
    }
  }

  function showApp(email) {
    $("#auth-view").hidden = true;
    $("#app-view").hidden = false;
    $("#account-email").textContent = email;
    $("#account-avatar").textContent = (email[0] || "U").toUpperCase();
    setPage("dashboard");
  }

  function setPage(page) {
    state.page = page;
    $("#page-title").textContent = pageTitles[page];
    document.querySelectorAll(".page-content").forEach((element) => {
      element.hidden = element.id !== `${page}-page`;
    });
    document.querySelectorAll(".nav-link").forEach((element) => {
      element.classList.toggle("active", element.dataset.page === page);
    });
    if (page === "alerts") renderAlertsPage();
    if (page === "servers") renderServersPage();
  }

  function statusPill(status) {
    return `<span class="status-pill ${status === "online" ? "online" : ""}">${escapeText(status || "offline")}</span>`;
  }

  function serverTable(servers) {
    if (!servers.length) return '<div class="empty-state">No servers registered yet. Add a Linux server to get started.</div>';
    return `<div class="table-wrap"><table><thead><tr><th>SERVER</th><th>STATUS</th><th>CPU</th><th>MEMORY</th><th>CONNECTIONS</th><th>RISK</th></tr></thead><tbody>${servers.map((server) => `
      <tr><td><span class="server-name" data-server-detail="${server.id}">${escapeText(server.name)}</span><div class="alert-meta">${escapeText(server.hostname || "Linux host")}</div></td>
      <td>${statusPill(server.status)}</td><td>${server.cpu_percent == null ? "—" : `${Number(server.cpu_percent).toFixed(1)}%`}</td>
      <td>${server.memory_percent == null ? "—" : `${Number(server.memory_percent).toFixed(1)}%`}</td>
      <td>${Number(server.tcp_connections || 0) + Number(server.udp_connections || 0)}</td><td><span class="risk-pill risk-${String(server.risk || "LOW").toLowerCase()}">${escapeText(server.risk || "LOW")}</span></td></tr>`).join("")}</tbody></table></div>`;
  }

  function renderDashboard(data) {
    state.dashboard = data;
    state.servers = data.servers || [];
    state.alerts = data.alerts || [];
    state.events = data.events || [];
    $("#stat-servers").textContent = data.summary.server_count;
    $("#stat-online").textContent = `${data.summary.online_servers} online`;
    $("#stat-connections").textContent = data.summary.connections;
    $("#stat-protocols").textContent = `${data.summary.tcp_connections} TCP · ${data.summary.udp_connections} UDP`;
    $("#stat-alerts").textContent = data.summary.active_alerts;
    $("#server-nav-count").textContent = data.summary.server_count;
    $("#stat-suspicious").textContent = data.summary.suspicious_connections || 0;
    $("#normal-connections").textContent = data.summary.normal_connections || 0;
    $("#suspicious-connections").textContent = data.summary.suspicious_connections || 0;
    $("#listed-connections").textContent = data.summary.listed_connections || 0;
    const connectionRisk = $("#connection-risk-level");
    connectionRisk.textContent = data.summary.suspicious_connections ? "REVIEW NEEDED" : "LOW REVIEW";
    connectionRisk.className = `risk-pill ${data.summary.suspicious_connections ? "risk-medium" : ""}`;
    $("#alert-nav-count").textContent = (data.summary.active_alerts || 0) + (data.summary.active_events || 0);
    $("#dashboard-servers").innerHTML = serverTable(state.servers);
    $("#recent-alerts").innerHTML = alertRows(state.alerts.slice(0, 4), true);
    $("#recent-events").innerHTML = eventRows(state.events.slice(0, 5), true);
    renderProcessBars(data.top_processes || []);
    drawTraffic(data.traffic || []);
    $("#last-updated").textContent = `Updated ${new Date().toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" })}`;
    if (state.page === "servers") renderServersPage();
    if (state.page === "alerts") renderAlertsPage();
  }

  function alertRows(alerts, compact = false) {
    if (!alerts.length) return '<div class="empty-state">No alerts to show. Your systems look quiet.</div>';
    return alerts.map((alert) => `<div class="alert-row">
      <span class="alert-severity ${escapeText(alert.severity)}"></span>
      <div class="alert-copy"><strong>${escapeText(alert.title)}</strong><p>${escapeText(alert.description)}</p>
      <div class="alert-meta">${escapeText(alert.server_name)} · ${escapeText(new Date(alert.last_seen_at).toLocaleString())} · ${escapeText(alert.severity.toUpperCase())}</div></div>
      ${!compact && alert.status === "active" ? `<button class="alert-action" type="button" data-resolve-alert="${alert.id}">Resolve</button>` : ""}
    </div>`).join("");
  }

  function eventRows(events, compact = false) {
    if (!events.length) return '<div class="empty-state">No noteworthy events have been detected.</div>';
    return events.map((item) => `<div class="alert-row">
      <span class="alert-severity ${escapeText(item.severity)}"></span>
      <div class="alert-copy"><strong>${escapeText(item.title)}</strong><p>${escapeText(item.details)}</p>
      <div class="alert-meta">${escapeText(item.server_name)} · ${escapeText(new Date(item.last_seen_at).toLocaleString())} · ${escapeText(item.occurrences)} occurrence(s)</div></div>
      ${!compact && item.status === "active" ? `<button class="alert-action" type="button" data-resolve-event="${item.id}">Resolve</button>` : ""}
    </div>`).join("");
  }

  function renderProcessBars(processes) {
    const target = $("#top-processes");
    if (!processes.length) {
      target.innerHTML = '<div class="empty-state">Process rankings appear when agents report established connections.</div>';
      return;
    }
    const maximum = Math.max(1, ...processes.map((item) => item.connections));
    target.innerHTML = processes.map((item, index) => `<div class="process-bar-row">
      <span class="process-name" title="${escapeText(item.process)}">${escapeText(item.process)}</span>
      <span class="process-bar-track"><i class="process-bar process-color-${index % 5}" style="width:${Math.max(2, item.connections / maximum * 100)}%"></i></span>
      <span class="process-count">${escapeText(item.connections)}</span>
    </div>`).join("");
  }

  async function renderAlertsPage() {
    const filter = $("#alert-filter").value;
    try {
      const suffix = filter === "all" ? "" : `?status=${encodeURIComponent(filter)}`;
      const [alerts, events] = await Promise.all([
        request(`/api/alerts${suffix}`),
        request(`/api/events${suffix}`),
      ]);
      state.alerts = alerts.alerts;
      state.events = events.events;
      $("#all-alerts").innerHTML = alertRows(alerts.alerts);
      $("#all-events").innerHTML = eventRows(events.events);
    } catch (error) {
      $("#all-alerts").innerHTML = `<div class="empty-state">${escapeText(error.message)}</div>`;
      $("#all-events").innerHTML = `<div class="empty-state">${escapeText(error.message)}</div>`;
    }
  }

  function renderServersPage() {
    $("#server-grid").innerHTML = state.servers.length ? state.servers.map((server) => `
      <article class="server-card"><div class="server-card-head"><div><h3>${escapeText(server.name)}</h3><span class="hostname">${escapeText(server.hostname || "Linux host")}</span></div>${statusPill(server.status)}</div>
      <div class="server-card-stats"><div><span>CPU</span><strong>${server.cpu_percent == null ? "—" : `${Number(server.cpu_percent).toFixed(1)}%`}</strong></div>
      <div><span>Memory</span><strong>${server.memory_percent == null ? "—" : `${Number(server.memory_percent).toFixed(1)}%`}</strong></div>
      <div><span>Connections</span><strong>${Number(server.tcp_connections || 0) + Number(server.udp_connections || 0)}</strong></div>
      <div><span>Risk</span><strong class="risk-pill risk-${String(server.risk || "LOW").toLowerCase()}">${escapeText(server.risk || "LOW")}</strong></div></div>
      <div class="server-card-actions"><button class="text-button" type="button" data-server-detail="${server.id}">View details →</button><button class="alert-action" type="button" data-delete-server="${server.id}">Remove</button></div></article>`).join("") : '<article class="panel empty-state">No servers yet. Add a Linux host to begin collecting metrics.</article>';
  }

  function drawTraffic(traffic) {
    const canvas = $("#traffic-chart");
    const ctx = canvas.getContext("2d");
    const box = canvas.getBoundingClientRect();
    const ratio = window.devicePixelRatio || 1;
    canvas.width = Math.max(1, Math.floor(box.width * ratio));
    canvas.height = Math.max(1, Math.floor(box.height * ratio));
    ctx.scale(ratio, ratio);
    const width = box.width;
    const height = box.height;
    ctx.clearRect(0, 0, width, height);
    $("#chart-empty").hidden = traffic.length > 0;
    if (!traffic.length || width < 1 || height < 1) return;
    const pad = { top: 12, right: 12, bottom: 17, left: 48 };
    const plotWidth = width - pad.left - pad.right;
    const plotHeight = height - pad.top - pad.bottom;
    const max = Math.max(1, ...traffic.map((item) => Math.max(item.network_in_bytes, item.network_out_bytes)));
    ctx.font = '10px "DM Mono", monospace';
    ctx.textBaseline = "middle";
    for (let line = 0; line <= 3; line += 1) {
      const y = pad.top + plotHeight * line / 3;
      ctx.strokeStyle = "#1b2a3b";
      ctx.beginPath(); ctx.moveTo(pad.left, y); ctx.lineTo(width - pad.right, y); ctx.stroke();
      ctx.fillStyle = "#73859b";
      const value = max * (1 - line / 3);
      ctx.fillText(value >= 1024 * 1024 ? `${(value / 1024 / 1024).toFixed(1)}M` : `${Math.round(value / 1024)}K`, 1, y);
    }
    const series = [
      { key: "network_in_bytes", color: "#5595ff" },
      { key: "network_out_bytes", color: "#39d2df" },
    ];
    series.forEach(({ key, color }) => {
      ctx.strokeStyle = color; ctx.lineWidth = 2; ctx.beginPath();
      traffic.forEach((point, index) => {
        const x = pad.left + plotWidth * (traffic.length === 1 ? 0.5 : index / (traffic.length - 1));
        const y = pad.top + plotHeight * (1 - point[key] / max);
        if (index === 0) ctx.moveTo(x, y); else ctx.lineTo(x, y);
      });
      ctx.stroke();
    });
  }

  async function refresh() {
    $("#loading-state").hidden = false;
    try {
      renderDashboard(await request("/api/dashboard"));
    } catch (error) {
      if (error.message.includes("authentication required")) {
        showAuth();
      } else {
        showNotice(error.message, true);
      }
    } finally {
      $("#loading-state").hidden = true;
    }
  }

  async function showServerDetail(id) {
    try {
      const result = await request(`/api/servers/${id}`);
      state.selectedServerId = Number(id);
      const server = result.server;
      const metrics = result.metrics;
      const latest = metrics.at(-1);
      const ports = latest?.listening_ports || [];
      const connections = latest?.connections || [];
      const processCounts = {};
      for (const item of connections) {
        if (item.process) processCounts[item.process] = (processCounts[item.process] || 0) + 1;
      }
      const processes = Object.entries(processCounts)
        .map(([process, count]) => ({ process, connections: count }))
        .sort((left, right) => right.connections - left.connections || left.process.localeCompare(right.process));
      const rules = result.ip_rules || [];
      const detail = $("#server-detail");
      detail.innerHTML = `<div class="panel-heading"><div><p class="eyebrow">SERVER DETAILS</p><h2>${escapeText(server.name)}</h2><p class="muted">${escapeText(server.hostname || "Linux host")} · ${statusPill(server.status)}</p></div><button class="icon-button" type="button" data-close-detail aria-label="Close details">×</button></div>
        <div class="server-card-stats"><div><span>CPU</span><strong>${server.cpu_percent == null ? "—" : `${Number(server.cpu_percent).toFixed(1)}%`}</strong></div><div><span>Memory</span><strong>${server.memory_percent == null ? "—" : `${Number(server.memory_percent).toFixed(1)}%`}</strong></div><div><span>TCP</span><strong>${server.tcp_connections}</strong></div><div><span>UDP</span><strong>${server.udp_connections}</strong></div></div>
        <h2>Listening ports</h2><p class="muted">${ports.length ? ports.map(escapeText).join(", ") : "No listening ports reported."}</p>
        <h2 class="detail-section-title">Established connections</h2>
        ${connections.length ? `<div class="table-wrap"><table><thead><tr><th>PID</th><th>PROCESS</th><th>LOCAL ADDRESS</th><th>REMOTE ADDRESS</th><th>PROTOCOL</th><th>STATE</th><th>RISK / LABEL</th></tr></thead><tbody>${connections.map((item) => `<tr><td>${escapeText(item.pid ?? "—")}</td><td>${escapeText(item.process || "Unknown")}</td><td>${escapeText(item.local_ip || "—")}:${escapeText(item.local_port ?? "—")}</td><td>${escapeText(item.remote_ip || "—")}:${escapeText(item.remote_port ?? "—")}</td><td>${escapeText(item.protocol || "—")}</td><td>${escapeText(item.status || "—")}</td><td><span class="connection-risk risk-${escapeText(item.risk)}">${escapeText(item.risk.replaceAll("_", " "))}</span><div class="alert-meta">${escapeText(item.risk_reason)}</div></td></tr>`).join("")}</tbody></table></div>` : '<div class="empty-state">No established connections reported.</div>'}
        <h2 class="detail-section-title">Top processes by observed connections</h2>${processes.length ? processBarsCompact(processes) : '<div class="empty-state">No established connections to rank.</div>'}
        <h2 class="detail-section-title">Detected anomalies & logs</h2>${eventRows((result.events || []).slice(0, 15))}
        <div class="panel-heading rules-heading"><div><h2>IP allowlist & blocklist</h2><p class="muted">Informational only—these labels do not change Linux firewall traffic.</p></div><button type="button" class="button secondary" data-add-ip-rule="${server.id}">＋ Add IP</button></div>
        ${ipRulesTable(rules, server.id)}`;
      detail.hidden = false;
      detail.scrollIntoView({ behavior: "smooth", block: "nearest" });
    } catch (error) {
      showNotice(error.message, true);
    }
  }

  function processBarsCompact(processes) {
    const maximum = Math.max(1, ...processes.map((item) => item.connections));
    return `<div class="process-bars">${processes.slice(0, 10).map((item, index) => `<div class="process-bar-row">
      <span class="process-name" title="${escapeText(item.process)}">${escapeText(item.process)}</span>
      <span class="process-bar-track"><i class="process-bar process-color-${index % 5}" style="width:${Math.max(2, item.connections / maximum * 100)}%"></i></span>
      <span class="process-count">${escapeText(item.connections)}</span></div>`).join("")}</div>`;
  }

  function ipRulesTable(rules, serverId) {
    if (!rules.length) return '<div class="empty-state">No IP labels configured.</div>';
    return `<div class="table-wrap"><table><thead><tr><th>IP ADDRESS</th><th>LIST</th><th>NOTE</th><th></th></tr></thead><tbody>${rules.map((rule) => `<tr><td>${escapeText(rule.ip_address)}</td><td><span class="risk-pill ${rule.action === "block" ? "risk-medium" : ""}">${rule.action === "block" ? "Blocklist label" : "Allowed"}</span></td><td>${escapeText(rule.note || "—")}</td><td><button class="alert-action" type="button" data-delete-ip-rule="${rule.id}" data-server-id="${serverId}">Remove</button></td></tr>`).join("")}</tbody></table></div>`;
  }

  async function initialize() {
    try {
      const user = await request("/api/auth/me");
      showApp(user.email);
      await refresh();
      const params = new URLSearchParams(window.location.search);
      if (params.get("registered") === "1") {
        window.history.replaceState({}, "", "/");
        showNotice("Account created. Add your first Linux server to get started.");
      }
    } catch {
      showAuth();
    }
  }

  setAuthMode("login");
  $("#toggle-password").addEventListener("click", () => {
    const password = $("#auth-password");
    const isVisible = password.type === "password";
    password.type = isVisible ? "text" : "password";
    $("#toggle-password").setAttribute("aria-label", isVisible ? "Hide password" : "Show password");
    $("#toggle-password").setAttribute("aria-pressed", String(isVisible));
    $(".password-icon-show").hidden = isVisible;
    $(".password-icon-hide").hidden = !isVisible;
  });
  $("#login-tab").addEventListener("click", () => setAuthMode("login"));
  $("#register-tab").addEventListener("click", () => setAuthMode("register"));
  $("#auth-form").addEventListener("submit", async (event) => {
    event.preventDefault();
    const form = event.currentTarget;
    const button = $("#auth-submit");
    button.disabled = true;
    try {
      const data = Object.fromEntries(new FormData(form));
      const mode = form.dataset.mode;
      const user = await mutate(`/api/auth/${mode}`, "POST", data);
      showApp(user.email);
      await refresh();
    } catch (error) {
      $("#auth-error").textContent = error.message;
      $("#auth-error").hidden = false;
    } finally {
      button.disabled = false;
    }
  });
  $("#logout-button").addEventListener("click", async () => {
    try { await mutate("/api/auth/logout", "POST"); showAuth(); }
    catch (error) { showNotice(error.message, true); }
  });
  $("#refresh-button").addEventListener("click", refresh);
  $("#alert-filter").addEventListener("change", renderAlertsPage);
  document.querySelectorAll(".nav-link").forEach((link) => link.addEventListener("click", () => setPage(link.dataset.page)));
  document.querySelectorAll("[data-go-page]").forEach((link) => link.addEventListener("click", () => setPage(link.dataset.goPage)));
  document.querySelectorAll("[data-open-add]").forEach((button) => button.addEventListener("click", () => {
    $("#server-form-error").hidden = true;
    $("#add-server-dialog").showModal();
  }));
  document.querySelectorAll("[data-close-dialog]").forEach((button) => button.addEventListener("click", () => button.closest("dialog").close()));
  document.body.addEventListener("click", async (event) => {
    const addRuleButton = event.target.closest("[data-add-ip-rule]");
    if (addRuleButton) {
      state.selectedServerId = Number(addRuleButton.dataset.addIpRule);
      $("#rule-form-error").hidden = true;
      $("#ip-rule-form").reset();
      $("#ip-rule-dialog").showModal();
      return;
    }
    const deleteRuleButton = event.target.closest("[data-delete-ip-rule]");
    if (deleteRuleButton) {
      try {
        await mutate(`/api/servers/${deleteRuleButton.dataset.serverId}/ip-rules/${deleteRuleButton.dataset.deleteIpRule}`, "DELETE");
        await showServerDetail(deleteRuleButton.dataset.serverId);
        await refresh();
      } catch (error) { showNotice(error.message, true); }
      return;
    }
    const resolveEventButton = event.target.closest("[data-resolve-event]");
    if (resolveEventButton) {
      try { await mutate(`/api/events/${resolveEventButton.dataset.resolveEvent}/resolve`, "POST"); await refresh(); }
      catch (error) { showNotice(error.message, true); }
      return;
    }
    const detailButton = event.target.closest("[data-server-detail]");
    if (detailButton) return showServerDetail(detailButton.dataset.serverDetail);
    if (event.target.closest("[data-close-detail]")) { $("#server-detail").hidden = true; return; }
    const resolveButton = event.target.closest("[data-resolve-alert]");
    if (resolveButton) {
      try { await mutate(`/api/alerts/${resolveButton.dataset.resolveAlert}/resolve`, "POST"); await refresh(); }
      catch (error) { showNotice(error.message, true); }
    }
    const deleteButton = event.target.closest("[data-delete-server]");
    if (deleteButton && window.confirm("Remove this server and permanently delete its metrics and alerts?")) {
      try { await mutate(`/api/servers/${deleteButton.dataset.deleteServer}`, "DELETE"); $("#server-detail").hidden = true; await refresh(); showNotice("Server removed."); }
      catch (error) { showNotice(error.message, true); }
    }
  });
  $("#ip-rule-form").addEventListener("submit", async (event) => {
    event.preventDefault();
    const button = event.currentTarget.querySelector('[type="submit"]');
    button.disabled = true;
    try {
      const body = Object.fromEntries(new FormData(event.currentTarget));
      await mutate(`/api/servers/${state.selectedServerId}/ip-rules`, "POST", body);
      $("#ip-rule-dialog").close();
      await showServerDetail(state.selectedServerId);
      await refresh();
    } catch (error) {
      $("#rule-form-error").textContent = error.message;
      $("#rule-form-error").hidden = false;
    } finally { button.disabled = false; }
  });
  $("#add-server-form").addEventListener("submit", async (event) => {
    event.preventDefault();
    const form = event.currentTarget;
    const button = form.querySelector('[type="submit"]');
    button.disabled = true;
    try {
      const values = Object.fromEntries(new FormData(form));
      const result = await mutate("/api/servers", "POST", values);
      $("#add-server-dialog").close();
      form.reset();
      $("#new-agent-token").value = result.agent_token;
      $("#token-dialog").showModal();
      setPage("servers");
      await refresh();
    } catch (error) {
      $("#server-form-error").textContent = error.message;
      $("#server-form-error").hidden = false;
    } finally {
      button.disabled = false;
    }
  });
  $("#copy-token").addEventListener("click", async () => {
    try {
      await navigator.clipboard.writeText($("#new-agent-token").value);
      $("#copy-token").textContent = "Copied";
      window.setTimeout(() => { $("#copy-token").textContent = "Copy"; }, 1800);
    } catch {
      $("#new-agent-token").select();
      showNotice("Clipboard access is unavailable. Select and copy the token manually.", true);
    }
  });
  window.addEventListener("resize", () => {
    if (state.dashboard) drawTraffic(state.dashboard.traffic || []);
  });
  window.setInterval(() => {
    if (!document.hidden && !$("#app-view").hidden) refresh();
  }, 30000);

  initialize();
})();
