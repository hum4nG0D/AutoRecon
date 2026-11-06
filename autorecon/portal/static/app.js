"use strict";

const api = {
  async get(path) {
    const response = await fetch(path, { credentials: "same-origin" });
    return readResponse(response);
  },
  async post(path, body) {
    const response = await fetch(path, {
      method: "POST",
      credentials: "same-origin",
      headers: { "Content-Type": "application/json", "X-CSRF-Token": state.csrfToken },
      body: JSON.stringify(body),
    });
    return readResponse(response);
  },
};

async function readResponse(response) {
  const type = response.headers.get("content-type") || "";
  const data = type.includes("application/json") ? await response.json() : { message: await response.text() };
  if (!response.ok) {
    throw new Error(data.error || data.message || `Request failed (${response.status})`);
  }
  return data;
}

const state = {
  csrfToken: "",
  targets: [],
  jobs: [],
  catalog: [],
  selectedTarget: null,
  selectedJob: null,
  selectedTask: null,
  selectedFile: { reports: null, scans: null },
  files: { reports: [], scans: [] },
  proof: { confirmed: 0, total: 0, findings: [] },
  tasks: [],
  view: "reports",
  primaryView: "results",
  events: null,
  eventSequence: 0,
  fileRequest: { reports: 0, scans: 0 },
  filesRequest: 0,
  downloadUrls: { reports: null, scans: null },
  refreshTimer: null,
  refreshing: false,
  authPluginBeforeForce: null,
};

const $ = (id) => document.getElementById(id);

function element(tag, className, content) {
  const node = document.createElement(tag);
  if (className) node.className = className;
  if (content !== undefined) node.textContent = String(content);
  return node;
}

function formatTime(value) {
  if (!value) return "";
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) return "";
  return date.toLocaleString(undefined, { month: "short", day: "numeric", hour: "numeric", minute: "2-digit" });
}

function humanStatus(status) {
  return String(status || "unknown").replaceAll("_", " ");
}

function statusBadge(status) {
  const badge = element("span", "status-badge", humanStatus(status));
  badge.dataset.status = String(status || "").toLowerCase();
  return badge;
}

function showError(id, message) {
  const node = $(id);
  node.textContent = message;
  node.hidden = !message;
}

let toastTimer;
function toast(message) {
  const node = $("toast");
  node.textContent = message;
  node.hidden = false;
  clearTimeout(toastTimer);
  toastTimer = setTimeout(() => { node.hidden = true; }, 4500);
}

function setPrimaryView(view) {
  state.primaryView = view;
  for (const name of ["results", "runs", "tasks"]) {
    const active = name === view;
    $(name + "-page").hidden = !active;
    const button = $("nav-" + name);
    button.classList.toggle("is-active", active);
    if (active) button.setAttribute("aria-current", "page");
    else button.removeAttribute("aria-current");
  }
}

function toggleTargets() {
  const collapsed = $("workspace").classList.toggle("targets-collapsed");
  const button = $("toggle-targets");
  button.textContent = collapsed ? "›" : "‹";
  button.setAttribute("aria-expanded", String(!collapsed));
  button.setAttribute("aria-label", collapsed ? "Expand targets" : "Collapse targets");
}

async function refreshAll() {
  if (state.refreshing) return;
  state.refreshing = true;
  try {
    const [targets, jobs] = await Promise.all([api.get("/api/targets"), api.get("/api/jobs")]);
    state.targets = Array.isArray(targets.targets) ? targets.targets : [];
    state.jobs = Array.isArray(jobs.jobs) ? jobs.jobs : [];
    renderTargets();
    renderJobs();
    if (state.selectedTarget) await refreshFiles();
    if (state.selectedJob && state.jobs.some((job) => job.id === state.selectedJob)) {
      await refreshTasks();
    } else if (state.jobs.length) {
      const active = state.jobs.find((job) => ["running", "queued"].includes(job.status));
      selectJob((active || state.jobs[0]).id);
    } else {
      if (state.events) state.events.close();
      state.events = null;
      state.selectedJob = null;
      state.tasks = [];
      renderJobPicker();
      renderTasks();
    }
  } catch (error) {
    toast(error.message);
  } finally {
    state.refreshing = false;
  }
}

function renderTargets() {
  $("targets-count").textContent = state.targets.length;
  const tabs = $("target-tabs");
  const focusedId = document.activeElement?.dataset?.targetId;
  tabs.replaceChildren();
  for (const target of state.targets) {
    const tab = element("button", "target-tab", target.name || target.id);
    tab.type = "button";
    tab.dataset.targetId = target.id;
    if (target.id === state.selectedTarget) tab.setAttribute("aria-current", "true");
    tab.classList.toggle("is-active", target.id === state.selectedTarget);
    tab.title = target.relative_path || target.name || target.id;
    tab.addEventListener("click", () => selectTarget(target.id, true));
    tabs.append(tab);
  }
  if (focusedId) [...tabs.children].find((tab) => tab.dataset.targetId === focusedId)?.focus({ preventScroll: true });
  if (!state.targets.length) {
    state.selectedTarget = null;
    $("empty-state").hidden = false;
    $("target-content").hidden = true;
    return;
  }
  if (!state.targets.some((target) => target.id === state.selectedTarget)) {
    selectTarget(state.targets[0].id);
  } else {
    updateTargetHeading();
  }
}

function updateTargetHeading() {
  const target = state.targets.find((entry) => entry.id === state.selectedTarget);
  if (!target) return;
  $("target-title").textContent = target.name || target.id;
  $("target-subtitle").textContent = "TARGET";
  $("target-status").textContent = target.status ? humanStatus(target.status) : (target.updated_at ? `Updated ${formatTime(target.updated_at)}` : "");
  for (const tab of $("target-tabs").children) {
    const active = tab.dataset.targetId === state.selectedTarget;
    tab.classList.toggle("is-active", active);
    if (active) tab.setAttribute("aria-current", "true");
    else tab.removeAttribute("aria-current");
  }
}

async function selectTarget(id, navigate = false) {
  if (navigate) setPrimaryView("results");
  if (state.selectedTarget === id) return;
  state.selectedTarget = id;
  state.selectedFile = { reports: null, scans: null };
  state.fileRequest.reports++;
  state.fileRequest.scans++;
  for (const kind of ["reports", "scans"]) {
    if (state.downloadUrls[kind]) URL.revokeObjectURL(state.downloadUrls[kind]);
    state.downloadUrls[kind] = null;
  }
  $("empty-state").hidden = true;
  $("target-content").hidden = false;
  updateTargetHeading();
  $("report-count").textContent = "0";
  $("scan-count").textContent = "0";
  $("findings-count").textContent = "0";
  state.proof = { confirmed: 0, total: 0, findings: [] };
  $("report-document").replaceChildren(element("p", "quiet", "Loading reports…"));
  $("scan-document").textContent = "Loading scans…";
  $("download-link").hidden = true;
  $("scan-download-link").hidden = true;
  await refreshFiles();
}

async function refreshFiles() {
  const id = state.selectedTarget;
  if (!id) return;
  const request = ++state.filesRequest;
  try {
    const data = await api.get(`/api/targets/${encodeURIComponent(id)}/files`);
    api.get(`/api/targets/${encodeURIComponent(id)}/proof`).then((proof) => {
      if (state.selectedTarget !== id) return;
      state.proof = proof && Array.isArray(proof.findings)
        ? proof
        : { confirmed: 0, total: 0, findings: [] };
      renderFindings();
    }).catch(() => {
      if (state.selectedTarget !== id) return;
      state.proof = { confirmed: 0, total: 0, findings: [] };
      renderFindings();
    });
    if (state.selectedTarget !== id || request !== state.filesRequest) return;
    const previousReports = state.files.reports;
    const previousScans = state.files.scans;
    state.files.reports = Array.isArray(data.reports) ? data.reports : [];
    state.files.scans = Array.isArray(data.scans) ? data.scans : [];
    $("report-count").textContent = state.files.reports.length;
    $("scan-count").textContent = state.files.scans.length;
    renderFileList("reports");
    renderFileList("scans");
    const preferred = state.files.reports.find((file) => file.path === state.selectedFile.reports) ||
      state.files.reports.find((file) => /(^|\/)ai-report\.md$/i.test(file.path)) || state.files.reports[0];
    if (preferred) {
      if (state.selectedFile.reports !== preferred.path ||
        previousReports.find((file) => file.path === preferred.path)?.size !== preferred.size) selectFile("reports", preferred);
    } else {
      $("report-document").replaceChildren(element("p", "quiet", "No reports for this target yet."));
    }
    const scan = state.files.scans.find((file) => file.path === state.selectedFile.scans) || state.files.scans[0];
    if (scan) {
      if (state.selectedFile.scans !== scan.path ||
        previousScans.find((file) => file.path === scan.path)?.size !== scan.size) selectFile("scans", scan);
    } else {
      $("scan-document").textContent = "No raw scans for this target yet.";
    }
  } catch (error) {
    if (state.selectedTarget !== id || request !== state.filesRequest) return;
    $("report-document").replaceChildren(element("p", "quiet", error.message));
    $("scan-document").textContent = error.message;
  }
}

function renderFileList(kind) {
  const container = $(kind === "reports" ? "report-files" : "scan-files");
  const focusedPath = document.activeElement?.dataset?.fileKind === kind ? document.activeElement.dataset.filePath : null;
  container.replaceChildren();
  if (!state.files[kind].length) {
    container.append(element("p", "quiet", "No files yet."));
    return;
  }
  for (const file of state.files[kind]) {
    const button = element("button", "file-item", file.label || file.path);
    button.type = "button";
    button.dataset.fileKind = kind;
    button.dataset.filePath = file.path;
    button.title = file.path;
    button.classList.toggle("is-active", state.selectedFile[kind] === file.path);
    button.addEventListener("click", () => selectFile(kind, file));
    container.append(button);
  }
  if (focusedPath) {
    [...container.children].find((button) => button.dataset.filePath === focusedPath)?.focus({ preventScroll: true });
  }
}

function renderFindings() {
  const list = $("findings-list");
  const count = $("findings-count");
  const summary = $("findings-summary");
  const title = $("findings-title");
  const findings = Array.isArray(state.proof.findings) ? state.proof.findings : [];
  count.textContent = String(findings.length);
  list.replaceChildren();
  if (!findings.length) {
    title.textContent = "No findings yet";
    summary.hidden = true;
    list.append(element("p", "quiet", "Proof checks have not produced findings for this target yet."));
    return;
  }
  const order = { critical: 0, high: 1, medium: 2, low: 3 };
  const sorted = [...findings].sort((a, b) =>
    (order[a.severity] ?? 9) - (order[b.severity] ?? 9) ||
    String(a.status).localeCompare(String(b.status)));
  title.textContent = "Proof-of-exploit findings";
  summary.hidden = false;
  summary.textContent = `${state.proof.confirmed} confirmed of ${state.proof.total}`;
  for (const finding of sorted) {
    const item = element("div", "finding-item");
    const head = element("div", "finding-head");
    const badge = element("span", "status-badge", finding.status || "unknown");
    badge.dataset.status = finding.status || "unknown";
    head.append(badge);
    head.append(element("strong", "", `${finding.severity || "?"} · ${finding.check || finding.module || "?"} (${finding.cwe || "?"})`));
    item.append(head);
    item.append(element("span", "finding-target", `${finding.url || "?"} — parameter \`${finding.parameter || "?"}\``));
    if (finding.evidence_file) item.append(element("span", "finding-source", finding.evidence_file));
    list.append(item);
  }
}

async function selectFile(kind, file) {
  const id = state.selectedTarget;
  const request = ++state.fileRequest[kind];
  state.selectedFile[kind] = file.path;
  renderFileList(kind);
  const report = kind === "reports";
  const documentNode = $(report ? "report-document" : "scan-document");
  $(report ? "document-name" : "scan-document-name").textContent = file.label || file.path;
  documentNode.textContent = "Loading file…";
  const download = $(report ? "download-link" : "scan-download-link");
  download.hidden = true;
  try {
    const query = new URLSearchParams({ target: id, path: file.path });
    const data = await api.get(`/api/file?${query}`);
    if (state.selectedTarget !== id || request !== state.fileRequest[kind]) return;
    if (report && data.kind === "markdown" && typeof data.html === "string") {
      // The server renders Markdown locally with raw HTML and unsafe links disabled.
      documentNode.innerHTML = data.html;
      highlightSeverities(documentNode);
    } else if (report) {
      const pre = element("pre", "raw-output", data.content || "");
      documentNode.replaceChildren(pre);
    } else {
      documentNode.textContent = data.content || "";
    }
    if (data.truncated) {
      if (report) documentNode.prepend(element("p", "preview-notice", "Preview limited to the first 1 MB of this file."));
      else documentNode.textContent += "\n\n[Preview limited to the first 1 MB of this file.]";
    }
    if (state.downloadUrls[kind]) URL.revokeObjectURL(state.downloadUrls[kind]);
    const type = data.kind === "markdown" ? "text/markdown;charset=utf-8" : "text/plain;charset=utf-8";
    state.downloadUrls[kind] = URL.createObjectURL(new Blob([data.content || ""], { type }));
    download.href = state.downloadUrls[kind];
    download.download = file.path.split("/").pop() || "result.txt";
    download.hidden = false;
  } catch (error) {
    if (state.selectedTarget === id && request === state.fileRequest[kind]) documentNode.textContent = error.message;
  }
}

function highlightSeverities(documentNode) {
  for (const node of documentNode.querySelectorAll("h1,h2,h3,h4,th,td")) {
    const value = node.textContent.trim().toLowerCase();
    const match = value.match(/^(?:severity\s*:\s*)?(critical|high|medium|low|info)(?:\b|\s*[:—-])/);
    if (match) node.classList.add(`severity-${match[1]}`);
  }
}

function selectView(view) {
  state.view = view;
  for (const name of ["reports", "scans", "findings"]) {
    const active = name === view;
    $(name + "-view").hidden = !active;
    const tab = $(name + "-tab");
    tab.classList.toggle("is-active", active);
    tab.setAttribute("aria-selected", String(active));
    tab.tabIndex = active ? 0 : -1;
  }
}

function renderJobs() {
  const activeJobs = state.jobs.filter((job) => ["queued", "running", "cancelling"].includes(job.status));
  $("jobs-count").textContent = activeJobs.length;
  renderJobPicker();
  const list = $("job-list");
  const focusedJob = document.activeElement?.dataset?.jobId;
  const focusedAction = document.activeElement?.dataset?.jobAction;
  list.replaceChildren();
  if (!activeJobs.length) {
    list.append(element("p", "quiet", "No scans are running. Start a new scan to watch it here."));
    return;
  }
  for (const job of activeJobs) {
    const item = element("div", "job-item");
    const button = element("button", "job-card");
    button.type = "button";
    button.dataset.jobId = job.id;
    button.dataset.jobAction = "select";
    button.classList.toggle("is-active", job.id === state.selectedJob);
    const top = element("span", "job-top");
    top.append(element("span", "job-name", job.target), statusBadge(job.status));
    button.append(top, element("span", "job-meta", formatTime(job.created_at) || "Just now"));
    button.addEventListener("click", () => {
      setPrimaryView("tasks");
      selectJob(job.id);
    });
    item.append(button);
    if (["queued", "running"].includes(job.status) && job.source !== "cli") {
      const actions = element("div", "job-actions");
      actions.append(element("span", "job-meta", job.ai ? "AI review on" : ""));
      const cancel = element("button", "cancel-button", "Cancel run");
      cancel.type = "button";
      cancel.dataset.jobId = job.id;
      cancel.dataset.jobAction = "cancel";
      cancel.addEventListener("click", () => cancelJob(job.id));
      actions.append(cancel);
      item.append(actions);
    }
    list.append(item);
  }
  if (focusedJob) {
    [...list.querySelectorAll("[data-job-id]")]
      .find((node) => node.dataset.jobId === focusedJob && node.dataset.jobAction === focusedAction)
      ?.focus({ preventScroll: true });
  }
}

function renderJobPicker() {
  const select = $("task-run-select");
  select.replaceChildren();
  const placeholder = element("option", "", "Choose a run");
  placeholder.value = "";
  select.append(placeholder);
  for (const job of state.jobs) {
    const option = element("option", "", `${job.target} · ${humanStatus(job.status)}${job.created_at ? " · " + formatTime(job.created_at) : ""}`);
    option.value = job.id;
    select.append(option);
  }
  select.value = state.selectedJob || "";
  select.disabled = !state.jobs.length;
}

async function selectJob(id) {
  if (state.selectedJob === id && state.events) return;
  if (state.events) state.events.close();
  state.events = null;
  state.selectedJob = id;
  state.selectedTask = null;
  state.tasks = [];
  state.eventSequence = 0;
  renderJobs();
  renderTasks();
  await refreshTasks();
  if (state.selectedJob === id) watchJob(id);
}

async function refreshTasks() {
  const id = state.selectedJob;
  if (!id) return;
  try {
    const data = await api.get(`/api/jobs/${encodeURIComponent(id)}`);
    if (state.selectedJob !== id) return;
    state.tasks = Array.isArray(data.tasks) ? data.tasks : [];
    if (data.job) {
      const index = state.jobs.findIndex((job) => job.id === id);
      if (index >= 0) state.jobs[index] = data.job;
      renderJobs();
    }
    renderTasks();
  } catch (error) {
    if (state.selectedJob === id) $("task-tree").replaceChildren(element("p", "quiet", error.message));
  }
}

function renderTasks() {
  const tree = $("task-tree");
  const focusedTask = document.activeElement?.dataset?.taskId;
  tree.replaceChildren();
  $("tasks-count").textContent = state.tasks.length;
  if (!state.selectedJob) {
    const empty = element("div", "task-empty");
    empty.append(element("p", "quiet", "Select a run to view its tasks."));
    const action = element("button", "button button-secondary", "View current runs");
    action.type = "button";
    action.addEventListener("click", () => setPrimaryView("runs"));
    empty.append(action);
    tree.append(empty);
    return;
  }
  if (!state.tasks.length) {
    const job = state.jobs.find((entry) => entry.id === state.selectedJob);
    tree.append(element("p", "quiet", job?.error || "Waiting for scan tasks…"));
    return;
  }
  const groups = new Map();
  for (const task of state.tasks) {
    const key = [task.target || "Target", task.category || "Other"].join(" · ");
    if (!groups.has(key)) groups.set(key, []);
    groups.get(key).push(task);
  }
  for (const [name, tasks] of groups) {
    const group = element("section", "task-group");
    group.append(element("span", "task-group-title", name));
    for (const task of tasks) {
      const item = element("button", "task-item");
      item.type = "button";
      item.dataset.taskId = task.task_id;
      item.classList.toggle("is-active", task.task_id === state.selectedTask);
      const indicator = element("span", "task-indicator");
      indicator.dataset.status = String(task.status || "").toLowerCase();
      const copy = element("span", "task-copy");
      copy.append(element("span", "task-title", task.plugin || task.category || "Task"));
      copy.append(element("span", "task-subtitle", [task.service, humanStatus(task.status)].filter(Boolean).join(" · ")));
      item.append(indicator, copy);
      item.addEventListener("click", () => {
        state.selectedTask = task.task_id;
        renderTasks();
      });
      group.append(item);
    }
    tree.append(group);
  }
  if (focusedTask) {
    [...tree.querySelectorAll("[data-task-id]")]
      .find((node) => node.dataset.taskId === focusedTask)
      ?.focus({ preventScroll: true });
  }
  if (state.selectedTask) {
    const task = state.tasks.find((entry) => entry.task_id === state.selectedTask);
    if (task) {
      const detail = element("div", "task-detail");
      detail.append(element("strong", "", task.plugin || "Task"));
      for (const [label, value] of [
        ["Status", humanStatus(task.status)],
        ["Service", task.service],
        ["Started", formatTime(task.started_at)],
        ["Finished", formatTime(task.finished_at)],
        ["Detail", task.detail],
      ]) {
        if (value) detail.append(element("p", "", `${label}: ${value}`));
      }
      tree.append(detail);
    }
  }
}

function watchJob(id) {
  if (state.events) state.events.close();
  if (!window.EventSource) return;
  const query = new URLSearchParams({ job_id: id, after: String(state.eventSequence) });
  const source = new EventSource(`/api/events?${query}`);
  state.events = source;
  source.addEventListener("scan", (message) => {
    if (state.selectedJob !== id) return;
    try {
      const event = JSON.parse(message.data);
      const sequence = Number(event.sequence);
      if (Number.isFinite(sequence)) {
        if (sequence <= state.eventSequence) return;
        state.eventSequence = sequence;
      }
      updateTaskFromEvent(event);
      scheduleRefresh();
    } catch (_) {
      scheduleRefresh();
    }
  });
  source.onerror = () => { scheduleRefresh(); };
}

function updateTaskFromEvent(event) {
  if (!event.task_id) return;
  const index = state.tasks.findIndex((task) => task.task_id === event.task_id);
  const status = {
    task_queued: "queued",
    task_started: "running",
    task_completed: "completed",
    task_failed: "failed",
    task_skipped: "skipped",
    task_cancelled: "cancelled",
  }[event.event];
  const fields = {
    task_id: event.task_id,
    target: event.target,
    category: event.category,
    plugin: event.plugin,
    service: event.service,
    status,
    detail: event.detail,
    started_at: event.event === "task_started" ? event.timestamp : undefined,
    finished_at: ["task_completed", "task_failed", "task_skipped", "task_cancelled"].includes(event.event) ? event.timestamp : undefined,
  };
  if (index >= 0) {
    state.tasks[index] = { ...state.tasks[index], ...Object.fromEntries(Object.entries(fields).filter(([, value]) => value !== undefined)) };
  } else {
    state.tasks.push(fields);
  }
  renderTasks();
}

function scheduleRefresh() {
  if (state.refreshTimer) return;
  state.refreshTimer = setTimeout(() => {
    state.refreshTimer = null;
    refreshAll();
  }, 400);
}

async function cancelJob(id) {
  try {
    await api.post(`/api/jobs/${encodeURIComponent(id)}/cancel`, {});
    toast("Run cancelled.");
    await refreshAll();
  } catch (error) {
    toast(error.message);
  }
}

const GROUP_ORDER = ["Port scans", "Web", "SMB, directory & RPC", "DNS", "Remote access", "Mail", "Databases", "Network services", "Other services", "Reports"];

function pluginGroup(plugin) {
  if (plugin.kind === "port") return "Port scans";
  if (plugin.kind === "report") return "Reports";
  const tags = new Set(plugin.tags || []);
  const has = (...names) => names.some((name) => tags.has(name));
  if (has("http", "https", "web")) return "Web";
  if (has("active-directory", "smb", "ldap", "kerberos", "netbios", "rpc")) return "SMB, directory & RPC";
  if (has("dns")) return "DNS";
  if (has("ssh", "rdp", "ftp", "telnet", "vnc")) return "Remote access";
  if (has("email", "smtp", "imap", "pop3")) return "Mail";
  if (has("databases", "mysql", "postgres", "mssql", "mongodb", "redis")) return "Databases";
  if (has("nfs", "snmp", "rsync", "sip", "ntp")) return "Network services";
  return "Other services";
}

function standardPlugins() {
  return state.catalog.filter((plugin) => Array.isArray(plugin.tags) && plugin.tags.includes("default"));
}

function currentMode() {
  return $("scan-form").querySelector('input[name="scan-mode"]:checked')?.value || "standard";
}

function updateMode() {
  $("custom-options").hidden = currentMode() !== "custom";
}

function updateSelectedCount() {
  const panel = $("plugin-choices");
  const inputs = [...panel.querySelectorAll("input[type=checkbox]")];
  const selected = inputs.filter((input) => input.checked).length;
  $("selected-count").textContent = `${selected} selected`;
  for (const group of panel.querySelectorAll(".plugin-group")) {
    const members = [...group.querySelectorAll("input[type=checkbox]")];
    group.querySelector(".group-count").textContent = `${members.filter((input) => input.checked).length}/${members.length}`;
  }
}

function filterPlugins() {
  const query = $("plugin-search").value.trim().toLowerCase();
  let matching = 0;
  for (const group of $("plugin-choices").querySelectorAll(".plugin-group")) {
    let groupMatches = 0;
    for (const label of group.querySelectorAll(".plugin-choice")) {
      const show = !query || label.dataset.search.includes(query);
      label.hidden = !show;
      if (show) groupMatches++;
    }
    group.hidden = groupMatches === 0;
    if (query && groupMatches) group.open = true;
    matching += groupMatches;
  }
  $("plugin-no-match").hidden = matching !== 0;
}

function renderCatalog() {
  $("standard-plugin-count").textContent = `(${standardPlugins().length})`;
  const panel = $("plugin-choices");
  panel.replaceChildren();
  const groups = new Map(GROUP_ORDER.map((name) => [name, []]));
  for (const plugin of state.catalog) groups.get(pluginGroup(plugin)).push(plugin);
  for (const name of GROUP_ORDER) {
    const plugins = groups.get(name).sort((a, b) => (a.name || a.slug).localeCompare(b.name || b.slug));
    if (!plugins.length) continue;
    const group = element("details", "plugin-group");
    group.open = name === "Port scans";
    const summary = element("summary");
    summary.append(element("span", "", name), element("span", "group-count"));
    group.append(summary);
    const grid = element("div", "plugin-grid");
    for (const plugin of plugins) {
      const label = element("label", "plugin-choice");
      label.title = plugin.description || plugin.slug;
      label.dataset.search = [plugin.name, plugin.slug, plugin.description, ...(plugin.tags || [])].join(" ").toLowerCase();
      const input = element("input");
      input.type = "checkbox";
      input.value = plugin.slug;
      input.dataset.kind = plugin.kind;
      input.checked = Array.isArray(plugin.tags) && plugin.tags.includes("default");
      input.defaultChecked = input.checked;
      input.addEventListener("change", updateSelectedCount);
      label.append(input, element("span", "", plugin.name || plugin.slug));
      grid.append(label);
    }
    group.append(grid);
    panel.append(group);
  }
  ensureAuthPlugin();
  updateSelectedCount();
}

function ensureAuthPlugin() {
  const input = [...$("plugin-choices").querySelectorAll("input[type=checkbox]")]
    .find((node) => node.value === "ssh-authenticated-host-checks");
  if (!input) return false;
  const authenticated = $("scan-auth").checked;
  if (authenticated && !input.disabled) {
    state.authPluginBeforeForce = input.checked;
    input.checked = true;
    input.disabled = true;
  } else if (!authenticated && input.disabled) {
    input.disabled = false;
    input.checked = state.authPluginBeforeForce === null ? input.defaultChecked : state.authPluginBeforeForce;
    state.authPluginBeforeForce = null;
  }
  updateSelectedCount();
  return true;
}

function openDialog() {
  showError("scan-error", "");
  $("scan-dialog").showModal();
  $("scan-targets").focus();
}

async function submitScan(event) {
  event.preventDefault();
  const authenticated = $("scan-auth").checked;
  const hasAuthPlugin = ensureAuthPlugin();
  const targets = [...new Set($("scan-targets").value.split(/\r?\n/).map((line) => line.trim()).filter(Boolean))];
  const plugins = currentMode() === "standard"
    ? standardPlugins().map((plugin) => plugin.slug)
    : [...$("plugin-choices").querySelectorAll("input:checked")].map((node) => node.value);
  if (authenticated && hasAuthPlugin && !plugins.includes("ssh-authenticated-host-checks")) plugins.push("ssh-authenticated-host-checks");
  const selected = new Set(plugins);
  const hasPortPlugin = state.catalog.some((plugin) => plugin.kind === "port" && selected.has(plugin.slug));
  const sshUser = $("ssh-user").value.trim();
  const sshKey = $("ssh-key").value.trim();
  if (!targets.length) return showError("scan-error", "Enter at least one target.");
  if (!hasPortPlugin) return showError("scan-error", "Select at least one port scan plugin.");
  if (authenticated && !hasAuthPlugin) return showError("scan-error", "The SSH authenticated host checks plugin is unavailable.");
  if (authenticated && (!sshUser || !sshKey)) return showError("scan-error", "Enter an SSH username and local private key path for an authenticated scan.");
  if (!state.csrfToken) return showError("scan-error", "The portal is not connected. Refresh and try again.");
  showError("scan-error", "");
  const submit = $("submit-scan");
  submit.disabled = true;
  submit.textContent = "Starting…";
  const created = [];
  const failures = [];
  for (const target of targets) {
    const body = {
      target,
      ai: $("scan-ai").checked,
      include_plugins: plugins,
      linpeas: authenticated,
    };
    if (authenticated) {
      body.ssh_user = sshUser;
      body.ssh_identity = sshKey;
    }
    try {
      const result = await api.post("/api/jobs", body);
      created.push(result.job);
    } catch (error) {
      failures.push({ target, message: error.message });
    }
  }
  submit.disabled = false;
  submit.textContent = "Start scan";
  if (created.length) {
    toast(`Started ${created.length} scan${created.length === 1 ? "" : "s"}.`);
    await refreshAll();
    if (created[0]?.id) {
      setPrimaryView("tasks");
      selectJob(created[0].id);
    }
  }
  if (failures.length) {
    $("scan-targets").value = failures.map((failure) => failure.target).join("\n");
    showError("scan-error", failures.map((failure) => `${failure.target}: ${failure.message}`).join("\n"));
  } else {
    $("scan-form").reset();
    $("auth-fields").hidden = true;
    state.authPluginBeforeForce = null;
    for (const input of $("plugin-choices").querySelectorAll("input[type=checkbox]")) {
      input.checked = input.defaultChecked;
      input.disabled = false;
    }
    $("plugin-search").value = "";
    filterPlugins();
    updateSelectedCount();
    updateMode();
    $("scan-dialog").close();
  }
}

async function start() {
  for (const name of ["results", "runs", "tasks"]) $("nav-" + name).addEventListener("click", () => setPrimaryView(name));
  $("toggle-targets").addEventListener("click", toggleTargets);
  $("task-run-select").addEventListener("change", (event) => {
    if (event.target.value) selectJob(event.target.value);
  });
  $("new-scan-button").addEventListener("click", openDialog);
  $("empty-new-scan").addEventListener("click", openDialog);
  $("close-dialog").addEventListener("click", () => $("scan-dialog").close());
  $("cancel-dialog").addEventListener("click", () => $("scan-dialog").close());
  for (const input of $("scan-form").querySelectorAll('input[name="scan-mode"]')) input.addEventListener("change", updateMode);
  $("plugin-search").addEventListener("input", filterPlugins);
  $("scan-auth").addEventListener("change", () => {
    $("auth-fields").hidden = !$("scan-auth").checked;
    ensureAuthPlugin();
  });
  $("scan-form").addEventListener("submit", submitScan);
  $("refresh-button").addEventListener("click", refreshAll);
  $("reports-tab").addEventListener("click", () => selectView("reports"));
  $("scans-tab").addEventListener("click", () => selectView("scans"));
  $("findings-tab").addEventListener("click", () => selectView("findings"));
  for (const name of ["reports", "scans"]) {
    $(name + "-tab").addEventListener("keydown", (event) => {
      if (!["ArrowLeft", "ArrowRight", "Home", "End"].includes(event.key)) return;
      event.preventDefault();
      const next = event.key === "Home" ? "reports" : event.key === "End" ? "scans" : (name === "reports" ? "scans" : "reports");
      selectView(next);
      $(next + "-tab").focus();
    });
  }
  try {
    const [config, catalog] = await Promise.all([api.get("/api/config"), api.get("/api/catalog")]);
    state.csrfToken = config.csrf_token || "";
    state.catalog = Array.isArray(catalog.plugins) ? catalog.plugins : [];
    renderCatalog();
  } catch (error) {
    $("plugin-choices").replaceChildren(element("p", "quiet", error.message));
    toast(error.message);
  }
  await refreshAll();
  setInterval(refreshAll, 8000);
}

start();
