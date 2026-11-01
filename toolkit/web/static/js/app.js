// --- API helpers ---

async function apiGet(path) {
  const res = await fetch(path);
  if (!res.ok) {
    const body = await res.json().catch(() => ({ detail: res.statusText }));
    throw new Error(body.detail || `GET ${path} failed`);
  }
  return res.json();
}

async function apiPost(path, body) {
  const res = await fetch(path, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(body || {}),
  });
  if (!res.ok) {
    const respBody = await res.json().catch(() => ({ detail: res.statusText }));
    throw new Error(respBody.detail || `POST ${path} failed`);
  }
  return res.json();
}

async function apiPostForm(path, formData) {
  const res = await fetch(path, { method: "POST", body: formData });
  if (!res.ok) {
    const respBody = await res.json().catch(() => ({ detail: res.statusText }));
    throw new Error(respBody.detail || `POST ${path} failed`);
  }
  return res.json();
}

function escapeHtml(s) {
  return String(s).replace(/[&<>"']/g, (c) => ({
    "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;",
  }[c]));
}

// --- CASE LIST VIEW ---

async function renderCaseList() {
  const app = document.getElementById("app");
  app.innerHTML = `
    <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:14px">
      <h2 style="margin:0">Cases</h2>
      <button class="btn" id="new-case-btn">+ New Case</button>
    </div>
    <div id="case-list" class="case-card-list"><p>Loading…</p></div>
  `;
  document.getElementById("new-case-btn").addEventListener("click", () => {
    location.hash = "#/new";
  });

  try {
    const cases = await apiGet("/api/cases");
    const listEl = document.getElementById("case-list");
    if (cases.length === 0) {
      listEl.innerHTML = "<p>No cases yet.</p>";
      return;
    }
    listEl.innerHTML = cases.map((c) => `
      <a class="case-card" href="#/case/${c.case_id}">
        <div>
          <div class="case-card-title">${escapeHtml(c.description || "Untitled case")}</div>
          <div class="case-card-meta">Examiner: ${escapeHtml(c.examiner)} &middot; Opened ${escapeHtml(c.created_at)} &middot; ${c.evidence_count} evidence item(s)</div>
        </div>
        <span class="badge ${c.custody_ok ? "ok" : "broken"}">${c.custody_ok ? "Custody intact" : "Custody broken"}</span>
      </a>
    `).join("");
  } catch (err) {
    document.getElementById("case-list").innerHTML =
      `<div class="error-banner">${escapeHtml(err.message)}</div>`;
  }
}

// --- NEW CASE FORM ---

function renderNewCaseForm() {
  const app = document.getElementById("app");
  app.innerHTML = `
    <h2>New Case</h2>
    <form id="new-case-form" style="display:flex;flex-direction:column;gap:10px;max-width:400px">
      <label>Examiner<br><input type="text" name="examiner" required></label>
      <label>Description<br><input type="text" name="description"></label>
      <div id="new-case-error"></div>
      <div style="display:flex;gap:8px">
        <button type="submit" class="btn">Create Case</button>
        <button type="button" class="btn secondary" id="cancel-btn">Cancel</button>
      </div>
    </form>
  `;
  document.getElementById("cancel-btn").addEventListener("click", () => {
    location.hash = "#/";
  });
  document.getElementById("new-case-form").addEventListener("submit", async (e) => {
    e.preventDefault();
    const form = e.target;
    try {
      const result = await apiPost("/api/cases", {
        examiner: form.examiner.value,
        description: form.description.value,
      });
      location.hash = `#/case/${result.case_id}`;
    } catch (err) {
      document.getElementById("new-case-error").innerHTML =
        `<div class="error-banner">${escapeHtml(err.message)}</div>`;
    }
  });
}

// --- CASE DETAIL VIEW ---

let activeTab = "overview";

async function renderCaseDetail(caseId) {
  const app = document.getElementById("app");
  app.innerHTML = "<p>Loading case…</p>";

  let detail, verify;
  try {
    [detail, verify] = await Promise.all([
      apiGet(`/api/cases/${caseId}`),
      apiGet(`/api/cases/${caseId}/verify`).catch(() => null),
    ]);
  } catch (err) {
    app.innerHTML = `<div class="error-banner">${escapeHtml(err.message)}</div>`;
    return;
  }

  app.innerHTML = caseDetailShell(detail, verify);
  wireCaseDetailEvents(caseId, detail);
  await renderTab(caseId, detail, activeTab);
}

function stepStatusFor(detail, verify) {
  const hasEvidence = detail.evidence.length > 0;
  const hasAnalysis = detail.evidence.some((e) => e._analyzed);
  return {
    acquire: hasEvidence ? "done" : "pending",
    analyze: hasAnalysis ? "done" : "pending",
    report: "pending",
    verify: verify ? (verify.custody_ok ? "done" : "failed") : "pending",
  };
}

function caseDetailShell(detail, verify) {
  const steps = stepStatusFor(detail, verify);
  const evidenceCount = detail.evidence.length;
  return `
    <p><a href="#/">&larr; All cases</a></p>
    <div class="status-ribbon">
      <div class="cell">CUSTODY&nbsp; <span class="value ${verify && verify.custody_ok ? "ok" : "warn"}">${verify ? (verify.custody_ok ? "● INTACT" : "● BROKEN") : "—"}</span></div>
      <div class="cell">EXAMINER&nbsp; <span class="value">${escapeHtml(detail.examiner)}</span></div>
      <div class="cell">EVIDENCE&nbsp; <span class="value">${evidenceCount} item(s)</span></div>
      <div class="cell">OPENED&nbsp; <span class="value">${escapeHtml(detail.created_at)}</span></div>
    </div>

    <div class="step-tracker">
      <div class="step ${steps.acquire === "done" ? "done" : ""}">1. Acquire</div>
      <div class="step ${steps.analyze === "done" ? "done" : ""}">2. Analyze</div>
      <div class="step ${steps.report === "done" ? "done" : ""}">3. Report</div>
      <div class="step ${steps.verify === "done" ? "done" : steps.verify === "failed" ? "failed" : ""}">4. Verify</div>
    </div>

    <div class="case-file-panel" style="margin-bottom:16px">
      <h3>Acquire Evidence</h3>
      <form id="acquire-form" style="display:flex;flex-wrap:wrap;gap:10px;align-items:end">
        <label>File<br><input type="file" name="file" required></label>
        <label>Platform<br>
          <select name="platform">
            <option value="ardupilot">ArduPilot (dataflash/telemetry)</option>
            <option value="dji">DJI (header metadata only)</option>
            <option value="px4">PX4 (ULog)</option>
            <option value="remote_controller">Remote Controller (not implemented)</option>
            <option value="mobile_app">Mobile App (not implemented)</option>
          </select>
        </label>
        <label>Description<br><input type="text" name="description"></label>
        <button type="submit" class="btn">Acquire</button>
      </form>
      <div id="acquire-error"></div>
    </div>

    <div style="display:flex;gap:8px;margin-bottom:10px">
      <button class="btn" id="analyze-btn" ${evidenceCount === 0 ? "disabled" : ""}>Analyze All</button>
      <button class="btn secondary" id="verify-btn">Re-verify Custody</button>
    </div>
    <div id="action-error"></div>

    <div class="tabs">
      <button class="tab-button" data-tab="overview">Overview</button>
      <button class="tab-button" data-tab="timeline">Timeline</button>
      <button class="tab-button" data-tab="map">Map</button>
      <button class="tab-button" data-tab="carved">Carved Media</button>
      <button class="tab-button" data-tab="custody">Custody Log</button>
      <button class="tab-button" data-tab="report">Report</button>
    </div>
    <div id="tab-panel" class="tab-panel"><p>Loading…</p></div>
  `;
}

function wireCaseDetailEvents(caseId, detail) {
  document.getElementById("acquire-form").addEventListener("submit", async (e) => {
    e.preventDefault();
    const form = e.target;
    const fd = new FormData();
    fd.append("file", form.file.files[0]);
    fd.append("platform", form.platform.value);
    fd.append("examiner", detail.examiner);
    fd.append("description", form.description.value);
    try {
      await apiPostForm(`/api/cases/${caseId}/evidence`, fd);
      await renderCaseDetail(caseId);
    } catch (err) {
      document.getElementById("acquire-error").innerHTML =
        `<div class="error-banner">${escapeHtml(err.message)}</div>`;
    }
  });

  document.getElementById("analyze-btn").addEventListener("click", async () => {
    try {
      await apiPost(`/api/cases/${caseId}/analyze`, { examiner: detail.examiner });
      await renderCaseDetail(caseId);
    } catch (err) {
      document.getElementById("action-error").innerHTML =
        `<div class="error-banner">${escapeHtml(err.message)}</div>`;
    }
  });

  document.getElementById("verify-btn").addEventListener("click", async () => {
    await renderCaseDetail(caseId);
  });

  document.querySelectorAll(".tab-button").forEach((btn) => {
    btn.addEventListener("click", async () => {
      activeTab = btn.dataset.tab;
      document.querySelectorAll(".tab-button").forEach((b) => b.classList.remove("active"));
      btn.classList.add("active");
      await renderTab(caseId, detail, activeTab);
    });
  });
  const initialBtn = document.querySelector(`.tab-button[data-tab="${activeTab}"]`);
  if (initialBtn) initialBtn.classList.add("active");
}

async function renderTab(caseId, detail, tab) {
  const panel = document.getElementById("tab-panel");
  if (tab === "overview") {
    await renderOverviewTab(panel, caseId, detail);
  } else if (tab === "timeline") {
    await renderTimelineTab(panel, caseId, detail);
  } else if (tab === "map") {
    await renderMapTab(panel, caseId, detail);
  } else if (tab === "carved") {
    await renderCarvedTab(panel, caseId, detail);
  } else if (tab === "custody") {
    await renderCustodyTab(panel, caseId, detail);
  } else if (tab === "report") {
    await renderReportTab(panel, caseId, detail);
  } else {
    panel.innerHTML = "<p>Unknown tab.</p>";
  }
}

async function renderOverviewTab(panel, caseId, detail) {
  if (detail.evidence.length === 0) {
    panel.innerHTML = "<p>No evidence acquired yet.</p>";
    return;
  }
  panel.innerHTML = "<p>Loading analysis…</p>";
  const rows = [];
  for (const ev of detail.evidence) {
    try {
      const result = await apiGet(`/api/cases/${caseId}/evidence/${ev.evidence_id}/analysis`);
      rows.push({ ev, result, error: null });
    } catch (err) {
      rows.push({ ev, result: null, error: err.message });
    }
  }

  panel.innerHTML = rows.map(({ ev, result, error }) => `
    <div class="case-file-panel" style="margin-bottom:12px">
      <h3>${escapeHtml(ev.original_filename)} <span style="font-weight:normal;color:var(--muted)">(${escapeHtml(ev.platform)})</span></h3>
      ${error ? `<p>${escapeHtml(error)}</p>` : overviewResultBody(result)}
    </div>
  `).join("");
}

// Single source of truth for the airspace-disclaimer text on the frontend:
// rather than hardcoding it, pull the exact string the backend appended to
// `result.warnings` (see AIRSPACE_DISCLAIMER in toolkit/service.py) by
// matching on a distinctive substring. Returns "" if not present.
function airspaceDisclaimerFrom(result) {
  const warnings = (result && result.warnings) || [];
  const match = warnings.find((w) => w.includes("static snapshot"));
  return match ? `<p class="warn">${escapeHtml(match)}</p>` : "";
}

function overviewResultBody(result) {
  if (!result.implemented) {
    return `<p>Not implemented for this platform. ${result.warnings.map(escapeHtml).join("<br>")}</p>`;
  }
  const summaryEntries = Object.entries(result.flight_summary || {});
  const incursionCount = (result.flight_summary || {}).airspace_incursions || 0;
  const incursionEvents = incursionCount > 0
    ? (result.events || []).filter((e) => e.event_type === "AIRSPACE_INCURSION")
    : [];
  return `
    <p>${result.events.length} timeline events, ${result.flight_path.length} flight-path points${result.partial ? " (partial coverage)" : ""}.</p>
    ${summaryEntries.length ? `
      <table class="ledger">
        <tbody>
          ${summaryEntries.map(([k, v]) => `<tr><td>${escapeHtml(k)}</td><td>${escapeHtml(v)}</td></tr>`).join("")}
        </tbody>
      </table>` : ""}
    ${incursionEvents.length ? `
      <div class="incursion">
        <p><strong>Airspace / no-fly-zone incursions:</strong></p>
        <ul>
          ${incursionEvents.map((e) => {
            const extra = e.extra || {};
            return `<li>${escapeHtml(extra.zone_name || "unknown zone")} — entry ${escapeHtml(extra.entry_ts || e.timestamp_utc)}, exit ${escapeHtml(extra.exit_ts || "—")}</li>`;
          }).join("")}
        </ul>
        ${airspaceDisclaimerFrom(result)}
      </div>` : ""}
    ${result.warnings.length ? `<p style="color:var(--muted)">${result.warnings.map(escapeHtml).join("<br>")}</p>` : ""}
  `;
}

// --- ROUTER ---

function route() {
  const hash = location.hash || "#/";
  const caseMatch = hash.match(/^#\/case\/([^/]+)$/);
  if (hash === "#/" || hash === "") {
    renderCaseList();
  } else if (hash === "#/new") {
    renderNewCaseForm();
  } else if (caseMatch) {
    renderCaseDetail(caseMatch[1]);
  } else {
    renderCaseList();
  }
}

// --- TIMELINE TAB ---

const ANOMALY_EVENT_TYPES = new Set(["ALTITUDE_ANOMALY"]);

async function renderTimelineTab(panel, caseId, detail) {
  if (detail.evidence.length === 0) {
    panel.innerHTML = "<p>No evidence acquired yet.</p>";
    return;
  }
  panel.innerHTML = "<p>Loading timeline…</p>";

  let allEvents = [];
  for (const ev of detail.evidence) {
    try {
      const result = await apiGet(`/api/cases/${caseId}/evidence/${ev.evidence_id}/analysis`);
      allEvents = allEvents.concat(result.events.map((e) => ({ ...e, _source_file: ev.original_filename })));
    } catch (err) {
      // No analysis yet for this evidence item — skip it in the timeline.
    }
  }

  if (allEvents.length === 0) {
    panel.innerHTML = "<p>No timeline events yet — analyze evidence first.</p>";
    return;
  }

  allEvents.sort((a, b) => a.timestamp_utc.localeCompare(b.timestamp_utc));

  panel.innerHTML = `
    <table class="ledger">
      <thead>
        <tr><th>Time (UTC)</th><th>Type</th><th>Description</th><th>Source</th></tr>
      </thead>
      <tbody>
        ${allEvents.map((e) => `
          <tr class="${ANOMALY_EVENT_TYPES.has(e.event_type) ? "anomaly" : ""}">
            <td>${escapeHtml(e.timestamp_utc)}</td>
            <td>${escapeHtml(e.event_type)}</td>
            <td>${escapeHtml(e.description)}</td>
            <td>${escapeHtml(e._source_file)}</td>
          </tr>
        `).join("")}
      </tbody>
    </table>
  `;
}

// --- MAP TAB ---

async function renderMapTab(panel, caseId, detail) {
  const withPaths = [];
  for (const ev of detail.evidence) {
    try {
      const result = await apiGet(`/api/cases/${caseId}/evidence/${ev.evidence_id}/analysis`);
      if (result.flight_path && result.flight_path.length > 0) {
        withPaths.push({ ev, flightPath: result.flight_path, result });
      }
    } catch (err) {
      // Not analyzed yet — no path to show for this item.
    }
  }

  if (withPaths.length === 0) {
    panel.innerHTML = "<p>No flight path available yet — analyze evidence with GPS data first.</p>";
    return;
  }

  // Every user-facing surface that shows an incursion must carry the
  // illustrative-dataset disclaimer alongside it — this map tab draws
  // incursion segments/tooltips, so check whether any evidence item has
  // incursion events and, if so, prepend the (shared) disclaimer text.
  const anyIncursions = withPaths.some(({ result }) =>
    (result.events || []).some((e) => e.event_type === "AIRSPACE_INCURSION"));
  const mapDisclaimer = anyIncursions
    ? withPaths.map(({ result }) => airspaceDisclaimerFrom(result)).find((html) => html) || ""
    : "";

  panel.innerHTML = `${mapDisclaimer}<div id="map" style="height:420px;border:1px solid var(--border)"></div>`;

  const map = L.map("map");
  L.tileLayer("https://{s}.tile.openstreetmap.org/{z}/{x}/{y}.png", {
    attribution: "&copy; OpenStreetMap contributors",
  }).addTo(map);

  const allLatLngs = [];
  for (const { ev, flightPath, result } of withPaths) {
    const latLngs = flightPath.map((p) => [p.latitude, p.longitude]);
    L.polyline(latLngs, { color: "#3fd0ff", weight: 3 }).addTo(map);
    if (latLngs.length > 0) {
      L.circleMarker(latLngs[0], { color: "#7ee787", radius: 5 }).addTo(map).bindTooltip("Start");
      L.circleMarker(latLngs[latLngs.length - 1], { color: "#ff4d4d", radius: 5 }).addTo(map).bindTooltip("End");
    }
    allLatLngs.push(...latLngs);

    // Overlay any airspace-incursion segments in red, on top of the base
    // track. Incursion intervals come from AIRSPACE_INCURSION events'
    // `extra` dict (entry_ts/exit_ts); we find the flight-path points
    // whose timestamp falls within that interval (ISO-8601 strings sort
    // lexically, so plain string comparison works).
    const incursionEvents = (result.events || []).filter((e) => e.event_type === "AIRSPACE_INCURSION");
    for (const inc of incursionEvents) {
      const extra = inc.extra || {};
      const entryTs = extra.entry_ts;
      const exitTs = extra.exit_ts;
      if (!entryTs || !exitTs) continue;
      const segment = flightPath
        .filter((p) => p.timestamp_utc >= entryTs && p.timestamp_utc <= exitTs)
        .map((p) => [p.latitude, p.longitude]);
      if (segment.length > 1) {
        L.polyline(segment, { color: "#ff4d4d", weight: 5 })
          .addTo(map)
          .bindTooltip(`Incursion: ${extra.zone_name || "restricted zone"}`);
      }
    }
  }
  map.fitBounds(allLatLngs, { padding: [20, 20] });
}

// --- CARVED MEDIA TAB ---

function formatBytes(n) {
  if (n < 1024) return `${n} B`;
  if (n < 1024 * 1024) return `${(n / 1024).toFixed(1)} KB`;
  return `${(n / (1024 * 1024)).toFixed(1)} MB`;
}

function formatExif(exif) {
  if (!exif) return "—";
  const parts = [];
  if (exif.DateTimeOriginal) parts.push(exif.DateTimeOriginal);
  if (exif.GPSLatitude != null && exif.GPSLongitude != null) {
    parts.push(`${exif.GPSLatitude.toFixed(5)}, ${exif.GPSLongitude.toFixed(5)}`);
  }
  return parts.length ? parts.join(" · ") : "—";
}

async function renderCarvedTab(panel, caseId, detail) {
  panel.innerHTML = `
    <div class="case-file-panel" style="margin-bottom:16px">
      <h3>Carve Removable-Media Image</h3>
      <p style="font-family:var(--sans);font-size:11px;color:var(--muted);margin-top:-4px">
        Signature-based recovery of JPEG/PNG/MP4 files from a raw disk/SD-card image
        (no filesystem metadata — recovered files carry no name or deletion time,
        only whatever EXIF timing/location a carved JPEG happens to contain).
      </p>
      <form id="carve-form" style="display:flex;flex-wrap:wrap;gap:10px;align-items:end">
        <label>Raw image file<br><input type="file" name="file" required></label>
        <button type="submit" class="btn">Carve</button>
      </form>
      <div id="carve-error"></div>
      <div id="carve-status"></div>
    </div>
    <div id="carved-list"><p>Loading carved files…</p></div>
  `;

  document.getElementById("carve-form").addEventListener("submit", async (e) => {
    e.preventDefault();
    const form = e.target;
    const statusEl = document.getElementById("carve-status");
    const errorEl = document.getElementById("carve-error");
    errorEl.innerHTML = "";
    statusEl.innerHTML = "<p>Carving…</p>";
    const fd = new FormData();
    fd.append("file", form.file.files[0]);
    fd.append("examiner", detail.examiner);
    try {
      const carved = await apiPostForm(`/api/cases/${caseId}/carve`, fd);
      statusEl.innerHTML = `<p>Carved ${carved.length} file(s).</p>`;
      await renderCarvedList(caseId);
    } catch (err) {
      statusEl.innerHTML = "";
      errorEl.innerHTML = `<div class="error-banner">${escapeHtml(err.message)}</div>`;
    }
  });

  await renderCarvedList(caseId);
}

async function renderCarvedList(caseId) {
  const listEl = document.getElementById("carved-list");
  let files;
  try {
    files = await apiGet(`/api/cases/${caseId}/carved`);
  } catch (err) {
    listEl.innerHTML = `<div class="error-banner">${escapeHtml(err.message)}</div>`;
    return;
  }

  if (files.length === 0) {
    listEl.innerHTML = "<p>No carved media yet.</p>";
    return;
  }

  const images = files.filter((f) => f.file_type.startsWith("jpeg") || f.file_type.startsWith("png"));

  listEl.innerHTML = `
    ${images.length ? `
      <div class="carved-thumb-grid">
        ${images.map((f) => `
          <a class="carved-thumb" href="${f.download_url}" target="_blank" rel="noopener">
            <img src="${f.download_url}" alt="${escapeHtml(f.file_type)} carved file" loading="lazy">
            <div class="carved-thumb-caption">${escapeHtml(f.file_type)} &middot; ${formatBytes(f.size)}</div>
          </a>
        `).join("")}
      </div>
    ` : ""}
    <table class="ledger">
      <thead>
        <tr><th>Type</th><th>Size</th><th>Offset</th><th>SHA-256</th><th>EXIF</th><th>Source</th><th></th></tr>
      </thead>
      <tbody>
        ${files.map((f) => `
          <tr class="${f.file_type.endsWith("_truncated") ? "anomaly" : ""}">
            <td>${escapeHtml(f.file_type)}</td>
            <td>${formatBytes(f.size)}</td>
            <td>${f.offset}</td>
            <td style="font-family:var(--mono);font-size:10px">${escapeHtml(f.sha256.slice(0, 16))}&hellip;</td>
            <td>${escapeHtml(formatExif(f.exif))}</td>
            <td>${escapeHtml(f.source_filename || "—")}</td>
            <td><a class="btn secondary" href="${f.download_url}" target="_blank" rel="noopener">Download</a></td>
          </tr>
        `).join("")}
      </tbody>
    </table>
  `;
}

// --- CUSTODY LOG TAB ---

async function renderCustodyTab(panel, caseId, detail) {
  panel.innerHTML = "<p>Loading custody log…</p>";
  let entries;
  try {
    entries = await apiGet(`/api/cases/${caseId}/custody-log`);
  } catch (err) {
    panel.innerHTML = `<div class="error-banner">${escapeHtml(err.message)}</div>`;
    return;
  }

  panel.innerHTML = `
    <table class="ledger">
      <thead>
        <tr><th>#</th><th>Time (UTC)</th><th>Action</th><th>Actor</th><th>Detail</th><th>Entry Hash</th></tr>
      </thead>
      <tbody>
        ${entries.map((e) => `
          <tr>
            <td>${e.seq}</td>
            <td>${escapeHtml(e.timestamp)}</td>
            <td>${escapeHtml(e.action)}</td>
            <td>${escapeHtml(e.actor)}</td>
            <td>${escapeHtml(e.detail)}</td>
            <td style="font-family:var(--mono);font-size:10px">${escapeHtml(e.entry_hash.slice(0, 12))}&hellip;</td>
          </tr>
        `).join("")}
      </tbody>
    </table>
  `;
}

// --- REPORT TAB ---

async function renderReportTab(panel, caseId, detail) {
  panel.innerHTML = `
    <div class="case-file-panel">
      <h3>Forensic Report</h3>
      <button class="btn" id="generate-report-btn">Generate / Regenerate Report</button>
      <div id="report-status"></div>
      <div id="report-frame-wrap" style="margin-top:14px"></div>
    </div>
  `;

  document.getElementById("generate-report-btn").addEventListener("click", async () => {
    const status = document.getElementById("report-status");
    status.innerHTML = "<p>Generating…</p>";
    try {
      const result = await apiPost(`/api/cases/${caseId}/report`, { examiner: detail.examiner });
      status.innerHTML = result.skipped.length
        ? `<p style="color:var(--muted)">Skipped ${result.skipped.length} unanalyzed evidence item(s).</p>`
        : "";
      if (result.pdf_url) {
        status.innerHTML += `<p><a class="btn" href="${result.pdf_url}" target="_blank" rel="noopener">Download PDF</a></p>`;
      }
      showReportFrame(caseId);
    } catch (err) {
      status.innerHTML = `<div class="error-banner">${escapeHtml(err.message)}</div>`;
    }
  });

  // If a report already exists, show it immediately without requiring a click.
  try {
    const res = await fetch(`/api/cases/${caseId}/report`, { method: "HEAD" });
    if (res.ok) {
      showReportFrame(caseId);
      const pdfRes = await fetch(`/api/cases/${caseId}/report.pdf`, { method: "HEAD" });
      if (pdfRes.ok) {
        document.getElementById("report-status").innerHTML =
          `<p><a class="btn" href="/api/cases/${caseId}/report.pdf" target="_blank" rel="noopener">Download PDF</a></p>`;
      }
    }
  } catch (err) {
    // No report yet — leave the "Generate" prompt as-is.
  }
}

function showReportFrame(caseId) {
  document.getElementById("report-frame-wrap").innerHTML =
    `<iframe src="/api/cases/${caseId}/report" style="width:100%;height:600px;border:1px solid var(--border)"></iframe>`;
}

window.addEventListener("hashchange", route);
window.addEventListener("DOMContentLoaded", route);
