"use strict";

const MAX_FILE_SIZE = 5 * 1024 * 1024;
const severityNames = { danger: "DANGER", warning: "WARNING", pending: "PENDING", info: "INFO", clear: "CLEAR" };
const fixAliases = {
  "play integrity": "play integrity",
  "play integrity api": "play integrity",
  "su": "native root",
  "root": "native root",
  "attestation": "tee",
  "keymint": "keymint keystore",
  "keystore": "keymint keystore",
  "keystore2": "keymint keystore",
  "keymint keystore": "keymint keystore",
  "avc": "selinux avc",
  "selinux avc": "selinux avc",
  "zygote": "zygote runtime",
  "zygote runtime": "zygote runtime",
  "system server": "systemserver",
  "systemserver": "systemserver",
  "modules": "module diagnostics",
  "module diagnostics": "module diagnostics",
  "verified boot": "bootloader",
  "adb": "adb runtime",
  "dangerous packages": "dangerous apps",
  "vpn": "network risk",
  "properties": "system properties"
};

const els = {
  file: document.getElementById("fileInput"),
  drop: document.getElementById("dropZone"),
  text: document.getElementById("reportText"),
  inputInfo: document.getElementById("inputInfo"),
  message: document.getElementById("message"),
  inputPanel: document.querySelector(".input-panel"),
  analyze: document.getElementById("analyzeButton"),
  analyzeLabel: document.getElementById("analyzeLabel"),
  empty: document.getElementById("analysisEmpty"),
  loading: document.getElementById("analysisLoading"),
  loadingLabel: document.getElementById("loadingLabel"),
  results: document.getElementById("results"),
  scoreRing: document.getElementById("scoreRing"),
  scoreValue: document.getElementById("scoreValue"),
  riskTitle: document.getElementById("riskTitle"),
  riskText: document.getElementById("riskText"),
  stats: document.getElementById("stats"),
  reportMeta: document.getElementById("reportMeta"),
  actionPlan: document.getElementById("actionPlan"),
  copy: document.getElementById("copyPlanButton"),
  copyLabel: document.getElementById("copyLabel"),
  copyStatus: document.getElementById("copyStatus"),
  findingList: document.getElementById("findingList"),
  repairSearch: document.getElementById("repairSearch"),
  repairGrid: document.getElementById("repairGrid"),
  repairCount: document.getElementById("repairCount"),
  adbSnapshotCmd: document.getElementById("adbSnapshotCmd"),
  copySnapshot: document.getElementById("copySnapshotButton"),
  copySnapshotLabel: document.getElementById("copySnapshotLabel"),
  snapshotCopyStatus: document.getElementById("snapshotCopyStatus"),
  methodSearch: document.getElementById("methodSearch"),
  methodsGrid: document.getElementById("methodsGrid"),
  methodCount: document.getElementById("methodCount")
};

let currentReport = null;
let currentPlan = [];
let currentMessage = null;
let copyFeedback = null;
let snapshotCopyFeedback = null;
let inputFile = null;
let busyStage = "";
let operationId = 0;
let findingFilter = "problem";
let repairFilter = "all";
let methodFilter = "all";
const reducedMotion = window.matchMedia("(prefers-reduced-motion: reduce)");
let currentLang = (() => {
  try { return localStorage.getItem("hideroot-language") === "en" ? "en" : "ru"; }
  catch (_) { return "ru"; }
})();

function t(key, values = {}) {
  const template = UI_TEXT[currentLang]?.[key] ?? UI_TEXT.ru[key] ?? key;
  return template.replace(/\{(\w+)\}/g, (match, name) => {
    const value = values[name];
    return typeof value === "number" ? value.toLocaleString(currentLang === "en" ? "en-US" : "ru-RU") : value ?? match;
  });
}

function localizedMethod(method) {
  return currentLang === "en" && METHOD_EN[method.id] ? { ...method, ...METHOD_EN[method.id] } : method;
}

function localizedGuideItem(item) {
  return currentLang === "en" && REPAIR_GUIDE_EN[item.id] ? { ...item, ...REPAIR_GUIDE_EN[item.id] } : item;
}

function localizedFinding(finding, report) {
  const localized = { ...finding };
  if (report.format === "demo" && currentLang === "en") Object.assign(localized, DEMO_EN[finding.name]);
  if (Array.isArray(finding.integrityLevels)) {
    const levels = finding.integrityLevels;
    localized.verdict = levels.length ? t("integrityPassed", { levels: levels.join(", ") }) : t("integrityFailed");
    localized.headline = t(levels.includes("DEVICE") ? "integrityDevicePassed" : "integrityDeviceFailed");
  }
  if (typeof finding.matchCount === "number") {
    localized.headline = t("genericHeadline");
    localized.quickFacts = t("genericMatches", { count: finding.matchCount });
  }
  return localized;
}

function formatName(format) {
  const keys = { demo: "demoFormat", duck: "duckFormat", "json/text": "jsonFormat", text: "textFormat" };
  return keys[format] ? t(keys[format]) : format || t("textFormat");
}

function setActiveButtons(selector, key, value) {
  document.querySelectorAll(selector).forEach(button => {
    const active = button.dataset[key] === value;
    button.classList.toggle("active", active);
    button.setAttribute("aria-pressed", String(active));
  });
}

function applyLanguage(lang, rerender = true) {
  const nextLang = lang === "en" ? "en" : "ru";
  if (currentLang !== nextLang) {
    copyFeedback = null;
    snapshotCopyFeedback = null;
  }
  currentLang = nextLang;
  document.documentElement.lang = currentLang;
  document.title = t("pageTitle");
  document.querySelectorAll("[data-i18n]").forEach(element => {
    element.textContent = t(element.dataset.i18n);
  });
  document.querySelectorAll("[data-i18n-html]").forEach(element => { element.innerHTML = t(element.dataset.i18nHtml); });
  ["placeholder", "aria-label", "content"].forEach(attribute => {
    document.querySelectorAll(`[data-i18n-${attribute}]`).forEach(element => {
      element.setAttribute(attribute, t(element.getAttribute(`data-i18n-${attribute}`)));
    });
  });
  setActiveButtons("[data-lang]", "lang", currentLang);
  try { localStorage.setItem("hideroot-language", currentLang); } catch (_) {}
  renderInputInfo();
  renderMessage();
  if (!currentReport) els.riskTitle.textContent = t("noData");
  if (rerender) {
    renderRepairGuide();
    renderMethods();
    if (currentReport) renderReport(currentReport, false);
  }
  renderBusyState();
  renderCopyFeedback();
  renderSnapshotCopyFeedback();
}

function escapeHTML(value) {
  return String(value ?? "").replace(/[&<>'"]/g, char => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", "'": "&#39;", '"': "&quot;" })[char]);
}

function icon(name, className = "") {
  return `<svg class="icon ${className}" aria-hidden="true"><use href="#icon-${name}"/></svg>`;
}

function scrollToElement(element, block = "start") {
  element.scrollIntoView({ behavior: reducedMotion.matches ? "auto" : "smooth", block });
}

// Let the loading skeleton paint before parsing or decoding a large local file.
function nextPaint() {
  return new Promise(resolve => requestAnimationFrame(() => requestAnimationFrame(resolve)));
}

function renderBusyState() {
  const busy = Boolean(busyStage);
  els.inputPanel.setAttribute("aria-busy", String(busy));
  els.loading.classList.toggle("hidden", !busy);
  els.empty.classList.toggle("hidden", busy || Boolean(currentReport));
  [els.file, els.drop, els.text, els.analyze, ...document.querySelectorAll("[data-demo]")].forEach(element => { element.disabled = busy; });
  els.analyzeLabel.textContent = t(busyStage === "analysis" ? "analyzing" : "analyze");
  els.loadingLabel.textContent = busy ? t(busyStage === "file" ? "readingReport" : "analyzingReport") : "";
}

function setBusy(stage = "") {
  busyStage = stage;
  renderBusyState();
}

function normalizeName(value) {
  return String(value || "").toLowerCase().replace(/[_-]+/g, " ").replace(/[^a-zа-яё0-9 ]/gi, "").replace(/\s+/g, " ").trim();
}

function getFix(name) {
  const normalized = normalizeName(name);
  const key = fixAliases[normalized] || normalized;
  if (FIXES[key]) {
    const base = { key, ...FIXES[key] };
    return currentLang === "en" && FIX_EN[key] ? { ...base, ...FIX_EN[key] } : base;
  }
  const fuzzyKey = Object.keys(FIXES).find(candidate => key.includes(candidate) || candidate.includes(key));
  if (!fuzzyKey) return null;
  const base = { key: fuzzyKey, ...FIXES[fuzzyKey] };
  return currentLang === "en" && FIX_EN[fuzzyKey] ? { ...base, ...FIX_EN[fuzzyKey] } : base;
}

function setMessage(key, type = "warning", values = {}) {
  currentMessage = key ? { key, type, values } : null;
  renderMessage();
}

function renderMessage() {
  const textErrors = ["needReport", "tooLarge", "notRecognized", "analysisError"];
  const fileErrors = ["fileTooLarge", "fileReadError"];
  els.text.setAttribute("aria-invalid", String(textErrors.includes(currentMessage?.key)));
  els.drop.classList.toggle("invalid", fileErrors.includes(currentMessage?.key));
  if (!currentMessage) {
    els.message.textContent = "";
    delete els.message.dataset.type;
    return;
  }
  const { key, type, values } = currentMessage;
  const localizedValues = { ...values };
  if ("format" in values) localizedValues.format = formatName(values.format);
  els.message.textContent = t(key, localizedValues);
  els.message.dataset.type = type;
}

function setCopyFeedback(key, type = "success") {
  copyFeedback = key ? { key, type } : null;
  renderCopyFeedback();
}

function renderCopyFeedback() {
  const copied = copyFeedback?.key === "planCopied";
  els.copy.classList.toggle("copied", copied);
  els.copy.disabled = !currentPlan.length;
  els.copyLabel.textContent = t(copied ? "copied" : "copy");
  els.copy.querySelector("use").setAttribute("href", copied ? "#icon-check" : "#icon-copy");
  els.copyStatus.textContent = copyFeedback ? t(copyFeedback.key) : "";
  els.copyStatus.dataset.type = copyFeedback?.type || "success";
}

function setSnapshotCopyFeedback(key, type = "success") {
  snapshotCopyFeedback = key ? { key, type } : null;
  renderSnapshotCopyFeedback();
}

function renderSnapshotCopyFeedback() {
  if (!els.copySnapshot) return;
  const copied = snapshotCopyFeedback?.key === "snapshotCopied";
  els.copySnapshot.classList.toggle("copied", copied);
  els.copySnapshotLabel.textContent = t(copied ? "copied" : "copySnapshot");
  els.copySnapshot.querySelector("use").setAttribute("href", copied ? "#icon-check" : "#icon-copy");
  els.snapshotCopyStatus.textContent = snapshotCopyFeedback ? t(snapshotCopyFeedback.key) : "";
  els.snapshotCopyStatus.dataset.type = snapshotCopyFeedback?.type || "success";
}

function renderInputInfo() {
  if (inputFile) {
    const digits = inputFile.size > 1024 ? 0 : 1;
    const size = (inputFile.size / 1024).toLocaleString(currentLang === "en" ? "en-US" : "ru-RU", { minimumFractionDigits: digits, maximumFractionDigits: digits });
    els.inputInfo.textContent = t("fileSize", { name: inputFile.name, size });
  } else {
    els.inputInfo.textContent = els.text.value ? t("characterCount", { count: els.text.value.length }) : t("noFile");
  }
}

function riskFromReport(report) {
  const findings = report.findings || [];
  const problemFindings = findings.filter(item => ["danger", "warning", "pending"].includes(item.severity));
  let score = problemFindings.reduce((sum, item) => sum + (item.severity === "danger" ? 27 : item.severity === "warning" ? 9 : 3), 0);
  if (report.countsParsed && report.counts) {
    score = Math.max(score, report.counts.danger * 27 + report.counts.warning * 7 + report.counts.pending * 3);
  }
  score = Math.min(100, score);
  if (score >= 76) return { score, title: t("riskCritical"), text: t("riskCriticalText"), color: "var(--red)" };
  if (score >= 46) return { score, title: t("riskHigh"), text: t("riskHighText"), color: "var(--red)" };
  if (score >= 20) return { score, title: t("riskMedium"), text: t("riskMediumText"), color: "var(--yellow)" };
  if (score > 0) return { score, title: t("riskLow"), text: t("riskLowText"), color: "var(--green)" };
  return { score: 0, title: t("riskClean"), text: t("riskCleanText"), color: "var(--green)" };
}

function getProblemFindings(report) {
  const order = { danger: 0, warning: 1, pending: 2, info: 3, clear: 4 };
  return (report.findings || []).filter(item => ["danger", "warning", "pending"].includes(item.severity)).sort((a, b) => {
    const fixA = getFix(a.name), fixB = getFix(b.name);
    return (order[a.severity] - order[b.severity]) || ((fixA?.priority ?? 9) - (fixB?.priority ?? 9));
  });
}

function buildPlan(report) {
  const plan = [];
  const seen = new Set();
  for (const finding of getProblemFindings(report)) {
    const fix = getFix(finding.name);
    const steps = fix?.steps?.length ? fix.steps : [t("genericStep")];
    for (const step of steps) {
      const plainKey = step.replace(/<[^>]+>/g, "").toLowerCase();
      if (seen.has(plainKey)) continue;
      seen.add(plainKey);
      plan.push({ html: step, source: finding.name, severity: finding.severity });
      if (plan.length >= 10) return plan;
    }
  }
  return plan;
}

function renderStats(counts) {
  const safe = { danger: 0, warning: 0, ready: 0, pending: 0, ...(counts || {}) };
  els.stats.innerHTML = [
    ["danger", t("statDanger")], ["warning", t("statWarning")], ["ready", t("statReady")], ["pending", t("statPending")]
  ].map(([key, label]) => `<div class="stat ${key}"><b>${Number(safe[key]) || 0}</b><span>${label}</span></div>`).join("");
}

function renderMeta(report) {
  const values = [
    [t("metaDevice"), report.device], [t("metaVersion"), report.appVersion], [t("metaTime"), report.reportTime], [t("metaFormat"), formatName(report.format)]
  ].filter(([, value]) => value);
  els.reportMeta.innerHTML = values.map(([label, value]) => `<span class="meta-item"><b>${escapeHTML(label)}:</b> ${escapeHTML(value)}</span>`).join("");
  els.reportMeta.classList.toggle("hidden", !values.length);
}

function renderPlan(report) {
  currentPlan = buildPlan(report);
  renderCopyFeedback();
  if (!currentPlan.length) {
    els.actionPlan.innerHTML = `<li class="empty-plan">${escapeHTML(t("planEmpty"))}</li>`;
    return;
  }
  els.actionPlan.innerHTML = currentPlan.map(item => `<li>${item.html}<small>${escapeHTML(t("source"))}: ${escapeHTML(item.source)} · ${severityNames[item.severity] || item.severity}</small></li>`).join("");
}

function relatedButtons(fix, findingName) {
  const normalized = normalizeName(findingName);
  const guideMatches = REPAIR_GUIDE.filter(item =>
    item.relatedFindings.includes(normalized) || (fix?.key && item.relatedFindings.includes(fix.key))
  );
  const methodBtns = (fix?.related || []).map(id => {
    const method = METHODS.find(item => item.id === id);
    const localized = method ? localizedMethod(method) : null;
    return localized ? `<button class="related-button" type="button" data-method-id="${escapeHTML(id)}">${escapeHTML(localized.title)}</button>` : "";
  });
  const guideBtns = guideMatches.map(item => {
    const localized = localizedGuideItem(item);
    return `<button class="related-button" type="button" data-guide-id="${escapeHTML(item.id)}">${escapeHTML(t("openInRepairGuide", { title: localized.title }))}</button>`;
  });
  const html = [...guideBtns, ...methodBtns].join("");
  return html ? `<div class="related-row">${html}</div>` : "";
}

function renderFindings(report, preserveState = true) {
  const openFindings = new Set(preserveState ? Array.from(els.findingList.querySelectorAll(".finding-card.open"), card => card.dataset.findingIndex) : []);
  const items = (report.findings || []).map((finding, index) => ({ finding, index }))
    .filter(({ finding }) => findingFilter === "all" || ["danger", "warning", "pending"].includes(finding.severity));
  if (!items.length) {
    const hasCleanChecks = findingFilter === "problem" && report.findings?.length;
    els.findingList.innerHTML = `<div class="findings-empty">
      ${icon(hasCleanChecks ? "shield" : "file")}
      <h4>${escapeHTML(t(hasCleanChecks ? "noProblemsTitle" : "noSections"))}</h4>
      ${hasCleanChecks ? `<p>${escapeHTML(t("noProblems"))}</p><button class="text-link" type="button" data-show-all>${escapeHTML(t("showAllChecks"))}${icon("arrow")}</button>` : ""}
    </div>`;
    return;
  }
  els.findingList.innerHTML = items.map(({ finding: sourceFinding, index }) => {
    const finding = localizedFinding(sourceFinding, report);
    const isOpen = openFindings.has(String(index));
    const severity = severityNames[finding.severity] ? finding.severity : "info";
    const fix = getFix(finding.name);
    const clean = severity === "clear" || severity === "info";
    const cleanKey = normalizeName(finding.name);
    const why = clean ? (currentLang === "en" ? CLEAN_EN[cleanKey] : CLEAN_NOTES[cleanKey]) : fix?.why;
    const guidance = !clean && fix?.steps?.length ? `<strong>${escapeHTML(t("whatToDo"))}</strong><ol>${fix.steps.map(step => `<li>${step}</li>`).join("")}</ol>` : "";
    const packages = finding.packages?.length ? `<p><strong>${escapeHTML(t("matches"))}:</strong> ${finding.packages.map(escapeHTML).join(" · ")}</p>` : "";
    return `<article class="finding-card ${severity}${isOpen ? " open" : ""}" data-finding-index="${index}">
      <button class="finding-summary" type="button" aria-expanded="${isOpen}" aria-controls="finding-body-${index}">
        <span class="severity-dot" aria-hidden="true"></span>
        <span class="finding-main"><b>${escapeHTML(finding.name)}</b><span>${escapeHTML(finding.verdict || finding.headline || t("sectionRecognized"))}</span></span>
        <span class="severity-label">${severityNames[severity]}</span>
        ${icon("chevron", "finding-chevron")}
      </button>
      <div class="finding-body" id="finding-body-${index}">
        ${finding.quickFacts ? `<p><strong>${escapeHTML(t("facts"))}:</strong> ${escapeHTML(finding.quickFacts)}</p>` : ""}
        ${finding.extra ? `<p><strong>${escapeHTML(t("details"))}:</strong> ${escapeHTML(finding.extra)}</p>` : ""}
        ${packages}
        ${why ? `<div class="finding-why">${why}</div>` : ""}
        ${guidance}
        ${!clean && !fix ? `<p>${escapeHTML(t("noExactRecipe"))}</p>` : ""}
        ${relatedButtons(fix, finding.name)}
      </div>
    </article>`;
  }).join("");
}

function renderReport(report, shouldScroll = true) {
  const preserveState = currentReport === report;
  if (!preserveState) copyFeedback = null;
  currentReport = report;
  const risk = riskFromReport(report);
  els.scoreValue.textContent = risk.score;
  els.scoreRing.style.setProperty("--score-angle", `${risk.score * 3.6}deg`);
  els.scoreRing.style.setProperty("--score-color", risk.color);
  els.riskTitle.textContent = risk.title;
  els.riskText.textContent = risk.text;
  renderStats(report.counts);
  renderMeta(report);
  renderPlan(report);
  renderFindings(report, preserveState);
  els.results.classList.remove("hidden");
  renderBusyState();
  if (shouldScroll) requestAnimationFrame(() => {
    if (currentReport !== report) return;
    els.results.focus({ preventScroll: true });
    scrollToElement(els.results);
  });
}

function clearResults() {
  currentReport = null;
  currentPlan = [];
  setCopyFeedback(null);
  els.results.classList.add("hidden");
  els.scoreValue.textContent = "0";
  els.scoreRing.style.setProperty("--score-angle", "0deg");
  els.riskTitle.textContent = t("noData");
  els.riskText.textContent = "";
  [els.stats, els.reportMeta, els.actionPlan, els.findingList].forEach(element => { element.replaceChildren(); });
  renderBusyState();
}

async function analyzeText() {
  if (busyStage) return;
  const operation = ++operationId;
  clearResults();
  setMessage("");
  const text = els.text.value.trim();
  if (!text) {
    setMessage("needReport", "error");
    els.text.focus();
    return;
  }
  if (new Blob([text]).size > MAX_FILE_SIZE) {
    setMessage("tooLarge", "error");
    return;
  }
  setBusy("analysis");
  try {
    await nextPaint();
    if (operation !== operationId) return;
    const report = parseDetectorReport(text);
    if (!report.findings.length) {
      setMessage("notRecognized", "error");
      return;
    }
    setMessage("recognizedReport", "success", { count: report.findings.length, format: report.format });
    renderReport(report);
  } catch (_) {
    if (operation === operationId) setMessage("analysisError", "error");
  } finally {
    if (operation === operationId) setBusy();
  }
}

async function loadFile(file) {
  if (!file) return;
  const operation = ++operationId;
  setBusy();
  clearResults();
  setMessage("");
  if (file.size > MAX_FILE_SIZE) {
    setMessage("fileTooLarge", "error");
    return;
  }
  setBusy("file");
  try {
    await nextPaint();
    if (operation !== operationId) return;
    const text = await file.text();
    if (operation !== operationId) return;
    els.text.value = text;
    inputFile = { name: file.name, size: file.size };
    renderInputInfo();
    setMessage("fileRead", "success");
  } catch (error) {
    if (operation === operationId) setMessage("fileReadError", "error", { error: error.message });
  } finally {
    if (operation === operationId) setBusy();
  }
}

function clearAnalyzer() {
  operationId++;
  setBusy();
  els.file.value = "";
  els.text.value = "";
  inputFile = null;
  renderInputInfo();
  clearResults();
  setMessage("");
}

function showExample() {
  operationId++;
  setBusy();
  const report = { ...EXAMPLE_REPORT, format: "demo" };
  setMessage("demoLoaded", "success");
  renderReport(report);
}

function plainText(html) {
  const temp = document.createElement("div");
  temp.innerHTML = html;
  return temp.textContent.trim();
}

async function copyTextWithFallback(text) {
  try {
    await navigator.clipboard.writeText(text);
    return true;
  } catch (_) {
    const helper = document.createElement("textarea");
    const focused = document.activeElement;
    helper.value = text;
    helper.className = "visually-hidden";
    document.body.appendChild(helper);
    helper.select();
    try {
      return document.execCommand("copy");
    } catch (_) {
      return false;
    } finally {
      helper.remove();
      focused?.focus({ preventScroll: true });
    }
  }
}

async function copyPlan() {
  if (!currentPlan.length) return setCopyFeedback("planIsEmpty", "warning");
  const report = currentReport;
  const language = currentLang;
  const text = currentPlan.map((item, index) => `${index + 1}. ${plainText(item.html)} [${item.source}]`).join("\n");
  const copied = await copyTextWithFallback(text);
  if (currentReport === report && currentLang === language) {
    setCopyFeedback(copied ? "planCopied" : "copyFailed", copied ? "success" : "error");
  }
}

async function copySnapshotCmd() {
  if (!els.adbSnapshotCmd) return;
  const language = currentLang;
  const copied = await copyTextWithFallback(els.adbSnapshotCmd.textContent.trim());
  if (currentLang === language) {
    setSnapshotCopyFeedback(copied ? "snapshotCopied" : "copyFailed", copied ? "success" : "error");
  }
}

function renderRepairGuide(animate = false) {
  if (!els.repairGrid) return;
  const openItems = new Set(Array.from(els.repairGrid.querySelectorAll(".method-card details[open]"), details => details.closest(".method-card").id));
  const term = els.repairSearch.value.trim().toLowerCase();
  const sevKeys = { critical: "sevCritical", high: "sevHigh", medium: "sevMedium" };
  const visible = REPAIR_GUIDE.filter(item => {
    const matchesFilter = repairFilter === "all" || item.category === repairFilter;
    const english = REPAIR_GUIDE_EN[item.id] || {};
    const haystack = `${item.title} ${item.symptom} ${item.cause} ${item.verifyCmds.join(" ")} ${item.healthyState} ${english.title || ""} ${english.symptom || ""} ${english.cause || ""}`.toLowerCase();
    return matchesFilter && (!term || haystack.includes(term));
  }).map(localizedGuideItem);
  els.repairGrid.classList.toggle("is-entering", animate);
  els.repairGrid.innerHTML = visible.length ? visible.map((item, index) => {
    const number = String(REPAIR_GUIDE.findIndex(entry => entry.id === item.id) + 1).padStart(2, "0");
    const sevLabel = t(sevKeys[item.severity] || "sevMedium");
    const verifyHtml = item.verifyCmds?.length ? `<div class="repair-block"><span class="repair-block-label">${escapeHTML(t("repairVerify"))}</span><div class="verify-cmds">${item.verifyCmds.map(cmd => `<code>${escapeHTML(cmd)}</code>`).join("")}</div></div>` : "";
    return `<article class="method-card" id="guide-${escapeHTML(item.id)}" style="--index: ${Math.min(index, 6)}" aria-labelledby="guide-title-${escapeHTML(item.id)}">
      <span class="method-index" aria-hidden="true">${number}</span>
      <div class="method-content">
        <div class="method-top"><h3 id="guide-title-${escapeHTML(item.id)}">${escapeHTML(item.title)}</h3><span class="sev-pill ${escapeHTML(item.severity)}">${escapeHTML(sevLabel)}</span></div>
        <p class="repair-symptom">${escapeHTML(item.symptom)}</p>
        <p class="repair-cause"><strong>${escapeHTML(t("repairCause"))}:</strong> ${item.cause}</p>
        <details${openItems.has(`guide-${item.id}`) ? " open" : ""}>
          <summary>${escapeHTML(t("repairOpenDetails"))}${icon("chevron")}</summary>
          ${verifyHtml}
          <div class="repair-block"><span class="repair-block-label">${escapeHTML(t("repairSteps"))}</span><ol>${item.steps.map(step => `<li>${step}</li>`).join("")}</ol></div>
          <p class="repair-healthy"><strong>${escapeHTML(t("repairHealthy"))}:</strong> ${escapeHTML(item.healthyState)}</p>
        </details>
      </div>
    </article>`;
  }).join("") : `<div class="search-empty">${icon("search")}<h3>${escapeHTML(t("repairEmptyTitle"))}</h3><p>${escapeHTML(t("repairEmptyText"))}</p><button class="text-link" type="button" data-reset-repair>${escapeHTML(t("resetRepair"))}${icon("arrow")}</button></div>`;
  els.repairCount.textContent = t("repairCount", { count: visible.length, total: REPAIR_GUIDE.length });
  document.querySelectorAll("[data-repair-count]").forEach(element => {
    const filter = element.dataset.repairCount;
    element.textContent = REPAIR_GUIDE.filter(item => filter === "all" || item.category === filter).length;
  });
}

function resetRepairGuide() {
  repairFilter = "all";
  els.repairSearch.value = "";
  setActiveButtons("#repairFilters button", "repairFilter", "all");
  renderRepairGuide(true);
  els.repairSearch.focus({ preventScroll: true });
}

function openRepairGuide(id) {
  repairFilter = "all";
  setActiveButtons("#repairFilters button", "repairFilter", "all");
  els.repairSearch.value = "";
  renderRepairGuide();
  const card = document.getElementById(`guide-${id}`);
  if (card) {
    card.classList.add("highlight");
    card.querySelector("details").open = true;
    card.querySelector("summary").focus({ preventScroll: true });
    scrollToElement(card, "center");
  }
}

function renderMethods(animate = false) {
  const openMethods = new Set(Array.from(els.methodsGrid.querySelectorAll(".method-card details[open]"), details => details.closest(".method-card").id));
  const term = els.methodSearch.value.trim().toLowerCase();
  const visible = METHODS.filter(method => {
    const matchesFilter = methodFilter === "all" || method.cats.includes(methodFilter);
    const english = METHOD_EN[method.id] || {};
    const haystack = `${method.title} ${method.desc} ${method.keys} ${method.tags.join(" ")} ${english.title || ""} ${english.desc || ""} ${(english.tags || []).join(" ")}`.toLowerCase();
    return matchesFilter && (!term || haystack.includes(term));
  }).map(localizedMethod);
  els.methodsGrid.classList.toggle("is-entering", animate);
  els.methodsGrid.innerHTML = visible.length ? visible.map((method, index) => {
    const number = String(METHODS.findIndex(item => item.id === method.id) + 1).padStart(2, "0");
    const level = method.level === "info" ? t("levelInfo") : method.level === "tools" ? t("levelTools") : method.level;
    return `<article class="method-card" id="method-${escapeHTML(method.id)}" style="--index: ${Math.min(index, 6)}" aria-labelledby="method-title-${escapeHTML(method.id)}">
      <span class="method-index" aria-hidden="true">${number}</span>
      <div class="method-content">
        <div class="method-top"><h3 id="method-title-${escapeHTML(method.id)}">${escapeHTML(method.title)}</h3><span class="level">${escapeHTML(level)}</span></div>
        <p class="method-desc">${escapeHTML(method.desc)}</p>
        <div class="tag-row">${method.tags.map(tag => `<span class="tag">${escapeHTML(tag)}</span>`).join("")}</div>
        <details${openMethods.has(`method-${method.id}`) ? " open" : ""}><summary>${escapeHTML(t("setupDetails"))}${icon("chevron")}</summary><ol>${method.steps.map(step => `<li>${step}</li>`).join("")}</ol></details>
      </div>
    </article>`;
  }).join("") : `<div class="search-empty">${icon("search")}<h3>${escapeHTML(t("methodsEmptyTitle"))}</h3><p>${escapeHTML(t("methodsEmptyText"))}</p><button class="text-link" type="button" data-reset-methods>${escapeHTML(t("resetMethods"))}${icon("arrow")}</button></div>`;
  els.methodCount.textContent = t("methodCount", { count: visible.length, total: METHODS.length });
  document.querySelectorAll("[data-filter-count]").forEach(element => {
    const filter = element.dataset.filterCount;
    element.textContent = METHODS.filter(method => filter === "all" || method.cats.includes(filter)).length;
  });
}

function resetMethods() {
  methodFilter = "all";
  els.methodSearch.value = "";
  setActiveButtons("#methodFilters button", "filter", "all");
  renderMethods(true);
  els.methodSearch.focus({ preventScroll: true });
}

function openMethod(id) {
  methodFilter = "all";
  setActiveButtons("#methodFilters button", "filter", "all");
  const foundMethod = METHODS.find(item => item.id === id);
  els.methodSearch.value = foundMethod ? localizedMethod(foundMethod).title : "";
  renderMethods();
  const card = document.getElementById(`method-${id}`);
  if (card) {
    card.classList.add("highlight");
    card.querySelector("details").open = true;
    card.querySelector("summary").focus({ preventScroll: true });
    scrollToElement(card, "center");
  }
}

// The static app uses a tiny, frame-batched equivalent of a motion value.
// Only primary buttons participate; touch and reduced-motion users opt out.
function setupButtonMotion() {
  const finePointer = window.matchMedia("(hover: hover) and (pointer: fine)");
  document.querySelectorAll(".button.primary").forEach(button => {
    let frame = 0;
    let x = 0, y = 0;
    const update = () => {
      if (frame) return;
      frame = requestAnimationFrame(() => {
        frame = 0;
        button.style.setProperty("--magnetic-x", `${x}px`);
        button.style.setProperty("--magnetic-y", `${y}px`);
      });
    };
    button.addEventListener("pointermove", event => {
      if (reducedMotion.matches || !finePointer.matches || button.disabled) return;
      const rect = button.getBoundingClientRect();
      x = Math.max(-3, Math.min(3, (event.clientX - rect.left - rect.width / 2) * .06));
      y = Math.max(-2, Math.min(2, (event.clientY - rect.top - rect.height / 2) * .08));
      update();
    });
    button.addEventListener("pointerleave", () => { x = 0; y = 0; update(); });
  });
}

els.drop.addEventListener("click", () => els.file.click());
els.file.addEventListener("change", () => loadFile(els.file.files[0]));
["dragenter", "dragover"].forEach(type => els.drop.addEventListener(type, event => { event.preventDefault(); els.drop.classList.add("dragging"); }));
["dragleave", "drop"].forEach(type => els.drop.addEventListener(type, event => { event.preventDefault(); els.drop.classList.remove("dragging"); }));
els.drop.addEventListener("drop", event => loadFile(event.dataTransfer.files[0]));
els.analyze.addEventListener("click", analyzeText);
document.getElementById("clearButton").addEventListener("click", clearAnalyzer);
document.querySelectorAll("[data-demo]").forEach(button => button.addEventListener("click", showExample));
els.copy.addEventListener("click", copyPlan);
els.text.addEventListener("input", () => {
  operationId++;
  setBusy();
  inputFile = null;
  els.file.value = "";
  clearResults();
  setMessage("");
  renderInputInfo();
});

document.querySelector(".language-switch").addEventListener("click", event => {
  const button = event.target.closest("button[data-lang]");
  if (button && button.dataset.lang !== currentLang) applyLanguage(button.dataset.lang);
});

document.getElementById("findingFilters").addEventListener("click", event => {
  const button = event.target.closest("button[data-severity]");
  if (!button) return;
  findingFilter = button.dataset.severity;
  setActiveButtons("#findingFilters button", "severity", findingFilter);
  if (currentReport) renderFindings(currentReport);
});
els.findingList.addEventListener("click", event => {
  if (event.target.closest("[data-show-all]")) {
    findingFilter = "all";
    setActiveButtons("#findingFilters button", "severity", findingFilter);
    renderFindings(currentReport);
    document.querySelector('#findingFilters [data-severity="all"]').focus({ preventScroll: true });
    return;
  }
  const relatedGuide = event.target.closest("[data-guide-id]");
  if (relatedGuide) return openRepairGuide(relatedGuide.dataset.guideId);
  const related = event.target.closest("[data-method-id]");
  if (related) return openMethod(related.dataset.methodId);
  const summary = event.target.closest(".finding-summary");
  if (!summary) return;
  const card = summary.closest(".finding-card");
  card.classList.toggle("open");
  summary.setAttribute("aria-expanded", String(card.classList.contains("open")));
});

els.copySnapshot?.addEventListener("click", copySnapshotCmd);
els.repairSearch?.addEventListener("input", () => renderRepairGuide());
els.repairGrid?.addEventListener("click", event => {
  if (event.target.closest("[data-reset-repair]")) resetRepairGuide();
});
document.getElementById("repairFilters")?.addEventListener("click", event => {
  const button = event.target.closest("button[data-repair-filter]");
  if (!button) return;
  repairFilter = button.dataset.repairFilter;
  setActiveButtons("#repairFilters button", "repairFilter", repairFilter);
  renderRepairGuide(true);
});

els.methodSearch.addEventListener("input", () => renderMethods());
els.methodsGrid.addEventListener("click", event => {
  if (event.target.closest("[data-reset-methods]")) resetMethods();
});
document.getElementById("methodFilters").addEventListener("click", event => {
  const button = event.target.closest("button[data-filter]");
  if (!button) return;
  methodFilter = button.dataset.filter;
  setActiveButtons("#methodFilters button", "filter", methodFilter);
  renderMethods(true);
});

applyLanguage(currentLang, false);
renderRepairGuide(true);
renderMethods(true);
setupButtonMotion();
