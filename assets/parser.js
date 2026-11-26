/* ============================================================
   HideRoot 2026 — парсер отчётов DUCK Detector
   На вход: текст отчёта. На выход: {device, appVersion, reportTime,
   counts, findings:[{severity,name,verdict,headline,quickFacts,packages,extra}]}
   integrityLevels и matchCount хранят данные для локализуемых пояснений UI.
   Поддерживает DUCK Detector и распространённые текстовые/JSON-логи.
   Работает и в браузере (глобал), и в Node (module.exports) для тестов.
   ============================================================ */
"use strict";

const SEV_MAP = {
  "DANGER": "danger",
  "WARNING": "warning",
  "CLEAR": "clear",
  "READY": "clear",
  "INFO": "info",
  "PENDING": "pending"
};
const SEV_ORDER = { danger: 0, warning: 1, pending: 2, info: 3, clear: 4 };

function parseDuckReport(text) {
  const lines = String(text || "").split(/\r?\n/);
  const out = {
    device: "", appVersion: "", reportTime: "",
    counts: { danger: 0, warning: 0, ready: 0, pending: 0 },
    countsParsed: false,
    findings: []
  };
  const byName = new Map();

  let current = null;      // текущий finding
  let currentSub = "";     // текущий подраздел [Detected Packages] и т.п.
  let inTopFindings = false;
  let topFindingsCurrent = null;

  const headerRe = /^\s*\[(?:[✖▲✔ℹ·])?\s*(DANGER|WARNING|CLEAR|READY|INFO|PENDING)\]\s*(.+?)\s*$/i;
  const verdictRe = /^\s*Verdict\s*:\s*(.+?)\s*$/;
  const headlineRe = /^\s*Headline\s*:\s*(.+?)\s*$/;
  const quickRe = /^\s*Quick Facts\s*:\s*(.+?)\s*$/;
  const subRe = /^\s*\[([A-Za-z&][A-Za-z0-9 &/+-]*)\]\s*$/;
  const bulletRe = /^\s*[•·]\s+(.+?)\s*$/;

  for (let i = 0; i < lines.length; i++) {
    const line = lines[i];

    if (/^\s*Target Device\s*:\s*(.+)$/.test(line)) out.device = line.replace(/^\s*Target Device\s*:\s*/, "").trim();
    else if (/^\s*App Version\s*:\s*(.+)$/.test(line)) out.appVersion = line.replace(/^\s*App Version\s*:\s*/, "").trim();
    else if (/^\s*Report Time\s*:\s*(.+)$/.test(line)) out.reportTime = line.replace(/^\s*Report Time\s*:\s*/, "").trim();

    // Счётчики из Executive Summary: "[✖] Danger   : 2"
    const cnt = line.match(/^\s*\[[✖▲✔·]\]\s*(Danger|Warning|Ready|Pending)\s*:\s*(\d+)\s*$/i);
    if (cnt) {
      const k = cnt[1].toLowerCase();
      out.counts[k === "ready" ? "ready" : k] = parseInt(cnt[2], 10);
      out.countsParsed = true;
      continue;
    }

    if (/^\s*TOP FINDINGS\s*$/.test(line)) { inTopFindings = true; continue; }

    const h = line.match(headerRe);
    if (h) {
      const sev = SEV_MAP[h[1].toUpperCase()] || "info";
      const name = h[2].trim();
      if (name.toLowerCase() === "danger") continue; // служебная строка счётчика
      inTopFindings = false;

      if (!byName.has(name)) {
        const f = { severity: sev, name, verdict: "", headline: "", quickFacts: "", packages: [], extra: "" };
        byName.set(name, f);
        out.findings.push(f);
      } else {
        const f = byName.get(name);
        // более строгая severity побеждает
        if (SEV_ORDER[sev] < SEV_ORDER[f.severity]) f.severity = sev;
      }
      current = byName.get(name);
      currentSub = "";
      continue;
    }

    if (inTopFindings) continue; // содержимое TOP FINDINGS не дублируем

    if (!current) continue;

    const v = line.match(verdictRe);
    if (v) { if (!current.verdict) current.verdict = v[1]; currentSub = ""; continue; }
    const hl = line.match(headlineRe);
    if (hl) { if (!current.headline) current.headline = hl[1]; continue; }
    const qf = line.match(quickRe);
    if (qf) { if (!current.quickFacts) current.quickFacts = qf[1]; currentSub = ""; continue; }

    const sub = line.match(subRe);
    if (sub) { currentSub = sub[1].toLowerCase(); continue; }

    const b = line.match(bulletRe);
    if (b) {
      const txt = b[1];
      if (currentSub.includes("detected packages") || currentSub.includes("matched root managers") || currentSub.includes("detected")) {
        if (current.packages.length < 12 && txt.length < 200) current.packages.push(txt);
      } else if (currentSub.includes("impact") || currentSub.includes("highlight")) {
        if (!current.extra && txt.length < 400) current.extra = txt;
      }
      continue;
    }
  }

  // headerRe требует severity внутри скобок, поэтому обычные подразделы вида
  // [Boot], [Native] и [Impact] сюда не попадают. Фильтруем только пустые имена,
  // чтобы не потерять реальные проверки Bootloader / Native Root.
  out.findings = out.findings.filter(f => f.name && f.name.trim());
  out.findings.sort((a, b) => SEV_ORDER[a.severity] - SEV_ORDER[b.severity]);

  // Если счётчики не распознаны — посчитать по findings
  if (!out.countsParsed) {
    out.counts = { danger: 0, warning: 0, ready: 0, pending: 0 };
    for (const f of out.findings) {
      if (f.severity === "danger") out.counts.danger++;
      else if (f.severity === "warning") out.counts.warning++;
      else if (f.severity === "clear" || f.severity === "info") out.counts.ready++;
      else out.counts.pending++;
    }
  }
  return out;
}

/* Универсальный fallback для logcat, dmesg, /proc/mounts, JSON и коротких отчётов.
   Он намеренно консервативен: срабатывает только на явные индикаторы сбоев и состояния. */
const GENERIC_RULES = [
  {
    name: "SELinux", severity: "danger",
    patterns: [
      /\bselinux\b.{0,40}(?:permissive(?!\s*=\s*0)|disabled|dirty|tamper|mismatch|paradox)/i,
      /\bgetenforce\b.{0,20}(?:permissive|disabled)/i,
      /^(?:selinux(?:\s+status|\s+mode)?|getenforce)\s*[:=]\s*(?:permissive|disabled)\b/i,
      /\bpermissive\s*=\s*1\b/i,
      /(?:precompiled_sepolicy|secilc|selinux_android_restorecon).{0,55}(?:fail(?:ed)?|error|mismatch|corrupt|unable|denied)/i,
      /dirty\s*sepolicy/i,
      /system_server.{0,35}execmem.{0,20}(?:allow|granted|yes|true)/i
    ],
    exclude: [/permissive\s*=\s*0\b(?!.*(?:dirty|tamper|mismatch|paradox|disabled))/i]
  },
  {
    name: "SELinux AVC", severity: "warning",
    patterns: [
      /avc:\s*denied\s*\{[^}]+\}/i,
      /\bsepolicy\b.{0,45}(?:error|failed|denied|invalid|syntax)/i,
      /u:(?:object_r|r):unlabeled:s0/i
    ],
    severityForMatches: matches => matches.some(line =>
      /\bpermissive\s*=\s*1\b|scontext=u:r:(?:system_server|init|keystore|zygote|vold|unlabeled):/i.test(line)
    ) ? "danger" : "warning"
  },
  {
    name: "TEE", severity: "danger",
    patterns: [
      /(?:tee|keymint|keymaster|attestation|keybox).{0,60}(?:mismatch|revoked|invalid|tamper|failed|fail\b|untrusted)/i,
      /(?:mismatch|revoked|invalid|tamper).{0,50}(?:keymint|keymaster|attestation|keybox)/i
    ]
  },
  {
    name: "KeyMint / Keystore", severity: "danger",
    patterns: [
      /(?:keystore2|keymint|keymaster|gatekeeper|trusty).{0,60}(?:error|fail(?:ed)?|exception|died|crash|timeout|unavailable|corrupt)/i,
      /android\.hardware\.security\.keymint.{0,50}(?:fail|error|not found|died|unavailable)/i,
      /ServiceSpecificException.{0,50}(?:keystore|keymint|keymaster)/i
    ]
  },
  {
    name: "Zygote Runtime", severity: "danger",
    patterns: [
      /(?:zygote(?:64)?|app_process(?:64)?|libandroid_runtime).{0,60}(?:fatal|crash|sigsegv|sigabrt|abort|died|dlopen failed|cannot locate symbol|jni_onload|fork failed)/i,
      /Fatal signal \d+.*(?:zygote|app_process)/i
    ]
  },
  {
    name: "SystemServer", severity: "danger",
    patterns: [
      /(?:system_server|SystemServer).{0,60}(?:fatal|crash|watchdog|killing system process|deadsystemexception|uncaught exception|failed to start|anr)/i,
      /\*\*\*\s*WATCHDOG KILLING SYSTEM PROCESS/i,
      /SELinuxMMAC.{0,50}(?:error|fail|exception|invalid)/i
    ]
  },
  {
    name: "Bootloader", severity: "danger",
    patterns: [
      /(?:bootloader|verified\s*boot|vbmeta).{0,45}(?:unlocked|orange|failed|invalid|tamper)/i,
      /ro\.boot\.(?:flash\.locked|verifiedbootstate)\s*[=:]\s*(?:0|orange)/i
    ]
  },
  {
    name: "Module Diagnostics", severity: "warning",
    patterns: [
      /(?:module\.prop|post-fs-data\.sh|service\.sh|boot-completed\.sh|uninstall\.sh).{0,60}(?:error|fail(?:ed)?|crash|timeout|permission denied|not found|syntax error)/i,
      /(?:magisk|ksu|ksud|apatch|zygisk)\s*(?:module)?\s.{0,45}(?:failed|broken|disabled|conflict|bootloop|incompatible|crash)/i,
      /(?:\/data\/adb\/modules\/[^\s/]+).{0,50}(?:disable|remove|update|error|fail|conflict|bootloop)/i,
      /(?:ksud|magiskd|apatchd).{0,50}(?:error|fail|abort|panic|denied)/i
    ],
    severityForMatches: matches => matches.some(line => /bootloop|crash|abort|panic|fatal/i.test(line)) ? "danger" : "warning"
  },
  {
    name: "Root Managers", severity: "warning",
    patterns: [
      /(?:magisk|kernelsu(?:-next)?|apatch|ksud|libksud).{0,45}(?:detected|found|visible|installed|matched|signature)/i,
      /(?:detected|found|visible|installed|matched).{0,45}(?:magisk|kernelsu|apatch|ksud|libksud)/i
    ]
  },
  {
    name: "LSPosed", severity: "warning",
    patterns: [
      /(?:lsposed|xposed).{0,45}(?:detected|found|visible|hook|bridge|active)/i,
      /(?:detected|found|visible).{0,35}(?:lsposed|xposed)/i
    ]
  },
  {
    name: "ADB Runtime", severity: "warning",
    patterns: [
      /(?:adb|adbd|usb\s*debugging|wireless\s*debugging).{0,45}(?:enabled|active|running|connected|present)/i,
      /init\.svc\.adbd\s*[=:]\s*running/i,
      /persist\.sys\.usb\.config\s*[=:].*adb/i
    ]
  },
  {
    name: "Dangerous Apps", severity: "warning",
    patterns: [
      /(?:dangerous|risky|suspicious)\s*(?:apps?|packages?).{0,45}(?:detected|found|visible|[1-9]\d*\s+hits?)/i,
      /(?:lucky\s*patcher|mt\s*manager|frida\s*server).{0,35}(?:detected|found|installed|visible)/i
    ]
  },
  {
    name: "Network Risk", severity: "warning",
    patterns: [
      /(?:vpn|proxy|tun\d*|frida).{0,40}(?:detected|active|connected|running|enabled)/i,
      /(?:network\s*risk|traffic\s*interception).{0,40}(?:detected|warning|high)/i
    ]
  },
  {
    name: "Zygisk", severity: "warning",
    patterns: [
      /zygisk.{0,45}(?:detected|found|visible|injected|active|trace)/i
    ]
  },
  {
    name: "Native Root", severity: "warning",
    patterns: [
      /(?:\bsu\b|root\s*(?:binary|access|artifact)|\/data\/adb|\/system\/xbin\/su).{0,45}(?:detected|found|exists|accessible|granted|visible)/i,
      /(?:detected|found|exists|accessible|granted).{0,45}(?:\bsu\b|root\s*binary|\/data\/adb|\/system\/xbin\/su)/i
    ]
  },
  {
    name: "Mount", severity: "warning",
    patterns: [
      /(?:mount|overlay|tmpfs).{0,45}(?:magisk|suspicious|modified|detected)/i,
      /\s\/(?:system|vendor|product|system_ext|odm|apex)(?:\/\S*)?\s+\S+\s+[^,\s]*\brw\b/i,
      /^(?:overlay|tmpfs)\s+\/(?:system|vendor|product|system_ext|odm|sbin|debug_ramdisk)\b/i,
      /(?:mount|overlayfs|erofs|ext4).{0,45}(?:failed|error|conflict|corrupt|read-only file system|permission denied)/i,
      /(?:\/sbin\/\.magisk|\/debug_ramdisk\/\.magisk|workerdir=.*\/adb)/i
    ],
    severityForMatches: matches => matches.some(line =>
      /\s\/(?:system|vendor|product|system_ext|odm|apex)(?:\/\S*)?\s+\S+\s+[^,\s]*\brw\b|corrupt|failed/i.test(line)
    ) ? "danger" : "warning"
  },
  {
    name: "System Properties", severity: "warning",
    patterns: [
      /(?:dangerous|suspicious|modified)\s*(?:system\s*)?(?:prop|propert)/i,
      /ro\.(?:debuggable|secure)\s*[=:]\s*(?:1|0).{0,30}(?:warning|detected|unexpected)/i
    ]
  }
];

function compactLine(value) {
  return String(value || "").replace(/\s+/g, " ").trim().slice(0, 420);
}

function parsePlayIntegrity(text) {
  const upper = String(text || "").toUpperCase();
  const mentionsIntegrity = /PLAY[_ ]?INTEGRITY|DEVICE[_ ]?RECOGNITION[_ ]?VERDICT|MEETS_(?:BASIC|DEVICE|STRONG)_INTEGRITY/.test(upper);
  if (!mentionsIntegrity) return null;

  const passed = ["BASIC", "DEVICE", "STRONG"].filter(level =>
    new RegExp(`(?:^|[^A-Z_])MEETS_${level}_INTEGRITY(?:[^A-Z_]|$)`).test(upper)
  );
  const explicitFail = /(?:PLAY[_ ]?INTEGRITY.{0,60}(?:FAIL|FAILED|DENIED)|(?:FAIL|FAILED).{0,50}PLAY[_ ]?INTEGRITY|DEVICE[_ ]?RECOGNITION[_ ]?VERDICT["']?\s*[=:]\s*\[\s*\])/.test(upper);
  if (!passed.length && !explicitFail) return null;

  const hasBasic = passed.includes("BASIC");
  const hasDevice = passed.includes("DEVICE");
  const severity = !hasBasic ? "danger" : (!hasDevice ? "warning" : "clear");
  return {
    severity,
    name: "Play Integrity",
    verdict: passed.map(level => `MEETS_${level}_INTEGRITY`).join(", "),
    headline: "",
    quickFacts: `BASIC: ${hasBasic ? "OK" : "FAIL"} | DEVICE: ${hasDevice ? "OK" : "FAIL"} | STRONG: ${passed.includes("STRONG") ? "OK" : "—"}`,
    integrityLevels: passed,
    packages: [], extra: ""
  };
}

function parseGenericReport(text) {
  const source = String(text || "");
  const lines = source.split(/\r?\n/).map(compactLine).filter(Boolean);
  const out = {
    device: "", appVersion: "", reportTime: "",
    counts: { danger: 0, warning: 0, ready: 0, pending: 0 },
    countsParsed: false,
    findings: []
  };

  const deviceMatch = source.match(/(?:Target Device|Device|Model|Устройство)\s*[=:]\s*([^\r\n,}{]{2,120})/i);
  const versionMatch = source.match(/(?:App Version|Scanner Version|Version|Версия)\s*[=:]\s*([^\r\n,}{]{1,80})/i);
  const timeMatch = source.match(/(?:Report Time|Scan Time|Timestamp|Время)\s*[=:]\s*([^\r\n}{]{4,100})/i);
  if (deviceMatch) out.device = compactLine(deviceMatch[1]);
  if (versionMatch) out.appVersion = compactLine(versionMatch[1]);
  if (timeMatch) out.reportTime = compactLine(timeMatch[1]);

  const integrity = parsePlayIntegrity(source);
  if (integrity) out.findings.push(integrity);

  for (const rule of GENERIC_RULES) {
    const matches = [];
    for (const line of lines) {
      if (rule.exclude && rule.exclude.some(re => re.test(line))) continue;
      if (rule.patterns.some(re => re.test(line))) {
        if (!matches.includes(line)) matches.push(line);
        if (matches.length === 3) break;
      }
    }
    if (!matches.length) continue;
    const severity = rule.severityForMatches ? rule.severityForMatches(matches) : rule.severity;
    out.findings.push({
      severity,
      name: rule.name,
      verdict: matches[0],
      headline: "",
      quickFacts: "",
      matchCount: matches.length,
      packages: [],
      extra: matches.slice(1).join(" · ")
    });
  }

  // Распознаём явный здоровый статус getenforce / SELinux, если не сработали правила ошибок SELinux
  if (!out.findings.some(f => f.name === "SELinux")) {
    const enforcingLine = lines.find(line =>
      /^(?:selinux(?:\s+status|\s+mode)?|getenforce)\s*[:=]?\s*enforcing\b/i.test(line)
    );
    if (enforcingLine) {
      out.findings.push({
        severity: "clear",
        name: "SELinux",
        verdict: enforcingLine,
        headline: "",
        quickFacts: "Mode: Enforcing",
        packages: [],
        extra: ""
      });
    }
  }

  // Распознаём валидный манифест module.prop без ошибок, если не сработало правило ошибок модулей
  if (!out.findings.some(f => f.name === "Module Diagnostics")) {
    const hasId = lines.find(line => /^id\s*=\s*[a-z0-9_.-]+/i.test(line));
    const hasMeta = lines.find(line => /^(?:name|version|versionCode)\s*=\s*\S+/i.test(line));
    if (hasId && hasMeta) {
      out.findings.push({
        severity: "info",
        name: "Module Diagnostics",
        verdict: `${hasId} (${hasMeta})`,
        headline: "",
        quickFacts: "module.prop",
        packages: [],
        extra: ""
      });
    }
  }

  out.findings.sort((a, b) => SEV_ORDER[a.severity] - SEV_ORDER[b.severity]);
  for (const finding of out.findings) {
    if (finding.severity === "danger") out.counts.danger++;
    else if (finding.severity === "warning") out.counts.warning++;
    else if (finding.severity === "pending") out.counts.pending++;
    else out.counts.ready++;
  }
  return out;
}

function parseDetectorReport(text) {
  const source = String(text || "").replace(/^\uFEFF/, "");
  if (!source.trim()) return parseGenericReport("");

  const looksLikeDuck = /DUCK DETECTOR|EXECUTIVE SUMMARY|\[(?:✖|▲|✔)?\s*(?:DANGER|WARNING|CLEAR|READY)\]/i.test(source);
  if (looksLikeDuck) {
    const parsed = parseDuckReport(source);
    parsed.format = "duck";
    if (parsed.findings.length) return parsed;
  }

  const parsed = parseGenericReport(source);
  parsed.format = /^\s*[\[{]/.test(source) ? "json/text" : "text";
  return parsed;
}

if (typeof window !== "undefined") {
  window.parseDuckReport = parseDuckReport;
  window.parseGenericReport = parseGenericReport;
  window.parseDetectorReport = parseDetectorReport;
}
if (typeof module !== "undefined") module.exports = { parseDuckReport, parseGenericReport, parseDetectorReport };
