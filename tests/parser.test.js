"use strict";

const test = require("node:test");
const assert = require("node:assert/strict");
const { parseDuckReport, parseDetectorReport } = require("../assets/parser.js");

test("parses DUCK summary and detailed findings without duplicates", () => {
  const input = `
DUCK DETECTOR — SECURITY SCAN REPORT
Target Device  : Test Phone (Android 16)
App Version    : 1.2.3
Report Time    : 2026-11-03 10:00 UTC
[✖] Danger   : 1
[▲] Warning  : 1
[✔] Ready    : 1
[·] Pending  : 0
TOP FINDINGS
[✖ DANGER] SELinux
Headline : Dirty policy
----------------
[✖ DANGER] SELinux
Verdict      : Dirty policy detected
Quick Facts  : Mode: Enforcing | Policy: Modified
[Impact]
  • system_server execmem is allowed
[▲ WARNING] ADB Runtime
Verdict      : ADB enabled
Quick Facts  : ADB: Active
[Detected Packages]
  • sample.package
[✔ CLEAR] Zygisk
Verdict      : No runtime signal
`;
  const report = parseDuckReport(input);
  assert.equal(report.device, "Test Phone (Android 16)");
  assert.deepEqual(report.counts, { danger: 1, warning: 1, ready: 1, pending: 0 });
  assert.equal(report.findings.filter(item => item.name === "SELinux").length, 1);
  assert.equal(report.findings[0].severity, "danger");
  assert.equal(report.findings.length, 3);
});

test("recognizes generic log indicators", () => {
  const report = parseDetectorReport(`
Device: Pixel Test
SELinux status: permissive
init.svc.adbd=running
Bootloader: unlocked
Magisk detected by signature
`);
  const names = report.findings.map(item => item.name);
  assert.equal(report.format, "text");
  assert.ok(names.includes("SELinux"));
  assert.ok(names.includes("ADB Runtime"));
  assert.ok(names.includes("Bootloader"));
  assert.ok(names.includes("Root Managers"));
});

test("understands Play Integrity JSON-like output", () => {
  const report = parseDetectorReport(`{
    "deviceRecognitionVerdict": ["MEETS_BASIC_INTEGRITY"]
  }`);
  const finding = report.findings.find(item => item.name === "Play Integrity");
  assert.ok(finding);
  assert.equal(finding.severity, "warning");
  assert.match(finding.quickFacts, /DEVICE: FAIL/);
});

test("recognizes an empty Play Integrity verdict as a failed check", () => {
  const report = parseDetectorReport('{"deviceIntegrity":{"deviceRecognitionVerdict":[]}}');
  assert.equal(report.format, "json/text");
  assert.equal(report.findings.length, 1);
  assert.equal(report.findings[0].name, "Play Integrity");
  assert.equal(report.findings[0].severity, "danger");
  assert.deepEqual(report.counts, { danger: 1, warning: 0, ready: 0, pending: 0 });
});

test("returns empty findings for unrelated text", () => {
  const report = parseDetectorReport("hello world\nno detector output here");
  assert.equal(report.findings.length, 0);
});

test("keeps Bootloader and Native Root as real DUCK sections", () => {
  const report = parseDuckReport(`
[✔ CLEAR] Bootloader
Verdict: Locked and attested verified
[ℹ INFO] Native Root
Verdict: No root indicators
`);
  assert.deepEqual(report.findings.map(item => item.name), ["Native Root", "Bootloader"]);
});
