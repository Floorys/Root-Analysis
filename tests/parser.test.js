"use strict";

const test = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const vm = require("node:vm");
const { parseDuckReport, parseDetectorReport } = require("../assets/parser.js");
const { FIXES, CLEAN_NOTES, REPAIR_GUIDE } = require("../assets/data.js");

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

test("parses SELinux avc: denied without false Permissive on permissive=0", () => {
  const report = parseDetectorReport(`
getenforce: Enforcing
type=1400 audit(0.0:12): avc: denied { read } for pid=412 comm="app" name="foo" dev="dm-0" scontext=u:r:untrusted_app:s0 tcontext=u:object_r:system_file:s0 tclass=file permissive=0
`);
  const avc = report.findings.find(item => item.name === "SELinux AVC");
  const selinux = report.findings.find(item => item.name === "SELinux");
  assert.ok(avc);
  assert.equal(avc.severity, "warning");
  assert.ok(selinux);
  assert.equal(selinux.severity, "clear");
});

test("escalates SELinux AVC when permissive=1 or system_server domain", () => {
  const report = parseDetectorReport(`
avc: denied { execmem } for pid=900 comm="system_server" scontext=u:r:system_server:s0 tcontext=u:r:system_server:s0 tclass=process permissive=1
`);
  const avc = report.findings.find(item => item.name === "SELinux AVC");
  const selinux = report.findings.find(item => item.name === "SELinux");
  assert.ok(avc);
  assert.equal(avc.severity, "danger");
  assert.ok(selinux);
  assert.equal(selinux.severity, "danger");
});

test("parses /proc/mounts rw system partitions and module script errors", () => {
  const report = parseDetectorReport(`
/dev/block/dm-0 /system ext4 rw,seclabel,relatime 0 0
overlay /vendor overlay rw,lowerdir=/vendor 0 0
/data/adb/modules/bad_mod/post-fs-data.sh failed with error code 1
`);
  const mountFinding = report.findings.find(item => item.name === "Mount");
  const moduleFinding = report.findings.find(item => item.name === "Module Diagnostics");
  assert.ok(mountFinding);
  assert.equal(mountFinding.severity, "danger");
  assert.ok(moduleFinding);
  assert.equal(moduleFinding.severity, "warning");
});

test("parses KeyMint/Keystore, Zygote, and SystemServer errors from logcat", () => {
  const report = parseDetectorReport(`
E keystore2: ServiceSpecificException in keymint HAL: failed to generate key
F libc    : Fatal signal 11 (SIGSEGV) in zygote64: dlopen failed: library "libbroken.so" not found
E Watchdog: *** WATCHDOG KILLING SYSTEM PROCESS: Blocked in monitor on com.android.server.am.ActivityManagerService
`);
  const names = report.findings.map(item => item.name);
  assert.ok(names.includes("KeyMint / Keystore"));
  assert.ok(names.includes("Zygote Runtime"));
  assert.ok(names.includes("SystemServer"));
});

test("recognizes clean module.prop manifest without errors", () => {
  const report = parseDetectorReport(`
id=sample_diag_module
name=Diagnostic Helper
version=v1.0
versionCode=10
`);
  const mod = report.findings.find(item => item.name === "Module Diagnostics");
  assert.ok(mod);
  assert.equal(mod.severity, "info");
});

test("keeps RU/EN translations and REPAIR_GUIDE links complete", () => {
  const i18nCode = fs.readFileSync(path.join(__dirname, "../assets/i18n.js"), "utf8");
  const ctx = {};
  vm.runInNewContext(`${i18nCode}\nthis.__exported = { UI_TEXT, FIX_EN, CLEAN_EN, REPAIR_GUIDE_EN };`, ctx);
  const { UI_TEXT, FIX_EN, CLEAN_EN, REPAIR_GUIDE_EN } = ctx.__exported;

  assert.deepEqual(Object.keys(UI_TEXT.ru).sort(), Object.keys(UI_TEXT.en).sort());
  for (const key of Object.keys(FIXES)) {
    assert.ok(FIX_EN[key], `Missing FIX_EN entry for ${key}`);
  }
  for (const key of Object.keys(CLEAN_NOTES)) {
    assert.ok(CLEAN_EN[key], `Missing CLEAN_EN entry for ${key}`);
  }
  for (const item of REPAIR_GUIDE) {
    assert.ok(REPAIR_GUIDE_EN[item.id], `Missing REPAIR_GUIDE_EN entry for ${item.id}`);
    assert.ok(Array.isArray(item.verifyCmds) && item.verifyCmds.length > 0);
  }
});
