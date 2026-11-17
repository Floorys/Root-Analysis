/* ============================================================
   HideRoot 2026 — данные: методы скрытия + база фиксов + пример
   Обычный скрипт (без модулей), работает и из file://, и с сервера.
   ============================================================ */
"use strict";

/* ---------- МЕТОДЫ СКРЫТИЯ ---------- */
const METHODS = [
  {
    id: "shamiko", title: "Shamiko", dot: "magisk", level: "device",
    desc: "Zygisk-модуль, скрывающий рут и сам Zygisk от приложений в DenyList. Стандарт скрытия в 2026.",
    cats: ["magisk", "ksu", "ap"], tags: ["Zygisk", "DenyList"],
    keys: "shamiko zygisk hide denylist blacklist whitelist magisk kernelsu apatch",
    steps: [
      "Включите Zygisk в Magisk (или поставьте ZygiskNext/ReZygisk для KSU/APatch).",
      "Установите Shamiko как модуль (ZIP через «Modules» / KSU-менеджер).",
      "Добавьте банковские и целевые приложения в DenyList.",
      "Shamiko работает в whitelist-режиме: скрывает только от приложений из DenyList. Не включайте «Enforce DenyList» без необходимости.",
      "Перезагрузка. Проверка: логи Shamiko в logcat, статус <code>magisk --denylist ls</code>."
    ]
  },
  {
    id: "denylist", title: "Magisk DenyList", dot: "magisk", level: "basic",
    desc: "Встроенный механизм Magisk: размонтирует оверлеи и прячет следы рута от выбранных процессов. База для Shamiko.",
    cats: ["magisk"], tags: ["Встроенное"],
    keys: "magisk denylist umount hide встроенный native",
    steps: [
      "Magisk → Settings → Configure DenyList.",
      "Отметьте целевые приложения и их процессы.",
      "Опция «Enforce DenyList» скрывает сам Magisk (используется без Shamiko).",
      "Сам по себе слаб против Play Integrity DEVICE/STRONG — нужен Shamiko + PIF."
    ]
  },
  {
    id: "zygisk", title: "Zygisk", dot: "gen", level: "device",
    desc: "Внедрение кода в zygote на native-уровне. Основа для Shamiko, PIF, LSPosed и большинства модулей скрытия.",
    cats: ["magisk", "ksu", "ap"], tags: ["Ядро стека"],
    keys: "zygisk injection zygote native magisk kernelsu",
    steps: [
      "Без включённого Zygisk Shamiko и Play Integrity Fix не работают.",
      "Модули хукают процессы приложений до старта, подменяя результаты проверок."
    ]
  },
  {
    id: "zygisknext", title: "ZygiskNext / ReZygisk", dot: "ksu", level: "device",
    desc: "Отдельная реализация Zygisk для KernelSU и APatch, где нет встроенного. Даёт совместимость с Shamiko и PIF.",
    cats: ["ksu", "ap"], tags: ["KernelSU", "APatch"],
    keys: "zygisknext rezygisk kernelsu apatch zygisk реализация",
    steps: [
      "Установите модуль ZygiskNext (или открытый форк ReZygisk).",
      "Затем ставьте Shamiko и PIF как обычные Zygisk-модули.",
      "ReZygisk — более лёгкая альтернатива, набирает популярность в 2026."
    ]
  },
  {
    id: "pif", title: "Play Integrity Fix (PIF)", dot: "gen", level: "device",
    desc: "Подменяет fingerprint/props, чтобы пройти Play Integrity на уровнях DEVICE и BASIC. Ключевой модуль для Google Wallet и банков.",
    cats: ["magisk", "ksu", "ap"], tags: ["BASIC", "DEVICE"],
    keys: "playintegrityfix pif chiteroman integrity device basic spoof props fingerprint",
    steps: [
      "Установите PlayIntegrityFix (chiteroman/osmosik) + включённый Zygisk.",
      "Модуль подставляет «чистый» отпечаток сертифицированного устройства.",
      "Для STRONG одного PIF мало — нужен TrickyStore с валидным keybox.",
      "Проверка: Play Integrity Checker / TB Checker.",
      "Обновляйте часто — Google регулярно отзывает отпечатки."
    ]
  },
  {
    id: "trickystore", title: "TrickyStore + Keybox", dot: "gen", level: "strong",
    desc: "Перехватывает hardware key attestation в TEE и подставляет валидный keybox. Единственный путь к STRONG на разблокированном загрузчике.",
    cats: ["magisk", "ksu", "ap"], tags: ["STRONG", "TEE"],
    keys: "trickystore keybox tee hardware strong attestation bootloader verified boot",
    steps: [
      "TrickyStore (Zygisk-модуль) хукает запросы key attestation.",
      "Нужен валидный keybox.xml с неотозванным сертификатом; публичные keybox массово отзываются.",
      "Связка Shamiko + PIF + TrickyStore = BASIC + DEVICE + STRONG.",
      "Также правит bootloader state и verified boot state (green/locked).",
      "Критично: версии keybox должны соответствовать KeyMint HAL устройства, иначе детекторы ловят MISMATCH."
    ]
  },
  {
    id: "susfs", title: "SUSFS (kernel-level hiding)", dot: "ksu", level: "strong",
    desc: "Патчи ядра susfs4ksu: прячет mounts, selinuxfs (enforce/policy), файлы и пути на уровне ядра. Главный ответ продвинутым детекторам в 2026.",
    cats: ["ksu", "ap"], tags: ["Ядро", "selinuxfs", "mounts"],
    keys: "susfs kernel susfs4ksu selinux mount hide dirty sepolicy duck detector",
    steps: [
      "Нужно ядро с susfs-патчами (susfs4ksu) для вашего устройства + KernelSU/SukiSu с поддержкой SUSFS.",
      "Включите susfs-фичи: spoof selinuxfs (enforce/policy/getenforce), hide mounts, hide files/paths.",
      "Закрывает «dirty sepolicy»-пробы детекторов: чтение политики из untrusted_app возвращает стоковые результаты.",
      "Комбинируется с Shamiko/PIF/TrickyStore — закрывает другой слой детекта.",
      "Минус: перепрошивка boot; проверяйте совместимость с вашей версией ядра/ROM."
    ]
  },
  {
    id: "kernelsu", title: "KernelSU / KernelSU-Next", dot: "ksu", level: "device",
    desc: "Рут на уровне ядра. Сложнее детектируется статически, но требует кастомного ядра. KernelSU-Next — активный форк 2025–2026.",
    cats: ["ksu"], tags: ["Kernel", "Manager"],
    keys: "kernelsu ksu next kernel based root hiding",
    steps: [
      "Менеджер умеет скрывать себя и работать в stealth-режиме.",
      "Для обхода детекта: ZygiskNext → Shamiko → PIF (+ SUSFS-ядро для сильных детекторов).",
      "Allowlist по умолчанию не виден непривилегированным приложениям.",
      "Учтите: менеджер палится не по имени пакета, а по подписи и libksud.so — прячьте пакет через HMA."
    ]
  },
  {
    id: "apatch", title: "APatch", dot: "ap", level: "device",
    desc: "Гибрид Magisk и KernelSU: патчит boot-образ ядра, поддерживает KernelPatch и Magisk-модули. Популярен в 2025–2026.",
    cats: ["ap"], tags: ["KernelPatch", "SuperKey"],
    keys: "apatch kernel patch root hiding android",
    steps: [
      "Поддерживает модули Magisk-формата, вкл. Shamiko/PIF через ZygiskNext.",
      "SuperKey: доступ к руту только по секретному ключу, менеджер не виден без него.",
      "Хорошо обходит детект su-бинаря и magisk-путей."
    ]
  },
  {
    id: "props", title: "MagiskHide Props Config", dot: "gen", level: "device",
    desc: "Точечная правка build.prop и device-отпечатка systemless-способом. Полезен для тонкой настройки отдельных props.",
    cats: ["magisk", "ksu", "ap"], tags: ["props"],
    keys: "props config magiskhide build.prop fingerprint spoof systemless",
    steps: [
      "В терминале: <code>props</code> → выбрать fingerprint сертифицированного устройства.",
      "Меняет ro.build.fingerprint, model, brand и т.д.",
      "В 2026 в основном вытеснен PIF, но полезен для отдельных свойств."
    ]
  },
  {
    id: "rename", title: "Переименование менеджера рута", dot: "gen", level: "basic",
    desc: "Пересборка приложения менеджера со случайным именем пакета, чтобы детект не нашёл его по пакету/подписи.",
    cats: ["magisk", "ksu", "ap", "gen"], tags: ["Hide app"],
    keys: "rename package hide manager app repack random magisk hide app",
    steps: [
      "Magisk → Settings → Hide the Magisk app → случайное имя.",
      "В KSU/APatch менеджеры также можно прятать/переименовывать (SuperKey).",
      "Помните: против продвинутых детекторов одного переименования мало — палится signing cert и native-payload (libksud.so). Нужен HMA."
    ]
  },
  {
    id: "hosts", title: "Systemless Hosts", dot: "gen", level: "basic",
    desc: "Подмена /etc/hosts без изменения системного раздела. Блокирует домены детект-сервисов и аналитики.",
    cats: ["magisk", "ksu", "ap", "gen"], tags: ["hosts"],
    keys: "systemless hosts adblock detection hosts magisk",
    steps: [
      "Модуль Magisk «Systemless Hosts» + AdAway.",
      "Помогает против приложений, обращающихся к внешним сервисам проверки.",
      "На Play Integrity напрямую не влияет."
    ]
  },
  {
    id: "lsposed", title: "LSPosed (Xposed)", dot: "gen", level: "device",
    desc: "Фреймворк хуков. Сам детектируется, поэтому прячется через Shamiko/DenyList, но даёт модули точечного обхода проверок.",
    cats: ["magisk", "ksu", "ap"], tags: ["Zygisk", "Xposed"],
    keys: "lsposed xposed frida hook hide detection modules",
    steps: [
      "Hide My Applist — скрывает установленные приложения от детекта.",
      "Android Faker / XPrivacyLua — подмена системных значений.",
      "Сам LSPosed прячьте в DenyList + случайное имя менеджера.",
      "Следите за sepolicy: «грязные» правила (system_server execmem) выдают стек детекторам."
    ]
  },
  {
    id: "hma", title: "Hide My Applist (HMA)", dot: "gen", level: "basic",
    desc: "Скрывает конкретные пакеты (Magisk, KSU, LSPosed, VPN-клиенты) от целевых приложений через hook списка пакетов.",
    cats: ["magisk", "ksu", "ap", "gen"], tags: ["LSPosed", "package visibility"],
    keys: "hide my applist hma package visibility android 11 detection",
    steps: [
      "Ставится как LSPosed-модуль.",
      "Создайте шаблон скрытия: менеджеры рута, MT Manager, VPN-клиенты и т.п.",
      "Примените шаблон к банковским приложениям и детекторам (например, com.eltavine.duckdetector).",
      "Файловые следы на /sdcard (папки приложений) HMA не прячет — чистите хранилище."
    ]
  },
  {
    id: "adb", title: "Скрытие developer options / ADB", dot: "gen", level: "basic",
    desc: "Детекторы проверяют включённую отладку, adbd-сокет и persist.sys.usb.config. ADB — дешёвый «палево»-признак.",
    cats: ["gen"], tags: ["ADB", "Dev settings"],
    keys: "usb debugging developer options adb detection flags adbd jdwp",
    steps: [
      "Держите USB-debugging выключенным, когда он не нужен.",
      "Проверьте: <code>getprop init.svc.adbd</code> → должно быть stopped, <code>persist.sys.usb.config</code> → mtp.",
      "Отозвать ADB-авторизации: Developer options → Revoke USB debugging authorizations.",
      "Противоречие «настройка выключена, но adbd работает» — само по себе сигнал детектору."
    ]
  },
  {
    id: "bootloader", title: "Маскировка bootloader / verified boot", dot: "gen", level: "strong",
    desc: "Разблокированный загрузчик выдаёт orange/unlocked state. TrickyStore и патчи ядра подменяют verified boot state на green/locked.",
    cats: ["magisk", "ksu", "ap", "gen"], tags: ["AVB", "dm-verity"],
    keys: "bootloader unlock verified boot state orange green avb dm-verity",
    steps: [
      "Play Integrity STRONG проверяет hardware-backed attestation, куда входит bootloader state.",
      "Без валидного keybox подменить его нельзя — нужен TrickyStore + keybox.",
      "dm-verity/AVB должны быть корректно пропатчены в boot/vbmeta-образе."
    ]
  },
  {
    id: "piapi", title: "Play Integrity API — уровни", dot: "gen", level: "info",
    desc: "Что именно проходят методы. SafetyNet устарел, его заменил Play Integrity API с тремя вердиктами.",
    cats: ["gen"], tags: ["BASIC", "DEVICE", "STRONG"],
    keys: "play integrity api safetynet basic device strong levels verdicts explanation",
    steps: [
      "MEETS_BASIC_INTEGRITY — грубых компрометаций нет; проходит почти любым скрытием.",
      "MEETS_DEVICE_INTEGRITY — сертифицированное устройство, CTS; нужен PIF + Shamiko.",
      "MEETS_STRONG_INTEGRITY — hardware-backed attestation; нужен TrickyStore + валидный keybox."
    ]
  },
  {
    id: "tools", title: "Инструменты проверки", dot: "gen", level: "tools",
    desc: "Чем тестировать скрытие перед использованием банков и Google Wallet.",
    cats: ["gen"], tags: ["Диагностика"],
    keys: "checker test yasnac tb checker root detection verify play integrity checker duck detector app",
    steps: [
      "Play Integrity Checker / TB Checker — вердикты BASIC/DEVICE/STRONG.",
      "Duck Detector — глубокий скан (SELinux-оракулы, TEE-аттестация, менеджеры, dirty policy).",
      "YASNAC — старый тестер attestation.",
      "Логи: <code>logcat | grep -iE 'shamiko|trickystore|susfs'</code>."
    ]
  }
];

/* ---------- БАЗА ФИКСОВ ДЛЯ ДИАГНОСТИКИ ----------
   Ключ = нормализованное имя секции отчёта Duck Detector.
   priority: 1 — критично, 2 — важно, 3 — желательно, 0 — инфо.
   ok — текст, когда секция чистая. steps — что делать, если не чистая. */
const FIXES = {
  "selinux": {
    priority: 1,
    why: "Детектор нашёл нестоковую SELinux-политику: «грязные» правила (например <code>system_server:process execmem = allowed</code>, на стоке запрещено), «paradox»-состояния и распознавание привилегированных контекстов через app_zygote-зонды и DirtySepolicy-запросы.",
    steps: [
      "Перейти на ядро с <b>SUSFS</b> (susfs4ksu) + KernelSU/SukiSu Ultra с его поддержкой: spoof selinuxfs прячет enforce/policy от untrusted_app — главный фикс 2026 против таких детекторов.",
      "Убрать «грязные» правила: проверьте модули KernelSU-Next и sepolicy-патчи; <code>system_server execmem</code> должен быть denied.",
      "Отключить модули, которые широко правят политику (кастомные sepolicy-модули, permissive-твики).",
      "Полностью выключить ADB (см. ADB Runtime) — часть «privileged context: ADB root» связана с ним.",
      "Пересканировать: DirtySepolicy-орaкулы должны вернуть стоковые вердикты."
    ],
    related: ["susfs", "kernelsu", "shamiko"]
  },
  "tee": {
    priority: 1,
    why: "Аттестация ключей неконсистентна: версия KeyMint из VINTF не совпадает с версией в attestation-расширении (напр. VINTF keymaster@4.0/41 vs attestation v3), либо отпечатки из разных источников расходятся. Это след TrickyStore/keybox-спуфинга.",
    steps: [
      "Обновить <b>TrickyStore</b> до последней версии.",
      "Использовать keybox, соответствующий реальному KeyMint HAL устройства (Android 17 → KeyMint, а не legacy keymaster@4.0).",
      "Выровнять fingerprint: PIF, TrickyStore и RKP-метаданные должны описывать одно устройство (никаких alioth:13 + fuxi:16 + Android 17 одновременно).",
      "Если STRONG не требуется целевым приложениям — оценить отключение спуфа аттестации: честный TEE даёт меньше рассинхронов.",
      "Проверить: KeyMint VINTF check → MATCH, tamper score снизился."
    ],
    related: ["trickystore", "pif", "bootloader"]
  },
  "adb runtime": {
    priority: 2,
    why: "adbd запущен (<code>init.svc.adbd=running</code>), видны /dev/socket/adbd и @jdwp-control, <code>persist.sys.usb.config=adb</code>. Противоречие «USB debugging: Disabled, но adbd работает» — отдельный сигнал.",
    steps: [
      "Settings → Developer options → выключить USB debugging и Wireless debugging.",
      "Revoke USB debugging authorizations (там же).",
      "Через рут: <code>setprop persist.sys.usb.config mtp</code>, затем перезагрузка.",
      "Контроль: <code>getprop init.svc.adbd</code> → stopped.",
      "Если adbd держит модуль (ADB Helper и т.п.) — отключить его."
    ],
    related: ["adb"]
  },
  "dangerous apps": {
    priority: 2,
    why: "Найдены пакеты из каталога «опасных» (MT Manager, Lucky Patcher, хук-фреймворки и т.д.) и/или их файловые следы на общем хранилище (напр. <code>/sdcard/MT2</code>).",
    steps: [
      "Удалить flagged-приложения (MT Manager и др.) или хотя бы их следы: папки на /sdcard видны всем.",
      "Остальное скрыть через <b>Hide My Applist</b>: шаблон с этими пакетами → применить к детектору/банку.",
      "Учесть: HMA прячет пакеты, но не файлы на общем хранилище — почистить /sdcard.",
      "Как вариант — вынести «опасные» приложения в рабочий профиль / второго пользователя."
    ],
    related: ["hma", "lsposed"]
  },
  "lsposed": {
    priority: 2,
    why: "Чаще всего горит из-за dirty sepolicy (то же правило <code>system_server execmem</code>), а не из-за самого LSPosed: рантайм-следы (классы, binder, maps, logcat) проверяются отдельно.",
    steps: [
      "Починить sepolicy (см. фикс SELinux) — обычно убирает и этот WARNING.",
      "Прятать менеджер LSPosed: случайное имя пакета + DenyList/HMA против детектора.",
      "Не давать модулям широкий scope на системные процессы без необходимости."
    ],
    related: ["lsposed", "hma", "susfs"]
  },
  "memory": {
    priority: 3,
    why: "Слабый сигнал: анонимные исполняемые страницы (часто WebView JIT), которые детектор не смог сравнить с файлом (нет доступа к /proc/self/pagemap).",
    steps: [
      "Обычно можно игнорировать — это review-уровень, не proof.",
      "Обновить Android System WebView.",
      "Проверить, не инжектят ли ваши модули во все процессы (сузить scope LSPosed-модулей).",
      "Убедиться, что нет memfd/ashmem-лоадеров от кастомных модулей."
    ],
    related: []
  },
  "network risk": {
    priority: 2,
    why: "Установлены/активны VPN- и прокси-клиенты (Clash, FlClash, v2ray, sing-box и т.п.), виден активный VPN-транспорт или прокси-модули (Box4Magisk). Банки трактуют это как риск перехвата трафика.",
    steps: [
      "Скрыть VPN-клиент от детектора/банка через HMA.",
      "Выключать VPN на время банковских операций и сканов.",
      "Прокси-модули (Box4Magisk/Box for Root) — в режим per-app exclusion, TUN-интерфейсы прятать, если модуль это умеет.",
      "Проверить global HTTP proxy: <code>settings get global http_proxy</code> → :0."
    ],
    related: ["hma"]
  },
  "root managers": {
    priority: 1,
    why: "Менеджер рута найден по совокупности якорей: signing certificate + native payload (<code>libksud.so</code>) + application class + label. Рандомизация имени пакета от этого НЕ спасает.",
    steps: [
      "Добавить детектор (com.eltavine.duckdetector) и банки в HMA → скрыть пакет менеджера KSU/Magisk.",
      "Shamiko whitelist / DenyList против тех же приложений.",
      "Продвинутый вариант: пересобрать менеджер с другой подписью и переименованным native-payload (libksud.so → другое имя), если форк это поддерживает.",
      "Крайний вариант: управление рут-профилем из второго пользователя / скрытого пространства."
    ],
    related: ["hma", "rename", "shamiko", "kernelsu"]
  },
  "system properties": {
    priority: 2,
    why: "Отдельные системные свойства выдают модификацию: чаще всего <code>persist.sys.usb.config=adb</code> (ожидаемо mtp) или следы PIF/спуфа в persist.*.",
    steps: [
      "<code>setprop persist.sys.usb.config mtp</code> (или выключить USB debugging в настройках).",
      "Проверить: <code>getprop | grep -iE 'usb|adb'</code>.",
      "Если светят PIF-свойства — обновить PIF до версии без persist-следов.",
      "Остальные boot/build-свойства обычно уже подменяются PIF/TrickyStore."
    ],
    related: ["adb", "pif", "props"]
  },
  "custom rom": {
    priority: 0,
    why: "Скан кастомной ROM: ищутся следы сторонних прошивок и их менеджеров.",
    steps: ["Если горит: скрывать ROM-менеджеры и OTA-пакеты через HMA; следить, чтобы props соответствовали stock-устройству."],
    related: ["pif", "hma"]
  },
  "location risk": {
    priority: 0,
    why: "Проверка подмены геолокации (mock location,fake GPS-приложения).",
    steps: ["Если горит: выключить mock location в Developer options, удалить fake-GPS-приложения или скрыть их через HMA."],
    related: ["hma"]
  },
  "mount": {
    priority: 3,
    why: "Наблюдение за монтированиями: magisk-оверлеи, tmpfs в неожиданных местах, следы модулей в /proc/mounts.",
    steps: [
      "Если горит: Shamiko должен unmount'ить оверлеи для приложений из DenyList — проверьте, что целевое приложение в списке.",
      "SUSFS (hide mounts) закрывает этот вектор на уровне ядра."
    ],
    related: ["susfs", "shamiko"]
  },
  "native root": {
    priority: 3,
    why: "Native-скан su-артефактов, бинарей и путей (/system/xbin/su, magisk, /data/adb).",
    steps: [
      "Если горит: DenyList/Shamiko против приложения; SUSFS hide files против путей /data/adb.",
      "Убедиться, что нет «забытых» su-бинарей от старых прошивок."
    ],
    related: ["susfs", "shamiko", "apatch"]
  },
  "su": {
    priority: 3,
    why: "Поиск su-артефактов, демонов и процессов.",
    steps: ["Если горит: см. Native Root — Shamiko/SUSFS; проверить, что su недоступен из shell без авторизации."],
    related: ["susfs", "shamiko"]
  },
  "virtualization": {
    priority: 3,
    why: "Проверка, не запущено ли приложение в виртуальном пространстве (VirtualApp, Parallel Space и т.п.).",
    steps: ["Если горит: не использовать виртуальные пространства для целевых приложений."],
    related: []
  },
  "zygote heap residue": {
    priority: 3,
    why: "Поиск остаточных строк в памяти zygote (аргументы процессов, следы модулей).",
    steps: ["Если горит: обновить Shamiko/Zygisk-реализацию; убрать модули, оставляющие строковые следы в zygote."],
    related: ["shamiko", "zygisknext"]
  },
  "bootloader": {
    priority: 0,
    why: "Статус загрузчика и verified boot (locked/green), сверка с аттестацией.",
    steps: ["Если горит: TrickyStore должен подменять verified boot state; проверить vbmeta-патч и консистентность с keybox."],
    related: ["trickystore", "bootloader"]
  },
  "kernel check": {
    priority: 3,
    why: "Маркеры кастомного ядра: имя/версия, boot-параметры, патчи.",
    steps: ["Если горит: ядро должно сохранять стоковую версию/строку (SUSFS-ядра обычно маскируются); проверить cmdline."],
    related: ["susfs"]
  },
  "play integrity fix": {
    priority: 3,
    why: "Остатки PIF: persist-свойства, pixel-props, следы в maps.",
    steps: ["Если горит: обновить PIF (новые версии не оставляют persist-следов); не использовать устаревшие USNF/Pixelify."],
    related: ["pif"]
  },
  "zygisk": {
    priority: 3,
    why: "Рантайм-следы Zygisk: FD-trap, TMP_PATH-утечки, linker-хуки, TracerPid, аномалии maps.",
    steps: ["Если горит: обновить Shamiko/ZygiskNext; современные реализации проходят FD-trap и solist-проверки."],
    related: ["shamiko", "zygisknext"]
  },
  "play integrity": {
    priority: 1,
    why: "Play Integrity не вернул обязательный уровень DEVICE (или не прошёл даже BASIC). Для большинства банков и Wallet одного скрытого <code>su</code> недостаточно: проверяются fingerprint, сертификация и attestation.",
    steps: [
      "Обновить <b>Play Integrity Fix</b> и используемую реализацию Zygisk, затем полностью перезагрузить устройство.",
      "Очистить данные Google Play Services, Play Store и целевого приложения только после проверки совместимости текущей конфигурации.",
      "Проверить согласованность fingerprint/props: модель, версия Android, security patch и device codename должны описывать один сертифицированный билд.",
      "Если нужен STRONG — отдельно проверить TrickyStore, keybox и соответствие KeyMint; PIF сам по себе даёт BASIC/DEVICE, но не гарантирует STRONG.",
      "Повторить проверку в Play Integrity Checker и сохранить новый отчёт для сравнения."
    ],
    related: ["pif", "trickystore", "shamiko", "bootloader"]
  }
};

/* Тексты для чистых состояний */
const CLEAN_NOTES = {
  "zygisk": "Zygisk-рантайм не виден. Не обновляйте модули «на всякий случай» — проверяйте статус после каждого изменения.",
  "play integrity fix": "Следов PIF нет. Держите PIF обновлённым, после OTA-обновлений системы перепроверяйте.",
  "bootloader": "Загрузчик выглядит заблокированным, verified boot подтверждён аттестацией. Так держать.",
  "kernel check": "Маркеров кастомного ядра нет.",
  "su": "su-артефактов и демонов не найдено.",
  "native root": "Native-скан чист.",
  "zygote heap residue": "Остатков в памяти zygote нет.",
  "virtualization": "Виртуализация не обнаружена.",
  "location risk": "Подмены геолокации нет.",
  "mount": "Подозрительных монтирований не видно.",
  "custom rom": "Следов кастомной ROM нет."
};

/* ---------- ПРИМЕР: разобранный отчёт POCO alioth ---------- */
const EXAMPLE_REPORT = {
  device: "POCO M2012K11AG (Android 17, API 37)",
  appVersion: "2026.11.01-31d82eef7fbb (Build 1103)",
  reportTime: "2026-11-01 23:13:10 (GMT+05:00)",
  counts: { danger: 2, warning: 7, ready: 20, pending: 0 },
  findings: [
    { severity: "danger", name: "SELinux",
      verdict: "Enforcing with recognized privileged contexts",
      quickFacts: "Mode: Enforcing (paradox) | Policy: Strong | Audit: Inconclusive | Context: untrusted_app",
      extra: "Dirty rule: system_server → system_server:process execmem = Allowed. KSU-контексты live-политикой отклонены (oracle 00). App-zygote пробы распознают привилегированный контекст (ADB root)." },
    { severity: "danger", name: "TEE",
      verdict: "Attestation aligned; local probes need review",
      quickFacts: "Verdict: Aligned + review | Tier: TEE | Trust: Google | Score: 10",
      extra: "KeyMint VINTF MISMATCH: keymasterVersion=41, attestationVersion=3, vintf=keymaster@4.0. RKP-метаданные: Xiaomi/fuxi_global:16, build: alioth:13, runtime: Android 17 — отпечатки расходятся." },
    { severity: "warning", name: "ADB Runtime",
      verdict: "ADB enabled",
      quickFacts: "ADB: Active | Contradictions: 0 | USB: adb | Network: Permission required",
      extra: "init.svc.adbd=running, JDWP-сокет подключён, при этом USB debugging setting: Disabled — противоречие." },
    { severity: "warning", name: "Dangerous Apps",
      verdict: "Platform behavior mismatch observed",
      quickFacts: "Runtime: 1 signal(s) | PM: Full · 409 | Hits: 1 | Hidden: 0",
      packages: ["MT Manager (bin.mt.termex) — через /sdcard/MT2"] },
    { severity: "warning", name: "LSPosed",
      verdict: "Dirty SELinux policy signal(s)",
      quickFacts: "Critical: N/A | Review: 1 | Bridge: Clean | Packages: Clean",
      extra: "Сам LSPosed чист (классы/binder/maps/logcat — 0). Горит только из-за dirty sepolicy: system_server execmem." },
    { severity: "warning", name: "Memory",
      verdict: "Runtime memory needs review",
      quickFacts: "Critical: Clean | Review: 1 | Hooks: Clean | Runtime: 1",
      extra: "webview.apk: 8 kB анонимных exec-страниц, pagemap не читается. Слабый сигнал." },
    { severity: "warning", name: "Network Risk",
      verdict: "Network risk indicators observed",
      quickFacts: "",
      packages: ["FlClash (com.follow.clash) — signature verified, version 2026104401", "Сеть 4: транспорт VPN+WIFI (caller default)"] },
    { severity: "warning", name: "Root Managers",
      verdict: "Root manager apps found",
      quickFacts: "Matches: 1 | Concealed: 0 | Apps checked: 409 | Profiles: 1 of 1",
      packages: ["KernelSU-Next (yqleqf.zfjhox.noqdwa): signing certificate + libksud.so + application class + label"] },
    { severity: "warning", name: "System Properties",
      verdict: "1 property signal(s) need review",
      quickFacts: "Critical: None | Review: 1 | Boot: Clean | Build: Clean",
      extra: "persist.sys.usb.config = adb (ожидаемо mtp). Boot-свойства (locked/green/enforcing) — чистые." },
    { severity: "clear", name: "Zygisk", verdict: "No Zygisk runtime signal",
      quickFacts: "State: Clear | Confidence: High | FD trap: Clean | Native: Ready" },
    { severity: "clear", name: "Play Integrity Fix", verdict: "No Play Integrity residue surfaced",
      quickFacts: "Direct: None | Review: None | Props: Clean | Native: Clean" },
    { severity: "clear", name: "Bootloader", verdict: "Locked and attested verified",
      quickFacts: "State: Verified | Proof: Attest | Tier: TEE | Trust: Google" },
    { severity: "clear", name: "Kernel Check", verdict: "No suspicious kernel markers",
      quickFacts: "Identity: Clean | Boot: Clean | Behavior: OK | Native: Loaded" },
    { severity: "info", name: "SU", verdict: "No root indicators",
      quickFacts: "Artifacts: None | Daemons: None | Context: Normal | Processes: 0" },
    { severity: "info", name: "Native Root", verdict: "Native root scan has reduced coverage",
      quickFacts: "Flags: None | Direct: Limited | Kernel: Clean | Runtime: Limited" },
    { severity: "info", name: "Mount", verdict: "Mount observation coverage is limited",
      quickFacts: "Critical: None | Review: None | Coverage: Partial | Native: Loaded" },
    { severity: "info", name: "Zygote heap residue", verdict: "No target trace observed",
      quickFacts: "Traces: 0 | Arguments: 316 | Coverage: Unknown" },
    { severity: "info", name: "Virtualization", verdict: "Virtualization scan has reduced coverage",
      quickFacts: "Danger: 0 | Review: 0 | Host: 0 | Native: Loaded" },
    { severity: "info", name: "Custom ROM", verdict: "Custom ROM scan has reduced coverage",
      quickFacts: "ROMs: None | Build: Unavailable | Runtime: None | Native: None" },
    { severity: "info", name: "Location Risk", verdict: "No local contract mismatch observed",
      quickFacts: "" }
  ]
};

if (typeof module !== "undefined") module.exports = { METHODS, FIXES, CLEAN_NOTES, EXAMPLE_REPORT };
