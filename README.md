# BT-AutoPwn v3.1
### Bluetooth Security Framework — Kali Linux / Raspberry Pi 4

Outil de test de sécurité Bluetooth tout-en-un avec interface graphique cyberpunk, automatisation complète et explications en français.

> **Usage personnel uniquement — appareils vous appartenant.**

---

## Fonctionnalités

### Interface
- GUI moderne (ttk.Notebook, 4 onglets) + mode CLI semi-automatisé
- Thème cyberpunk (fond noir, vert néon, cyan)
- Explications détaillées en français sur chaque attaque (hover → panel EXPLICATION)
- Conseils contextuels intelligents (Advisor) + boutons ▶ LANCER cliquables

### Scan & Détection
- Scan BLE + BT Classic simultané avec RSSI live
- Énumération complète : SDP, GATT, services, profils
- Score de risque 0–100 par appareil (RSSI + firmware + services + vulns)
- Fingerprinting fabricant via OUI

### Auto-sélection d'adaptateur
- Détection automatique des adaptateurs (DUAL / BLE_ONLY / CLASSIC)
- Routage intelligent par type d'attaque (BLE → hci1, Classic → hci0…)

### Full Auto Chain
- Séquence d'attaque automatique en 5 phases :
  1. Recon (SDP / Bettercap BLE)
  2. Énumération approfondie
  3. Priorités critiques (HFP micro, HID injection, PBAP dump)
  4. Escalation (RFCOMM, GATT, BLE MITM)
  5. CVE checks (BlueBorne, KNOB)

### Attaques (18 modules)
| Catégorie | Modules |
|-----------|---------|
| Recon | SDP Enumeration, RFCOMM Scan, Bettercap BLE Bridge |
| Exploit | GATT Write, RFCOMM Connect, BLE MITM, Notification Replay, PBAP Dump, OBEX Push, Bluejacking, HID Injection |
| Audio | Audio Intercept HFP/HSP (Blue Phantom) |
| DoS | BLE Deauth, BLE Crasher, ZeroJam Mesh Flood |
| CVE | BlueBorne (CVE-2017-1000251), CVE-2017-0785, KNOB (CVE-2019-9506) |
| Stealth | MAC Spoof, Broadcast Alias Loop |

### Export
- Session complète : JSON + TXT + CSV
- **Rapport HTML** (design cyberpunk, scores de risque, résultats par appareil)

---

## Installation

```bash
# Dépendances système
sudo apt install bluetooth bluez bluez-tools python3-pip \
     bettercap hcitool sdptool gatttool l2ping btmgmt \
     pulseaudio-utils lame python3-tk

# Dépendances Python
pip3 install rich

# Lancer
sudo python3 bt_autopwn.py --gui   # Mode GUI
sudo python3 bt_autopwn.py         # Mode CLI
```

---

## Matériel testé
- Raspberry Pi 4 (8GB) — Kali Linux
- 2× adaptateurs Bluetooth USB (DUAL mode recommandé pour MITM)

---

## Structure

```
bt_autopwn.py          # Script principal (~2600 lignes)
├── Section 1-4        # Config, dataclasses, logger, helpers
├── Section 5          # Smart Adapter Manager
├── Section 6          # Scan engines (Classic + BLE)
├── Section 7          # Énumération + analyse vulnérabilités
├── Section 8          # 18 modules d'attaque
├── Section 9          # Registry + auto_chain + HTML report + risk_score
├── Section 9.5        # EXPLANATIONS (19 entrées) + Advisor + TIP_ACTIONS
├── Section 10         # CLI mode
└── Section 11-12      # GUI mode (tkinter) + entry point
```

---

## Inspirations
- [ZeroSync](https://github.com/wickednull/ZeroSync)
- [Blue Phantom](https://github.com/CyberGuard-Anil/blue_phantom)
- BlueBorne (Armis Research)
- KNOB Attack (francozappa)
