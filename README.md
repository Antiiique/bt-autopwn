# BT-AutoPwn v3.1
### Bluetooth Security Framework — Kali Linux / Raspberry Pi 4

Outil de test de sécurité Bluetooth tout-en-un avec interface graphique cyberpunk, automatisation complète et explications en français.

---

## ⚠️ AVERTISSEMENT LÉGAL — USAGE ÉDUCATIF UNIQUEMENT

> **Cet outil est conçu exclusivement pour l'apprentissage, les tests autorisés et la recherche en sécurité.**

### Usages autorisés ✅
- Tests sur des appareils **vous appartenant** ou avec **autorisation écrite explicite**
- Missions de pentest avec contrat signé
- Compétitions CTF, travaux pratiques académiques, labs isolés
- Apprentissage des techniques d'attaque **pour mieux se défendre**

### Usages interdits ❌
- Attaquer des appareils sans autorisation
- Intercepter des communications de tiers
- Perturber des systèmes (DoS, flood, jamming)
- Toute activité illégale

### Cadre légal français applicable

| Article | Infraction | Peine maximale |
|---------|-----------|----------------|
| **Art. 323-1 CP** | Accès frauduleux à un STAD (système informatique) sans autorisation | 2 ans · 60 000 € |
| **Art. 323-1 CP** (aggravé) | Accès + suppression ou modification de données | 3 ans · 100 000 € |
| **Art. 323-2 CP** | Entrave au fonctionnement d'un système (DoS, flood BLE, jamming) | 5 ans · 150 000 € |
| **Art. 323-3 CP** | Introduction ou altération frauduleuse de données dans un système | 5 ans · 150 000 € |
| **Art. 323-3-1 CP** *(Loi LCEN 2004)* | Détention ou diffusion d'outils d'intrusion informatique hors autorisation | 2 ans · 30 000 € |
| **Art. 226-15 CP** | Interception de communications privées sans consentement (audio BT, données) | 1 an · 45 000 € |
| **Loi n°91-646 du 10/07/1991** | Interception de communications électroniques hors cadre légal | Peines correctionnelles |
| **RGPD — Règlement (UE) 2016/679** | Collecte de données personnelles sans base légale (contacts PBAP, audio) | Jusqu'à 20 M€ ou 4 % CA mondial |

> 💡 **En pratique :** utiliser cet outil sur un appareil qui ne vous appartient pas, ou sans autorisation écrite préalable, constitue une **infraction pénale** en France, même si vous n'en avez pas l'intention.
>
> **On apprend à attaquer pour mieux se défendre. Restez dans la légalité.**
> **Les auteurs déclinent toute responsabilité en cas de mauvais usage.**

---

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
