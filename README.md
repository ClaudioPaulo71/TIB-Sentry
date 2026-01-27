# TIB-Sentry | Network Asset Management & Security Audit

**TIB-Sentry** is a professional-grade network security tool designed for real-time asset discovery and governance. Developed by **Technologie & Investment Business (TIB)**, it empowers administrators to monitor, classify, and secure local area networks (LANs).



## 🚀 Key Features

* **Active ARP Scanning:** High-speed network discovery using Scapy.
* **Manufacturer Identification (OUI):** Automated vendor lookup (Apple, Intel, Cisco, etc.) via the `manuf` database.
* **Zero-Trust Governance:** Default "Unknown" status for new devices, requiring manual operator authorization.
* **Persistent Inventory:** SQLite-backed storage to maintain custom device nicknames and security classifications.
* **Professional Dashboard:** High-contrast Dark Mode UI optimized for QHD (2560x1440) monitoring environments.

## 🛠️ Tech Stack

* **Backend:** Python 3.13, Flask
* **Network Engine:** Scapy (Layer 2 Discovery)
* **Database:** SQLAlchemy (SQLite)
* **Frontend:** Bootstrap 5 (Cyber-Night Theme)

## 📋 Prerequisites

* Python 3.10+
* `libpcap` (for packet sniffing)
* Root/Sudo privileges (required for Raw Socket access on Linux)

## 🔧 Installation & Setup

1. **Clone the repository:**
   ```bash
   git clone [https://github.com/your-username/TIB-Sentry.git](https://github.com/your-username/TIB-Sentry.git)
   cd TIB-Sentry