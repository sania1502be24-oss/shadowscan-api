# 🕵️ ShadowScan

### Web-Based Intelligent Port Scanner

ShadowScan is a web-based cybersecurity tool that scans TCP ports on authorized targets and presents the results through an interactive hacker-style dashboard.

It combines a **FastAPI backend** with a **HTML/CSS/JavaScript frontend** to provide real-time scanning progress, open-port detection, risk analysis, security findings, scan history, and report export.

> ⚠️ **Responsible Use:** Only scan systems, devices, and networks that you own or have explicit permission to test.

---

## 🚀 Live Demo

### Frontend
https://shadowscan-sen8.onrender.com

### Backend API
https://shadowscan-backend-2vwh.onrender.com

### API Documentation
https://shadowscan-backend-2vwh.onrender.com/docs

---

## ✨ Features

- 🔎 TCP port scanning
- ⚡ Concurrent port scanning
- 📊 Real-time scan progress
- 🟢 Open and closed port detection
- ⚠️ Port-based security risk analysis
- 🔥 High and critical risk identification
- 🛡️ Automated security findings
- 🖥️ Hacker-style interactive dashboard
- 🔍 Search and filter scan results
- 📜 Scan history
- 📄 TXT report export
- ⛔ Scan cancellation
- 🌐 Hostname and IP address validation
- 📡 Service detection for common ports
- 🧩 REST API using FastAPI
- ☁️ Cloud deployment using Render

---

## 🛠️ Technology Stack

### Frontend

- HTML5
- CSS3
- JavaScript
- Responsive UI

### Backend

- Python
- FastAPI
- Uvicorn
- Socket programming
- Concurrent scanning with ThreadPoolExecutor

### Deployment

- GitHub
- Render

---

## 📂 Project Structure

```text
ShadowScan/
│
├── backend/
│   ├── main.py
│   ├── requirements.txt
│   └── ...
│
├── frontend/
│   ├── index.html
│   ├── style.css
│   └── script.js
│
├── README.md
└── .gitignore