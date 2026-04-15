cat > ~/modbus-zeek-monitor/README.md << 'EOF'
# modbus-zeek-monitor

> Real-time Modbus TCP traffic analysis and anomaly detection using the Zeek Network Security Monitor.

![License](https://img.shields.io/badge/license-MIT-green)
![Python](https://img.shields.io/badge/python-3.10+-blue)
![Zeek](https://img.shields.io/badge/zeek-6.x-orange)
![Status](https://img.shields.io/badge/status-active-brightgreen)

## Overview

Framework for monitoring industrial OT networks running Modbus TCP. Combines Zeek deep packet inspection with Python-based log analysis to detect anomalies, unauthorized commands, and suspicious traffic patterns in real time.

## Features

- Modbus TCP traffic capture and parsing via Zeek
- Anomaly detection: unauthorized function codes, unexpected device pairs, volume spikes
- Python-based log analyzer with color-coded terminal output
- Simulated Modbus traffic generator for lab testing
- Docker-ready deployment

## Project Structure
modbus-zeek-monitor/
├── zeek/ # Zeek scripts
├── analyzer/ # Python log analysis
├── simulator/ # Modbus TCP traffic simulator
├── docker/ # Docker files
├── tests/ # Unit tests
└── docs/ # Documentation

text

## Author

**Mateo Gallego** — Mechatronic Engineer & OT Security Specialist
EOF

cd ~/modbus-zeek-monitor
git add README.md
git commit -m "docs: add project README with overview and structure"
git push
