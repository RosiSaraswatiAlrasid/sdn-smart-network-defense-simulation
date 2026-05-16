# Smart Network Defense System Simulation
## Using SDN (Ryu Controller + Mininet)

Proyek simulasi sistem keamanan jaringan berbasis SDN untuk mata kuliah Software Defined Network.

## Fitur
- IDS (Intrusion Detection System) — deteksi DoS, Port Scan, UDP Flood
- Firewall otomatis — blokir IP penyerang
- Dashboard real-time — monitoring via browser

## Teknologi
- Ryu SDN Controller
- Mininet Network Simulator
- OpenFlow Protocol
- Flask Web Dashboard

## Cara Menjalankan

### 1. Jalankan Ryu Controller
```bash
ryu-manager smart_defense.py
```

### 2. Jalankan Dashboard
```bash
python3 dashboard.py
```

### 3. Jalankan Topologi
```bash
sudo python3 topology.py
```

## Simulasi Serangan
```bash
# SYN Flood
h3 hping3 -S --flood server

# UDP Flood  
h3 hping3 --udp --flood server

# Port Scan
h3 nmap -sS server
```
