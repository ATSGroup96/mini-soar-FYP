# Mini-SOAR on Windows without Docker ("native" mode)

Everything runs directly on the Windows PC as normal programs. VirtualBox only
runs the lab targets (Metasploitable, Ubuntu, Windows VM ...).

Because the Windows PC itself sits on the VirtualBox Host-only network
(e.g. `192.168.56.1`), Nmap + Npcap can send raw packets there. So the scan is
**the same as on Kali**: ARP discovery with MAC addresses, SYN scan, nmap OS
detection.

```
Windows PC (192.168.56.1)                        VirtualBox host-only lab
 ├─ api        :8000  (Python)  ─┐                 192.168.56.0/24
 ├─ soar worker       (Python)   ├── Nmap + Npcap ─┤  Metasploitable 2 (.101)
 ├─ nuclei / nxc (tools\\)      │   (raw packets) ├─ Ubuntu / Windows VM ...
 ├─ dashboard  :3000  (Node.js) ─┘                 └─ any new device -> rogue
 └─ Browser: http://localhost:3000
```

## Compared with the other ways

| | Kali (`host`) | Windows + Docker Desktop (`nat`) | **Windows native** |
|---|---|---|---|
| Host discovery | ARP + ping | TCP on common ports | **ARP + ping (Npcap)** |
| MAC address / rogue by MAC | yes | no | **yes** |
| Port scan | SYN `-sS` | connect `-sT` | **SYN `-sS`** |
| OS detection | nmap `-O` | from banners | **nmap `-O`** |
| Docker needed | yes (on Kali) | Docker Desktop | **no** |

## Install once (all free)

1. **Python 3.11** - https://www.python.org/downloads/ (Windows installer 64-bit).
   Tick **"Add python.exe to PATH"**.
2. **Nmap for Windows** - https://nmap.org/download (the `nmap-x.xx-setup.exe`).
   Keep **Npcap** ticked during the install (Npcap is the packet driver that
   makes ARP / SYN scan / OS detection possible on Windows).
3. **Node.js 20 LTS** - https://nodejs.org (for the dashboard).
4. **VirtualBox network**: the targets use a *Host-only* adapter. In PowerShell,
   `ipconfig` must show a "VirtualBox Host-Only" adapter with the lab address
   (e.g. `192.168.56.1`), and `ping 192.168.56.101` must answer.

## Project folder + .env

1. Unzip / clone the project, e.g. `F:\Softwares for Mini SOAR\mini-soar`.
2. Put your `.env` there (copy it from Kali or from `.env.example`) and set:
   ```
   NETWORK_MODE=native
   ALLOWED_RANGES=192.168.56.0/24
   DENY_HOSTS=192.168.56.1
   NEXT_PUBLIC_API_URL=auto
   ```
   The PC's own lab address is found automatically and never scanned.
3. If you have one: put the engine SSH key in `secrets\lab_id_rsa`
   (copied from Kali). Then targets enrolled from Kali keep working.

## Start

```
cd "F:\Softwares for Mini SOAR\mini-soar"
.\run.bat update
```

* Windows asks for **Administrator** (needed for raw packets) and opens an
  Administrator window, which does the rest.
* The first `update` creates `.venv` and installs the Python packages (about
  1 GB, 5-15 minutes), builds the dashboard (5-10 minutes), syncs CVEs and scans.
* Windows Firewall may ask about **python.exe** / **node.exe**: allow on
  **Private** networks.
* Open http://localhost:3000 and log in.

## Daily use

```
.\run.bat                          start
.\run.bat scan                     start + scan the whole authorized scope
.\run.bat scan 192.168.56.101      scan one host (comma for several)
.\run.bat enroll 192.168.56.101 msfadmin
.\run.bat check 192.168.56.101
.\run.bat logs soar                live log (api, soar, dashboard)
.\run.bat stop
```

Logs are in the `logs\` folder, the CVE database / model / scan lock in
`data\`, the audit chain in `audit\`.

## Switching back

* To Kali: `.\run.bat stop` here, then `./start.sh` on Kali.
* To Docker Desktop: set `NETWORK_MODE=nat` (+ `ENGINE_HOST_IPS`) in `.env`.

Only one engine at a time when they share the same Supabase project.

## Troubleshooting

| Problem | Fix |
|---|---|
| `Nmap not found` | install Nmap, or set `NMAP_PATH=` in `.env` to the full path of `nmap.exe` |
| `Npcap missing` | run the Nmap installer again and tick Npcap |
| `Python 3.11 not found` | install it and tick "Add to PATH"; close and reopen PowerShell |
| `API not answering` | `.\run.bat logs api` |
| Scan finds no MAC / no OS | the window must be **Administrator**; Npcap must be installed |
| Port 3000 / 8000 already in use | Docker Desktop version still running: `docker compose -f docker-compose.windows.yml down` |
