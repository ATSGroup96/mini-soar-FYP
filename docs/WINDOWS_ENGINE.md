# Running Mini-SOAR completely on Windows (no Kali)

Everything runs on your Windows PC in Docker Desktop. VirtualBox only runs the
lab targets (Metasploitable, and Ubuntu/Kali if you like as extra targets).

```
Windows PC (192.168.103.1)                       VirtualBox host-only lab
 ├─ Docker Desktop                                192.168.103.0/24
 │   ├─ api        :8000  ─┐                       ├─ Metasploitable 2 (.105)
 │   ├─ soar worker       ├── TCP through Windows ─┤  Ubuntu / Kali (optional)
 │   ├─ scanner (on demand)┘                        └─ any new device -> rogue
 │   └─ dashboard  :3000
 └─ Browser: http://localhost:3000
```

## What is different from the Kali version

| Feature | Kali (host mode) | Windows (nat mode) |
|---|---|---|
| Host discovery | ARP + ping | TCP "ping" on common ports (no ARP) |
| Port scan | SYN scan `-sS` | connect scan `-sT` (a bit slower, same ports found) |
| OS detection | nmap `-O` | guessed from service banners (e.g. "Linux - Ubuntu") |
| MAC address of hosts | yes | no (MAC is only visible on layer 2) |
| Rogue-device detection | by IP + MAC | by IP |
| CVE match, Nuclei, NetExec, ML score, tickets, patch prioritization, fixes, rollback, TLS, audit | same | same |

## One-time setup

1. **Docker Desktop** running (whale icon says "Engine running").
2. **VirtualBox**: Metasploitable's adapter = *Host-only* (`192.168.103.x`).
   In PowerShell run `ipconfig` and find the "VirtualBox Host-Only" adapter:
   its IPv4 is this PC's lab address (usually `192.168.103.1`).
3. In PowerShell: `ping 192.168.103.105` must answer. If not, the VM is off or on
   the wrong adapter.
4. Project folder: `F:\University\FYP MINI SOAR\mini-soar`. Copy your `.env` there
   (from Kali) and set:
   ```
   NETWORK_MODE=nat
   ENGINE_HOST_IPS=192.168.103.1/24
   DENY_HOSTS=192.168.103.1
   NEXT_PUBLIC_API_URL=auto
   ```
5. Start (first build takes 10+ minutes):
   ```
   cd "F:\University\FYP MINI SOAR\mini-soar"
   .\run.bat update
   ```
6. Open http://localhost:3000, log in, Settings -> Network scope -> click
   `windows-host: 192.168.103.0/24`, tick authorization, 2FA code, Save.
7. Prepare Metasploitable for fixes (new key for this PC):
   ```
   .\run.bat enroll 192.168.103.105 msfadmin
   ```

## Daily use

```
.\run.bat                 start
.\run.bat scan            start + scan the authorized scope
.\run.bat check 192.168.103.105
.\run.bat logs soar       watch fixes being applied
.\run.bat stop
```

## Notes

* `data` and `audit` are Docker volumes (`minisoar-data`, `minisoar-audit`), not
  folders on F:. On Windows this keeps SQLite and the audit file lock reliable.
  The first `update` re-downloads the CVE data and retrains/loads the model.
  for *Private* networks. With Docker Desktop the source IP shown can be Docker's
  gateway instead of the real VM address.
* Docker Desktop and VirtualBox share the CPU's virtualization: VMs may be a little
  slower. Give Docker Desktop at least 4 GB RAM (Settings -> Resources).
* The Kali way (`./start.sh`, `docker-compose.yml`) still works unchanged.
