# Moving Mini-SOAR to a new network

Only your own lab, or a network you have WRITTEN permission to test.

1. VirtualBox: put Kali's lab adapter and the target VMs on the new host-only network.
2. On Kali: `ip a` -> note the lab adapter name (e.g. eth1) and Kali's new IP.
3. `.env` (once): `AUTHORIZED_LAB_ONLY=true`, `SCOPE_SOURCE=dashboard`, `NEXT_PUBLIC_API_URL=auto`.
4. `IFACE=eth1 ./start.sh update`
5. Open `http://<Kali IP>:3000` -> log in as admin -> **Settings -> Network scope**:
   - click the detected network (e.g. `eth1: 192.168.110.0/24`)
   - deny list: the gateway / your PC (the engine itself is added automatically)
   - tick "I own this network or have written permission", write who authorized it
   - enter your 2FA code -> **Save scope**
6. Top bar now shows the new range. Press **Run scan**.
7. Assets -> authorize your own devices (otherwise they show as rogue).
8. For fixes: on each new target create the `soar` user + SSH key + sudoers (docs/REMEDIATION_SETUP.md).

Limits the dashboard cannot change (only .env can): private ranges only (`SCOPE_CEILING`), /22 or smaller,
`AUTHORIZED_LAB_ONLY` master switch. Every scope change is in the Audit Log as `scope.update`.
