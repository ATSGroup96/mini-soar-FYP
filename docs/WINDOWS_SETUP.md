# Windows target setup (auto-remediation on Windows)

The agent fixes Windows hosts the same way it fixes Linux ones: key-based SSH,
then PowerShell playbooks. Windows 10/11 and Windows Server 2019+ ship an
OpenSSH Server; it only needs to be switched on. Lab only.

| Playbook | What runs on Windows | Rollback |
|---|---|---|
| block_port | Windows Firewall inbound **Block** rule `MiniSOAR-Block-TCP-<port>` | rule removed |
| stop_service | `Stop-Service` + startup type **Disabled** (old type saved in `C:\ProgramData\MiniSOAR`) | old startup type restored, service started |
| disable_account | `Disable-LocalUser` | `Enable-LocalUser` |

Port 22 (OpenSSH), the `sshd` service, `Administrator` and the engine's own
`soar` account are protected and are always refused.

## 1. Create the VM

- Any Windows 10/11 or Windows Server 2019/2022 VM works. A free 90/180-day
  **evaluation** ISO is available from the Microsoft Evaluation Center.
- VirtualBox → Network → **Adapter 1: Host-only**, the SAME host-only network
  as Kali (so it gets a `192.168.103.x` address, inside ALLOWED_RANGES).
- Inside Windows run `ipconfig` and note the IPv4 address (example below:
  `192.168.103.110`).

## 2. Turn on OpenSSH Server (PowerShell **as Administrator**)

```powershell
Add-WindowsCapability -Online -Name OpenSSH.Server~~~~0.0.1.0
Start-Service sshd
Set-Service sshd -StartupType Automatic
Set-NetConnectionProfile -NetworkCategory Private
```

## 3. Create the agent's admin account

```powershell
net user soar * /add          # type a temporary password when asked
net localgroup Administrators soar /add
```

## 4. Install the agent's public key (from Kali)

Use the same key as for meta (`secrets/lab_id_rsa`). One key serves all lab hosts.

```bash
cd ~/Downloads/mini-soar
scp secrets/lab_id_rsa.pub soar@192.168.103.110:C:/ProgramData/ssh/administrators_authorized_keys
```

Then on Windows (PowerShell as Administrator) lock the file down — OpenSSH
ignores the key file if other users can edit it:

```powershell
icacls C:\ProgramData\ssh\administrators_authorized_keys /inheritance:r /grant "Administrators:F" /grant "SYSTEM:F"
Restart-Service sshd
```

Test from Kali — it must NOT ask for a password:

```bash
ssh -i secrets/lab_id_rsa soar@192.168.103.110 whoami
```

## 5. Make it a realistic "office PC" target for the demo

```powershell
# Remote Desktop on (exposes 3389)
Set-ItemProperty 'HKLM:\System\CurrentControlSet\Control\Terminal Server' -Name fDenyTSConnections -Value 0
Enable-NetFirewallRule -DisplayGroup "Remote Desktop"
# File sharing on (exposes 445)
Enable-NetFirewallRule -DisplayGroup "File and Printer Sharing"
# a weak local account to disable later
net user admin admin /add   # on Windows Server use a simple-but-allowed password, e.g. Admin123!
```

Keep Windows Firewall **on** (default). The block playbook checks this and
fails safely (auto-rollback) if every firewall profile is off.

## 6. Demo

1. Run a scan of the Windows IP. nmap should report a Windows OS guess, and
   tickets appear: *Exposed Remote Desktop (RDP) :3389*, *Exposed SMB file
   sharing :445*, each with a Windows suggested fix.
2. Tickets → **Fix**. *Target OS* shows `windows` (pick it manually if nmap
   could not fingerprint the OS). **Create dry-run** shows the exact PowerShell.
3. Remediation → **Approve & arm** with the 6-digit code.
4. The agent adds the firewall rule, then checks from Kali that 3389 is closed
   → ticket **resolved**. On Windows you can see the rule in
   *Windows Defender Firewall → Inbound Rules → MiniSOAR-Block-TCP-3389*.
5. **Roll back** (new 2FA code) → rule removed, RDP reachable again.
6. Account demo: on a ticket pick `disable_account` with username `admin`.
   The agent disables it and confirms `Enabled = False`.

Note: the default-credential checker tests SSH, FTP and HTTP logins only (not
SMB/RDP), so on Windows the `disable_account` playbook is chosen manually.
