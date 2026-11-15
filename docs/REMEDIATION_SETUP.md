# Remediation demo setup (Metasploitable 2 target)

One-time steps so the SOAR agent can apply fixes to `meta` (192.168.103.105)
from Kali (192.168.103.104). Lab only.

## 1. Upgrade the database (Supabase → SQL Editor)

Paste and run `supabase/migrations/002_v2_fixes.sql`. It removes duplicate
services/vulnerabilities and adds the `confidence` and `suggested_action`
columns. Safe to run more than once.

## 2. Rebuild and restart the engine (Kali)

```bash
cd ~/Downloads/mini-soar
docker compose build
docker compose up -d
```

## 3-5 the easy way: one command (recommended)

```bash
./start.sh enroll 192.168.103.105 msfadmin
```

It asks for msfadmin's password once (hidden, never stored), then creates the `soar` user,
installs the engine key (it creates `secrets/lab_id_rsa` if missing), writes the sudo rules
(checked with `visudo -c`, backup in `/etc/sudoers.mini-soar.bak`), locks the password,
clears the account expiry and prints a ready / not-ready checklist.
Test any time without changing anything: `./start.sh check 192.168.103.105`
or the **Test** button in the Assets page. Then continue at step 6.

The manual steps below are only a fallback.

## 3. Create a dedicated management user on meta

Log in to meta as `msfadmin`. Keep msfadmin as the "vulnerable default
account"; the agent uses its own `soar` user instead.

```bash
sudo useradd -m -s /bin/bash soar
sudo passwd soar          # temporary password, only for copying the key
```

## 4. Create the agent's SSH key (Kali)

Meta runs OpenSSH 4.7, which only understands RSA keys:

```bash
cd ~/Downloads/mini-soar
ssh-keygen -t rsa -b 2048 -m PEM -f secrets/lab_id_rsa -N ""
ssh-copy-id -o PubkeyAcceptedAlgorithms=+ssh-rsa -o HostKeyAlgorithms=+ssh-rsa \
    -i secrets/lab_id_rsa.pub soar@192.168.103.105
# test: must log in WITHOUT a password
ssh -o PubkeyAcceptedAlgorithms=+ssh-rsa -o HostKeyAlgorithms=+ssh-rsa \
    -i secrets/lab_id_rsa soar@192.168.103.105 'echo ok'
```

## 5. Allow the fix commands without a password (meta)

```bash
sudo visudo
```

Add this line at the end:

```
soar ALL=(ALL) NOPASSWD: /sbin/iptables, /usr/bin/passwd, /usr/bin/chage, /etc/init.d/*, /usr/sbin/update-rc.d, /bin/sed, /usr/bin/pkill
```

Lab note: `sed` as root can edit any file, so this is effectively full root
for the `soar` user. That is acceptable for an isolated lab; in production
you would wrap the edits in a single audited helper script instead.

Then lock the temporary password so only the key works, and clear the account
expiry that the old `passwd -l` on Metasploitable also sets (otherwise SSH says
"Your account has expired"):

```bash
sudo passwd -l soar
sudo chage -E -1 soar
```

## 6. Point the engine at the key (Kali `.env`)

```
SSH_PRIVATE_KEY_PATH=./secrets/lab_id_rsa
SSH_USERNAME=soar
FORCE_DRY_RUN=false
```

Then `docker compose up -d` again so the worker reloads `.env`.

## 7. Enrol 2FA

Dashboard → Settings → **Enroll TOTP**, then scan the QR with Google
Authenticator. Your profile role must be `admin`
(`update public.profiles set role='admin' where email='you@…';`).

## 8. Run the demo

1. Run a scan (one at a time).
2. **Tickets** → pick e.g. *Clear-text service telnet:23* → **Fix**. The
   suggested playbook (`stop_service telnet`) is pre-filled → **Create dry-run**.
3. **Topology** → what-if `block_port 21,1524,6667` to show the risk drop.
4. **Remediation** → **Review** → enter the 6-digit code → **Approve & arm**.
5. The worker applies the fix over SSH, verifies it on the host, and marks the
   ticket **resolved** (or rolls the change back automatically if it didn't verify).
6. **Details** → **Roll back this change** (needs a fresh 2FA code) to show undo.
7. Re-scan: the fixed port disappears and its CVEs turn `remediated`.
8. **Audit Log** → verify chain → "Chain intact".

Good first targets on meta: `stop_service telnet`, `block_port 1524`
(bind shell), `block_port 21` (vsftpd backdoor), `disable_account msfadmin`.
Port 22 and the `soar`/`root` accounts are protected and are refused.
