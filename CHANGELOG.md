# Changelog

What changed in each version of SGC, newest first. The section for a version is what SGC shows before you update to it, so it is written for the person running SGC, not for developers.

## 0.17.0

What you asked for after trying 0.16.

- **SGC's page opens at `https://sgc.your-domain`, without a port.** The proxy passes that name on to SGC itself, so it is SGC's own page with its own certificate, and SGC still sees which device you are on. With the proxy off (or not running) the page is where it always was, at `:8443` and at the device's address.
- **Icons without asking anyone outside.** SGC keeps a copy of the dashboard-icons collection on the device (about 20 MB, fetched once there is a service, looked at for news daily, or when you press "Update icons" on the Services page). Until now SGC asked a public CDN for each icon by your service's name.
- **A guided setup for a new device.** Setup starts with a choice: start fresh, or restore an export. Starting fresh takes you through the domain, the certificate, the device's name, the proxy, your SSH key, updates and, last, the firewall, one step at a time; any step can be skipped, and the dashboard keeps a list of what is left. (Devices that are already set up are not affected.)
- **Switching the proxy or the VPN on while the firewall is on** now offers to bring the firewall's rules up to date right there, with the usual confirmation, instead of on the System page.
- **The block for a server's compose file** can be shown again at any time on the Services page; the token itself is still shown only once.
- On a phone, the page links no longer make the page scroll sideways.

After updating, the proxy takes up the new way of passing on SGC's name by itself within a few seconds; nothing to do.

## 0.16.1

Fixes for things the page refused in 0.16.0.

- Switching the VPN on said "the request could not be read". It works now.
- The same happened when you changed a person or a service: both work now.
- When SGC refuses a request, the message now says what was wrong, so that a report of it points straight at the cause.

## 0.16.0

Everything SGC was meant to do is now there: names for your devices, the proxy, the VPN, people, the login gate, notifications, logs and backups. This is a large release; take a fresh export before you update (System page, Export).

**Names and the proxy**
- This device has a name under your domain (`sgc.your-domain`, changeable on the System page, Names), and its page opens there with the real certificate. By address it still opens with its own certificate, so there is always a way in.
- The proxy (Traefik) opens your services at `https://name.your-domain`, with the certificate. Switch it on on the new Services page; it is installed with SGC on new devices, and on updated ones when you switch it on.
- Add services by hand (a router, a printer, a NAS), or give a server running Docker a token and let it announce its own services when it starts (the Services page shows the block for its compose file). Game servers and other non-web services work too, by name (direct) or through a port of this device.
- The dashboard shows your services with their icons, grouped by category, with whether each answers. A friendly page says so when one does not.
- When the proxy or the VPN is on and the firewall's rules are older, the firewall card offers to bring them up to date (the usual confirmation).

**VPN and people**
- WireGuard: on the new People page, switch the VPN on, add people and their devices, and scan each device's QR code with the WireGuard app. Forward UDP port 51820 on your router to this device.
- Per person: the whole home network, all services, or only the services you pick. Guests get an end date, after which their devices and login stop.
- SGC keeps the VPN's public name (`vpn.your-domain`) pointing at your home's address at Zone.eu, also when that address changes, and says so when your provider shares one address between customers (then a VPN from outside cannot work).
- Usage per device: what it used, by the minute, hour and day.

**Login gate**
- Put a service behind SGC's login (Services page). You get in as yourself; people get in with the login you give them, and only to services on their list. People never get into SGC's own page.

**Notifications and logs**
- A bell at the top of every page, and a banner while a problem lasts. Optionally by email and to ntfy, per kind of event (System page, Notifications).
- The new Logs page: the notifications, the logs of each part of SGC (with a live view), and the full history.

**Backups and end of life**
- Daily backups to a share (SMB), an SFTP server or a WebDAV folder, the newest ten kept (System page, Backups). They are encrypted to a backup key that SGC shows you once and does not keep: keep it somewhere safe. To restore one, enter that key where the passphrase goes.
- SGC tells you when Debian or Traefik is about to stop getting security fixes.

**Also**
- `sudo sgc reset-admin` gives the admin a new password if it is lost or got out, and ends every admin sign-in, on SGC's page and at services behind the login gate.
- `sudo sgc doctor` checks the names, the proxy, the VPN, backups and end-of-life dates too.

What only you can check, because no test of SGC can: a phone on mobile data connecting to the VPN through your router, email through your provider, ntfy on your phone, and backups to your own NAS.

## 0.15.1

- Fixed: the first real certificate could fail with "Let's Encrypt refused: Incorrect TXT record … found". SGC tries with Let's Encrypt's test authority first, and both proofs are published under the same name in your domain's DNS. SGC asked Let's Encrypt to look as soon as the name servers it could reach showed the new proof; Let's Encrypt, asking from other parts of the world, still got the old one.
- SGC now waits: two minutes between the trial and the real request, and two minutes more in every attempt after it sees the proof itself. Getting the first certificate therefore takes about ten minutes instead of a few, and a renewal about three. It still runs by itself in the background, and the page says what it is waiting for.
- If Let's Encrypt does not find the proof, the page now says that in plain words, and that trying again later usually works.
- Fixed: on a device where AdGuard Home had taken over the DNS port after SGC started, SGC's checks for the certificate went through AdGuard Home. They now always use the device's own DNS servers, so getting and renewing a certificate does not depend on AdGuard Home running.
- If your first attempt failed with the message above: nothing is wrong with your set-up. Press "Get the certificate" again once the page allows it (fifteen minutes after a failure).

## 0.15.0

- The certificate: SGC can now get a real certificate from Let's Encrypt for every name under your domain (`*.your-domain`). On the System page, under "Network", press "Get the certificate". It takes a few minutes and goes on by itself if you leave the page.
- SGC proves to Let's Encrypt that the domain is yours by publishing a piece of text in its DNS through your Zone.eu account, and removes it again afterwards.
- Before the real certificate, SGC goes through the same steps with Let's Encrypt's test authority. If the set-up has a mistake in it, it shows there, where it does not count against your domain. Only if that works does SGC ask for the real one.
- You are asked once to agree to Let's Encrypt's Subscriber Agreement. SGC does not agree on your behalf.
- Good to know before you start: every certificate is listed in public logs. That a certificate for `*.your-domain` exists will be public. The names of your services are not in it, which is why SGC uses one certificate for all names.
- SGC renews the certificate by itself, at the time Let's Encrypt suggests, and tries again twice a day if that fails. "Renew now" does it at once; because Let's Encrypt counts requests, the button waits two days after a certificate and fifteen minutes after a failure.
- If something fails, the page says what, in words, and shows the steps as they were reported. The dashboard and `sudo sgc doctor` show how many days the certificate has left, and warn when renewing fails.
- The certificate, its key and SGC's account at Let's Encrypt are part of an export. A restored device has its certificate back without asking for a new one. No key is ever shown in the page or written to the log.
- Not yet: SGC's own page still uses its self-signed certificate. Serving the page under the new one, at a name of its own, is the next version.

## 0.14.0

- Your domain: on the System page, under "Network", you can now enter the domain your names will end in and the Zone.eu account that holds its DNS (your ZoneID username and an API key). This is the first step towards a real certificate, which the next version gets.
- SGC asks Zone.eu before saving, and saves nothing Zone.eu does not accept: a wrong key, or a domain that is not in that account, is refused with the reason.
- SGC then asks Zone.eu again every few hours. If the key stops being accepted, for example because it was replaced or withdrawn at Zone.eu, the dashboard and the System page say so, and `sudo sgc doctor` reports it. Later this is what will warn you weeks before a certificate fails to renew.
- The API key opens your whole Zone.eu account. SGC keeps it on the device and in exports, sends it to Zone.eu only, and never shows it again, not in the page, the activity log or its own log.
- The domain and the Zone.eu account are part of an export and come back with a restore.

## 0.13.0

- Logs in memory, for a device that runs from an SD card: a new switch on the System page, under "This device". Switched on, the device's logs are kept in memory and written to the card once a day and at shutdown, instead of all the time, which spares the card. It uses log2ram, from Debian's own archive.
- It comes with SGC, switched off: the installer installs it, and you switch it on if your device runs from an SD card. SGC does not try to detect that. A device that updates from an earlier version gets log2ram when you switch it on.
- Switching it on or off takes effect when the device restarts; the page says so until then. After a power cut, the log entries since the last write to the card are gone.
- It is made to stay stable when the logs get too big for the memory set aside for them (128 MB):
  - Before switching on, SGC checks that the logs fit with room to spare. If they do not, it refuses, changes nothing, and names what is in the way.
  - While it is switched on, the system journal, the one log that grows by itself, is limited to a quarter of that space. Switching on removes older journal entries beyond that.
  - If the space fills up all the same, the device keeps working. This was tried with DNS, SGC's page, SSH and installing updates. Log entries get lost until there is room again. The page and `sudo sgc doctor` warn from four fifths full, and name what takes the room.
  - If the logs do not fit at a restart, they stay on the card for that run and nothing is lost; the page says so. Once there is room, they go into memory again by themselves at the next restart.
  - SGC does not switch it on where it would take more than a quarter of the device's memory.
- AdGuard Home's query log is easier on an SD card as well. A newly installed AdGuard Home collects 5000 lookups in memory before writing them to its log in one go, instead of 1000. That is a fixed number of lookups, so it cannot outgrow the memory. After a power cut the lookups not yet written are missing from the log; a normal stop or restart writes them. An AdGuard Home that is already installed keeps its settings.
- Good to know: on Raspberry Pi OS the system journal is already kept in memory, by a setting Raspberry Pi ships. There, "logs in memory" only moves the smaller logs.

## 0.12.0

- DNS now comes with SGC. The installer installs AdGuard Home and starts it, so a new device answers the name lookups of your network from the start. The installer tells you so. To use it, enter the device's address as the DNS server in your router, or on single devices.
- On the System page, DNS is a switch: on or off. Switching it off stops AdGuard Home answering; nothing is removed and your settings stay. The "Install" and "Remove" buttons are gone.
- AdGuard Home now answers home-network addresses only, by itself, also while the firewall is off. This is set where this version installs AdGuard Home. On a device where 0.11.0 installed it, your existing settings are left alone: there the firewall does this once it is on, or you set it in AdGuard Home's page under "Settings", "DNS settings", "Access settings".
- After a restore your DNS settings are back without a click: SGC puts the settings from the export into AdGuard Home and switches it on or off as it was. AdGuard Home checks the settings first, and if it does not stay up on them the previous ones come back. If it could not be done, the System page says so and offers to try again.
- A device that updates from 0.11.0 and has no AdGuard Home gets nothing installed unasked. Switching DNS on installs it.
- New on the command line: `sgc dns` says whether DNS is on, and `sudo sgc dns on` and `sudo sgc dns off` do what the switch does.
- If the installer cannot download AdGuard Home, SGC is installed all the same and says so. Switch DNS on later, on the System page.
- `sudo sgc doctor` tells a DNS that is switched off from one that should be running and is not.

## 0.11.0

- DNS: SGC can now install AdGuard Home, which answers the name lookups of your network and leaves out advertising and tracking. One button on the System page installs it; SGC keeps it running, also when SGC itself is not.
- To use it, enter this device's address as the DNS server in your router, or on single devices.
- AdGuard Home's own page opens from SGC, behind SGC's sign-in. It has no separate login. What it blocks, whom it asks and what it logs are your settings, made there; SGC sets them once, at installation, and never touches them again.
- It starts out asking Quad9 over an encrypted connection, with a log of lookups kept for 7 days and AdGuard's own blocklist.
- With the firewall on, DNS is let in from your home network only. If the firewall was switched on before AdGuard Home was installed, the System page offers "Let DNS in", which you confirm like any firewall change.
- SGC downloads AdGuard Home from its makers and only installs the exact file this version of SGC expects. A newer AdGuard Home arrives with a newer SGC.
- On a Debian that runs systemd-resolved (a Raspberry Pi does not), installing AdGuard Home makes that service give up the DNS port and points the device's own lookups at the real name servers. Removing AdGuard Home puts that back.
- Your AdGuard Home settings are part of an export. After a restore, installing AdGuard Home on the new device starts it with them.
- Fixed: right after installation, two of SGC's programs opening its new database in the same instant could, very rarely, fail with "database is locked".
- `sudo sgc doctor` checks AdGuard Home, and tells you if another program sits on a port SGC needs. Right after a restart it no longer reports the clock as a problem.

## 0.10.0

- Maintenance window: on the System page you can set a time of day at which SGC may restart the device by itself, if an installed update needs a restart. It is off until you switch it on. Outside the window, and while it is off, nothing restarts by itself.
- SGC restarts the device at most once per window, never in the first minutes after start-up, never while updates are being installed, and only once the device's clock has been set from the network. The page shows what the device's own clock says.
- SGC's own updates can now install by themselves: a new switch on the dashboard, off by default. A new version then installs in the maintenance window once your device has known it for 3 days. The "View update" button still installs it sooner.
- If SGC itself is not running, nothing happens in the window.
- After restoring an export, the window and this switch are set as they were on the old device.

## 0.9.0

- Updates for the device: the System page now looks after the updates of the device itself (Debian's security fixes and corrections), which are separate from SGC's own updates. You choose once how they are installed: by themselves, once a day, or by hand, when you press "Install now" on that page.
- Either way the same updates are installed, by Debian's own update tool. On a Raspberry Pi that includes its kernel and firmware, which come from Raspberry Pi and not from Debian.
- The page shows what is waiting. SGC looks once a day; "Look now" does it at once.
- Nothing restarts the device by itself. When an installed update needs a restart to take effect, the System page and the dashboard say so, and you restart when it suits you. (A time window in which SGC may do that for you comes with the next version.)
- Until you have chosen, SGC changes nothing about how the device gets its updates, and the page tells you what the device does of its own accord.
- The Restart button refuses while updates are being installed.
- `sudo sgc doctor` also checks the device's updates now.
- After restoring an export, the page shows how the old device got its updates. The new device is not set up until you choose.

## 0.8.0

- SSH keys: the System page can add SSH keys for an account on the device. You paste the public key; SGC asks for your password again, because a key is a way to log in to the device itself. The keys travel with an export.
- "Keys only": one switch makes SSH refuse passwords and logins as root. It takes effect at once and stays only if SGC then sees a login with a key within two minutes. Otherwise passwords are accepted again by themselves, and so they are after a restart during that time.
- The switch is only offered once SGC has seen a login with a key, so that a key is known to work before passwords are refused.
- Under "keys only", removing a key works the same way: it comes back unless a login with another key is seen.
- `sudo sgc ssh allow-passwords` makes SSH accept passwords again from the device itself, should a key ever stop working.
- `sudo sgc doctor` also checks SSH now.
- After restoring an export, the keys are listed but not installed, and "keys only" is not switched on. Both are steps for you to take on the new device.
- Fixed: undoing a firewall change with the "Undo" button could, now and then, leave the firewall's rules in effect while SGC showed the firewall as off. If you used "Undo" in 0.7.0, check with `sudo sgc doctor`; it reports that state and how to clear it.

## 0.7.0

- Firewall: the new System page can switch on a firewall for this device. With it on, SGC's page and SSH answer only to devices in your home network; anything else that arrives uninvited is ignored.
- A safety net against locking yourself out: a firewall change takes effect at once, and the page then asks you to confirm that you can still reach SGC. Without that confirmation within 60 seconds, SGC undoes the change by itself. Restarting the device also returns to the last state you confirmed.
- The first time the firewall is switched on, SGC installs the firewall software (nftables) from Debian.
- `sudo sgc doctor` checks every part of SGC over SSH and says what to do about anything that is wrong. It works when SGC's page does not.
- `sudo sgc firewall off` switches the firewall off from the device itself, should that ever be needed.
- Export and Restart have moved from the dashboard to the new System page. The dashboard shows whether the firewall is on.
- After restoring an export, the firewall is not switched on by itself. SGC shows that it was on before and leaves the step, with its confirmation, to you.

## 0.6.0

- Export: the dashboard can save everything SGC holds (your account, settings and history) as one encrypted file, protected by a passphrase you choose. SGC asks for your password again before it does.
- Restore: on a fresh install, the setup link now also offers "Restore from an export". You see what the file contains before anything is restored.
- The export uses the standard age format, so it can be opened without SGC if ever needed: `age -d export.age | tar -x`.
- A newer SGC can restore an export made by an older one.

## 0.5.0

- SGC can update itself. The dashboard shows when a newer version exists; one click installs it, and `sudo sgc update` does the same over SSH.
- If a new version does not start correctly, SGC goes back to the previous one by itself, including its data, and tells you what happened.
- Updates are only accepted if they carry a valid signature and are newer than the installed version.
- SGC looks for a newer version once a day. A switch on the dashboard turns that off.

## 0.4.0

- A one-time setup link, printed by the installer, for creating the admin account in a browser.
- Sign-in, with a lock-out after repeated wrong passwords.
- A first dashboard: processor, memory, disk, temperature, uptime, recent activity, and a Restart button.
- Light and dark appearance, following your device.

## 0.3.0

- The one-line installer, which only installs a release that carries a valid signature.
- SGC runs as a locked-down background service.

## 0.2.0

- First build of the `sgc` program for PC and Raspberry Pi.
