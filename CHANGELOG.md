# Changelog

What changed in each version of SGC, newest first. The section for a version is what SGC shows before you update to it, so it is written for the person running SGC, not for developers.

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
