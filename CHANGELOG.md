# Changelog

What changed in each version of SGC, newest first. The section for a version is what SGC shows before you update to it, so it is written for the person running SGC, not for developers.

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
