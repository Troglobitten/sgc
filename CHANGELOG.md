# Changelog

What changed in each version of SGC, newest first. The section for a version is what SGC shows before you update to it, so it is written for the person running SGC, not for developers.

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
