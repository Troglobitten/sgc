# Installer test

Runs the real installer on the clean test machine from [`../vm`](../vm), then drives the installed SGC the way a browser would.

```powershell
.\Test-Installer.ps1
```

| Step | What is checked |
|---|---|
| Altered download | One byte added to the archive: refused, nothing installed |
| Altered checksum list | Archive altered and the list recalculated to match, which is all an attacker without the key can do: refused, nothing installed |
| Wrong key | Genuine files signed with a different key: refused, nothing installed |
| Genuine release | Installs; reports the right version; runs as the unprivileged user `sgc`; starts at boot; program files owned by root; database and state folder private |
| Setup link | The installer prints a one-time link, and the fingerprint it prints matches the certificate actually served |
| Web interface and API | The interface is served over TLS only; a fresh install asks for setup; a wrong link is refused; the real link works exactly once; dashboard data needs a sign-in |
| Signing in and out | Sign out ends access; a wrong password is refused; the right one signs in |
| Root helper | Socket owned by `root:sgc`, closed to other users; answers the service user; has no "run a command" operation |
| Second run | Running the installer again is harmless and does not hand out a new setup link |
| Firewall | Off on a clean machine. Switched on, a stand-in neighbour with a public address no longer reaches SGC's page or SSH while one with a home address still does. Not confirmed: off again by itself after a minute. The process that waits for the confirmation killed, and then everything belonging to its unit killed: off again within seconds. Undone on request. Confirmed: stays, is saved where the web process cannot write, and loads at start-up. A request to the helper with anything but on or off is refused |
| SSH | On a machine that accepts passwords: a key added in the page needs the admin password again; a private key, a key with options and two keys at once are refused; the key is installed in a root-owned file without options or comment, and gets in. "Keys only" without a login with a key: passwords are refused at once and accepted again after two minutes. The waiting process killed, then its whole unit: undone within seconds. Undone on request. With a login with a key: stays, and the SSH server reports no passwords and no root. Under keys only, removing a key waits for a login with another key. Requests to the helper for root, or with an option on a key, are refused |
| Updates for the device | Nothing is written and no package tool is run until the owner chooses. By hand: SGC's settings file is in place and apt reads it; the page lists exactly what Debian's update tool would install; Debian's own daily run installs nothing; "Install now" installs them, and meanwhile a second installation, a look and a restart of the device are refused; the result names what was installed and is not taken for Debian's daily run. A look while Debian's servers cannot be reached says so and does not pass for a fresh one. A restart that an update needs is shown and not carried out. Requests to the helper that name a package are refused. A settings file that would overrule SGC's makes the choice fail with the reason. By themselves: apt reads it, and Debian's daily timers are started |
| AdGuard Home | Not there until asked for. Installed from the page: the pinned release, owned by root, running under an account of its own; it answers lookups and answers an advertising name with nothing. Its own page listens on the machine only; SGC passes it on to a signed-in owner and to nobody else, also not for changing settings. It asks Quad9 and keeps its log for 7 days. A rule the "owner" makes in its page takes effect. With the firewall on from before, a neighbour with a home address gets no answer until the rules are made afresh and confirmed; then it does, the neighbour with a public address still does not, and AdGuard Home's own page stays out of reach |
| Tampered update | An update whose archive was altered is refused before the root updater is even started; nothing changes |
| Genuine update | Installs through the API; SGC comes back as the new version; the earlier sign-in still works; the previous version is kept; the outcome is in the activity log; the firewall and "keys only" stay on throughout |
| Broken update | A correctly signed release whose program does not start: SGC goes back to the previous version and its data by itself, and says so; the firewall and "keys only" stay on throughout |
| Older release | Never offered, and refused if asked for |
| `sgc update` | Needs root; `--check` only looks; answering "no" changes nothing; `--yes` installs |
| Export | Needs the admin password again; a short passphrase is refused; the file is a standard age file with nothing readable in it; no temporary copy is left behind |
| Maintenance window | Off until switched on; times that are none are refused. With a restart needed and the window some hours away, nothing happens. With the window around now, SGC restarts the machine by itself, once, and the history says that it did and for what |
| Restart | (The button, in the test below.) A restart needs confirmation; SGC restarts the machine; afterwards SGC and the helper are back by themselves, the earlier sign-in still works and the restart is in the activity log; the firewall's rules were loaded again before the network came up, and the confirmed SSH settings were put in place before the SSH server started |
| `sgc doctor` | Needs root; reports no problems on the healthy machine; reports firewall rules, SSH settings and keys removed behind SGC's back, and its advice puts them back; reports a setting that overrules SGC's choice for the device's updates and a stopped daily timer, and mentions a restart that is needed without calling it a problem; reports a stopped SGC, and works without it |
| `sgc firewall` | The state can be read without root; `off` needs root, removes the rules for good, leaves SGC's files to its own user and is in the activity log; the firewall can be switched on again from the page |
| `sgc ssh` | The state can be read without root; `allow-passwords` needs root, makes the SSH server accept passwords again, keeps the keys, and is in the activity log |

After the restart the machine is wiped and installed again, and the export is restored through the setup link:

| Step | What is checked |
|---|---|
| Restore | Refused without the setup link or with a wrong passphrase; the preview names the account and changes nothing; after confirming, SGC comes back with the old account and password, the changed setting and the full history, including updates made on the old machine; the fresh install's setup link is closed; the firewall is shown as wanted but is not switched on unasked; how the old machine got its updates is shown and the new one is not set up unasked; AdGuard Home is shown as having been there, and installed here it starts with the settings from the old machine, the owner's own rule included; the SSH key from the old machine is listed but does not get in until it is installed, which needs the admin password again; "keys only" is shown as wanted and not switched on |

The test builds its own releases (the version under test and three later ones, one of them deliberately broken) and signs them with a throwaway key created on the spot (`make-test-release.sh`). The updates are served from a folder on the test machine itself. The stand-in neighbours for the firewall are network namespaces on the test machine: separate network stacks joined to it by a virtual cable, one with an address from a range reserved for examples (203.0.113.0/24), one with a private address. The real release key is never involved, and nothing built for the test is ever published. The admin account it creates uses a random password that exists only on the test machine.

`cases.sh` is the part that runs on the test machine.

## Updating from the previous release

```powershell
.\Test-UpgradeFromPrevious.ps1
```

An update is carried out by the version that is already installed, so a new release has to work with what the *previous* release's updater does with it. The installer test cannot see that: it installs the current source and updates it with its own updater.

This test builds the previous release from its tag (`make-upgrade-release.sh`), exactly as published except that it trusts a throwaway key, installs it on the clean test machine, and lets it update itself to the current source. It then checks that every unit of the new release is installed and will be part of start-up, and runs the firewall, SSH, restart and command-line steps from above on the machine that got there by updating. Updates for the device are tested the other way round here: set to install by themselves, after which Debian's own daily run is started and has to install everything that was waiting.

Both tests stop Debian's two daily timers when they reset the machine, and start Debian's daily run themselves where they want to see it. Left alone it would start within the hour after a reset, at a moment of its own choosing.

Run both tests before a release.
