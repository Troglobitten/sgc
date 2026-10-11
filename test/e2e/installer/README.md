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
| Tampered update | An update whose archive was altered is refused before the root updater is even started; nothing changes |
| Genuine update | Installs through the API; SGC comes back as the new version; the earlier sign-in still works; the previous version is kept; the outcome is in the activity log |
| Broken update | A correctly signed release whose program does not start: SGC goes back to the previous version and its data by itself, and says so |
| Older release | Never offered, and refused if asked for |
| `sgc update` | Needs root; `--check` only looks; answering "no" changes nothing; `--yes` installs |
| Export | Needs the admin password again; a short passphrase is refused; the file is a standard age file with nothing readable in it; no temporary copy is left behind |
| Restart | A restart needs confirmation; SGC restarts the machine; afterwards SGC and the helper are back by themselves, the earlier sign-in still works and the restart is in the activity log |

After the restart the machine is wiped and installed again, and the export is restored through the setup link:

| Step | What is checked |
|---|---|
| Restore | Refused without the setup link or with a wrong passphrase; the preview names the account and changes nothing; after confirming, SGC comes back with the old account and password, the changed setting and the full history, including updates made on the old machine; the fresh install's setup link is closed |

The test builds its own releases (the version under test and three later ones, one of them deliberately broken) and signs them with a throwaway key created on the spot (`make-test-release.sh`). The updates are served from a folder on the test machine itself. The real release key is never involved, and nothing built for the test is ever published. The admin account it creates uses a random password that exists only on the test machine.

`cases.sh` is the part that runs on the test machine.
