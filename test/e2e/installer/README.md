# Installer test

Runs the real installer on the clean test machine from [`../vm`](../vm).

```powershell
.\Test-Installer.ps1
```

| Step | What is checked |
|---|---|
| Altered download | One byte added to the archive: refused, nothing installed |
| Altered checksum list | Archive altered and the list recalculated to match, which is all an attacker without the key can do: refused, nothing installed |
| Wrong key | Genuine files signed with a different key: refused, nothing installed |
| Genuine release | Installs; reports the right version; runs as the unprivileged user `sgc`; starts at boot; program files owned by root; state folder private |
| Second run | Running the installer again is harmless |

The test builds its own release and signs it with a throwaway key created on the spot (`make-test-release.sh`). The real release key is never involved.

`cases.sh` is the part that runs on the test machine.
