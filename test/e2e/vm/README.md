# Test machine

SGC is installed on a clean Debian server, so testing it needs a clean Debian server that can be thrown away and recreated at will. These scripts provide one as a Hyper-V virtual machine named `sgc-test`, built from Debian's official cloud image.

| Script | What it does |
|---|---|
| `New-TestVM.ps1` | Builds the machine from scratch and takes a checkpoint named `clean`. Add `-Force` to delete and rebuild an existing one. |
| `Reset-TestVM.ps1` | Returns the machine to the `clean` checkpoint and starts it. Takes a few seconds. Run it before every installer or hardening test. |
| `Common.ps1` | Shared settings and helpers; not run directly. |
| `fetch-image.sh` | Downloads, verifies and converts the Debian image. Called by `New-TestVM.ps1` inside WSL. |

## Requirements

- Windows with Hyper-V, and your account in the **Hyper-V Administrators** group
- A Debian WSL distribution with `qemu-utils` and `cloud-image-utils`
- An SSH key at `%USERPROFILE%\.ssh\sgc-test` (`ssh-keygen -t ed25519 -f "$env:USERPROFILE\.ssh\sgc-test"`)

## The machine

- Debian 13 (amd64), 2 CPU cores, 2 GB memory, 16 GB disk, on the Hyper-V "Default Switch"
- User `tester` with passwordless `sudo`, as on a fresh Raspberry Pi OS; login by SSH key only
- Its address can change between boots; the scripts look it up and print it

Nothing is stored in the repository: the downloaded image and the machine's `known_hosts` file live in `%LOCALAPPDATA%\sgc-dev`, the virtual disk next to Hyper-V's other disks.

## Safety

The scripts only ever touch a virtual machine that carries their own marker in its notes. A machine that merely happens to be called `sgc-test` is refused, not deleted.

## How it differs from a real server

- It is amd64. arm64, the Raspberry Pi's architecture, is covered by the CI runners and by testing on a real Pi before a release.
- Debian's cloud image includes `cloud-init`, which a normal installation does not.
- It sits behind Hyper-V's own NAT rather than directly on the home network.
