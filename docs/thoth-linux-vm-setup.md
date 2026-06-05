# Thoth Linux VM Setup

This guide is for students, analysts, and contributors running the Thoth preview package inside a normal Linux VM.

Thoth does not require a custom VM image. Use a clean Linux VM, download the preview package, and keep all SEKER collections synthetic or approved for the lab.

## VM Baseline

Recommended VM profile:

- Ubuntu Desktop, Ubuntu Server, Debian, Fedora, or another current Linux distribution
- 2 CPU cores
- 4 GB RAM minimum
- 20 GB disk minimum
- snapshots enabled if your hypervisor supports them
- shared clipboard/folders disabled unless needed for the lab
- no personal accounts, browser sessions, or unrelated work inside the VM

Thoth is local-only by default. The web UI listens on `127.0.0.1:8080` inside the VM.

## Prepare The VM

Install basic tools:

```bash
sudo apt update
sudo apt install -y ca-certificates curl tar
```

On non-Debian distributions, install the equivalent packages with the system package manager.

Take a clean snapshot before importing any SEKER bundle.

## Download Thoth

From the Linux VM:

```bash
curl -LO https://github.com/cthornsburg/triage-kit/releases/download/thoth-0.1-preview/thoth-0.1-preview.tar.gz
curl -LO https://github.com/cthornsburg/triage-kit/releases/download/thoth-0.1-preview/thoth-0.1-preview.tar.gz.sha256
shasum -a 256 -c thoth-0.1-preview.tar.gz.sha256
tar -xzf thoth-0.1-preview.tar.gz
cd thoth-0.1-preview
```

If `shasum` is unavailable, use:

```bash
sha256sum -c thoth-0.1-preview.tar.gz.sha256
```

## Start Thoth

Run the package doctor:

```bash
./scripts/doctor-thoth.sh
```

Start the web UI:

```bash
./scripts/run-thoth.sh
```

Open this URL in the VM browser:

```text
http://127.0.0.1:8080
```

Thoth stores mutable runtime data inside the extracted package under:

```text
data/
logs/
tmp/
```

Do not commit or publish imported bundles, SQLite databases, exported investigations, or runtime folders unless they are synthetic and intentionally documented.

## Ingest SEKER Media

Use one of these source shapes:

- the SEKER USB root
- a copied `collections/` directory
- a specific batch directory containing `batch-manifest.json`

The web UI auto-detects likely SEKER media under common mount roots:

- `/media`
- `/run/media`
- `/mnt`
- `/Volumes` when running on macOS

Example Linux mount paths:

```text
/media/$USER/SEKER-001
/run/media/$USER/SEKER-001
/mnt/SEKER-001
```

If the dropdown does not list the media, enter the path manually on the Thoth home page.

## Safe Lab Rules

- Treat every SEKER bundle as untrusted input.
- Use synthetic or approved lab collections only.
- Do not ingest real endpoint data for public coursework.
- Do not execute files from a collected bundle.
- Snapshot before deeper review.
- Export notes and reports out of the VM; avoid moving raw suspect artifacts around.

## Troubleshooting

If the UI does not start:

```bash
./scripts/doctor-thoth.sh
uname -a
ls -l bin/
```

If the browser cannot connect, confirm the terminal still shows Thoth running and open:

```text
http://127.0.0.1:8080
```

If SEKER media is not auto-detected:

```bash
find /media /run/media /mnt -maxdepth 3 -type f -name batch-manifest.json 2>/dev/null
find /media /run/media /mnt -maxdepth 3 -type d -name collections 2>/dev/null
```

Then paste the parent source path into the manual source field.

For source-code development instead of packaged use, see `docs/student-onboarding.md`.
