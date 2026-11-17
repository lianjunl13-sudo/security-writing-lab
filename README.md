# Security writing lab: local tool boundary

Reproducible local POSIX filesystem experiment. This is not a real MCP server/client, a prompt-injection benchmark, or a production security guarantee. All requests use synthetic data. AI-assisted code and documentation, reviewed against local tests.

## Run

Python 3.12 on a local POSIX system with dir_fd and O_NOFOLLOW. No third-party Python dependencies.

```sh
python3 -m unittest -v test_experiment.py
python3 experiment.py
```

Original recorded run: 2026-11-17T23:23:45+08:00, macOS, Python 3.12.14; 29 tests passed. See tests.txt, demo-result.json and run.json.

Host identity mapping, approval issuance and root directories are trusted. Approval is in-memory without expiry, revocation or durable audit. No Windows/network-filesystem/crash persistence guarantee. Do not expose approval issuance as a model tool. See source docstrings and run.json for scope.

This repository contains supporting code and evidence only; article manuscripts are submitted separately to publishers.
