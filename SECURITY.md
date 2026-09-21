# Security policy

## Reporting a vulnerability

Please report security issues privately to **security@engramic.ai**. Do not open a
public issue for a suspected vulnerability.

Include the affected version, what you observed, and steps to reproduce. We aim to
acknowledge reports within a few working days and will keep you updated on a fix.

This tool runs with administrative or SYSTEM privileges during an audit, so we take
reports about privilege escalation, code execution, or reading or writing files
outside its own data folder especially seriously.

## What the tool reads, and what it never records

An audit is read-only (see the README's "Read first. Change nothing."). It reads
Windows settings, and - in the per-user probe, in the signed-in user's own session -
the configuration files of recognised AI tools (for example MCP client configs) to
inventory the servers each agent is wired to.

When it finds a credential in one of those files it records **only a classification**:
the provider, the credential type, and whether the value is held in plaintext or
referenced from an environment variable or credential manager. It never records:

- the credential value, or any hash, fingerprint or other value derived from it, in
  `status.json`, `user-status.json`, the report, the transcript, or any verbose stream;
- another user's secrets from a SYSTEM / machine audit - that context records only that
  a config file is present, its path and its permissions, and never opens it. Parsing
  and credential classification happen only in the user's own session.

No credential is validated or sent anywhere; there are no network calls in this path.
