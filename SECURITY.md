# Security policy

## Supported versions

Engramic Baseline is in beta. Fixes go into the next release; while the version
number starts with 0 there are no long-term support branches.

| Version | Supported |
|---|---|
| Latest release | Yes |
| Anything earlier | No - please update |

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

To find AI browser extensions it lists folder and file names in the browser profile
folders named in `config/browser-profiles.json`, including when it runs as SYSTEM over
the signed-in user's profile. It never opens a file there, so it never reads browsing
history, cookies, browser settings or extension data, and it records only extensions
listed in `config/ai-tools.json`. It skips folders below the profile folder that are
junctions or symbolic links, and names ending in a dot or a space, which Windows would
read as a different folder. The same rules apply when it looks for AI tools' folders in
the profile and lists VS Code extensions there: it checks that each folder on the way is
a plain folder, and checks the last one by its attributes only, without following it.

A few files in the profile are opened, including by a SYSTEM audit: the `package.json`
of each extension that ships with a per-user VS Code install (to tell GitHub Copilot
Chat, whose folder is just `copilot`, from the others), and the VMware, VirtualBox and
WSL settings files (`inventory.vmls`, `VirtualBox.xml`, `.wslconfig`). Each is reached
through plain folders only, is skipped when it is itself a junction or symbolic link,
and is read only up to a size limit (2 MB for `package.json`, with 32 MB in all; 1 MB or
4 MB for the others), and nothing in it is run. The virtual machine files those settings
name get the same link check and size limit, and are read only when they are on a local
fixed drive. When the MCP presence check runs as SYSTEM, the config files are reached
the same way, so their presence and permissions are never looked up through a link.

These checks are made by path, so a user who can create symbolic links (for example with
Developer Mode on) could swap a folder or file for a link between the check and the read;
a SYSTEM audit could then connect to a network share. Blocking local-to-remote symbolic
link evaluation by policy prevents this.

When it finds a credential in one of those files it records **only a classification**:
the provider, the credential type, and whether the value is held in plaintext or
referenced from an environment variable or credential manager. It never records:

- the credential value, or any hash, fingerprint or other value derived from it, in
  `status.json`, `user-status.json`, the report, the transcript, or any verbose stream;
- another user's secrets from a SYSTEM / machine audit - that context records only that
  a config file is present, its path and its permissions, and never opens it. Parsing
  and credential classification happen only in the user's own session.

No credential is validated or sent anywhere; there are no network calls in this path.
