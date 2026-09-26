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
listed in `config/ai-tools.json`. It skips names ending in a dot or a space, which
Windows would read as a different folder.

A few files in the profile are opened, including by a SYSTEM audit: the `package.json`
of each extension that ships with a per-user VS Code install (to tell GitHub Copilot
Chat, whose folder is just `copilot`, from the others), the VMware, VirtualBox and WSL
settings files (`inventory.vmls`, `VirtualBox.xml`, `.wslconfig`), and the virtual
machine files those settings name, which are read only when they are on a local fixed
drive. Each is read only up to a size limit (2 MB for `package.json`, with 32 MB in
all; 1 MB or 4 MB for the others), and nothing in it is run.

### Links in the user's profile

The user controls their own profile, so the tool does not follow their links when it
reads the profile with more rights than they have: when it runs as SYSTEM or elevated
(including "Restart as administrator", which a standard user's links could otherwise
steer). Then:

- every folder on the way to a browser profile, an AI tool's folder, a VS Code
  extensions folder, one of the files above or an MCP client config must be a plain
  folder, not a junction or symbolic link. For the virtual machine files named in the
  VMware and VirtualBox settings, that is every folder from the drive root, or from the
  profile folder when the file is below it (the profile folder itself may be a link, as
  profile containers and moved profiles are);
- a file that is opened, or an MCP client config whose presence and permissions are
  recorded, must not be a link itself. An AI tool's folder is found by its own
  attributes, and a link there is not followed;
- a file stored online only (a cloud file that is not downloaded) is not opened, so the
  audit never makes OneDrive or another sync app download it. A cloud file that is
  already downloaded is read as usual: only reparse points that are name surrogates
  (junctions, symbolic links) count as links;
- at most 64 virtual machine files named in one inventory are read
  (`maxVmFilesPerInventory` in `config/virtualisation.json`). A virtual machine file
  that is found but not read, and reaching that limit, are reported in the evidence of
  SC-12 and FW-07.

In the user's own non-elevated session (the per-user probe, or a standard user running
the tool) it has no more rights than the user, so their links are followed as usual.

These checks are made by path, so a user who can create symbolic links (for example with
Developer Mode on) could swap a folder or file for a link between the check and the read;
a SYSTEM audit could then connect to a network share. Blocking local-to-remote symbolic
link evaluation by policy prevents this.

### Credentials

When it finds a credential in an MCP client config it records **only a classification**:
the provider, the credential type, and whether the value is held in plaintext or
referenced from an environment variable or credential manager. It never records:

- the credential value, or any hash, fingerprint or other value derived from it, in
  `status.json`, `user-status.json`, the report, the transcript, or any verbose stream;
- another user's secrets from a SYSTEM / machine audit - that context records only that
  a config file is present, its path and its permissions, and never opens it. Parsing
  and credential classification happen only in the user's own session.

No credential is validated or sent anywhere; there are no network calls in this path.
