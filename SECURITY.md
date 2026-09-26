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
all; 1 MB or 4 MB for the others; 16 MB for an MCP client config), and nothing in it is run.

### Links in the user's profile

The user controls their own profile, so the tool reads it under stricter rules when it
has more rights than the account that owns the profile: when it runs as SYSTEM, or
elevated. All of these reads go through one layer (`src/CEAudit/Private/15-ProfileReads.ps1`):

1. It may list folder names, and check that a file or folder exists, through a
   **junction** only after reading the junction's target without following it. The
   target must be on a local fixed drive or a local volume, and no folder on the way to
   it may be a symbolic link or another link the tool does not recognise. The target's
   names are checked as the kernel follows them, not as Windows' path rules would rewrite
   them (a name ending in a dot or a space is refused), and a folder on the way whose
   attributes the tool may not read is refused, not taken as missing. A junction can
   only name a local volume: one whose target names a network path, directly or through
   a drive letter mapped to one, fails to resolve ("the data present in the reparse
   point buffer is invalid") and never connects. Listing names there shows only whether
   folders named after catalog ids exist.
2. **Symbolic links, other name-surrogate reparse points, and reparse points whose tag
   cannot be read are not followed, even for listing.** With Developer Mode on, a
   standard user can point a symbolic link at `\\server\share` and make SYSTEM, or the
   computer account, authenticate to it. A link's own attributes are still read, so a
   tool folder that is itself a link counts as found.
3. **File contents** (`package.json`, `inventory.vmls`, `VirtualBox.xml`, `.wslconfig`,
   `.vmx` and `.vbox` files, MCP client configs) are never opened through any junction or
   symbolic link anywhere on the path below the profile folder (the profile folder itself
   may be a link, as profile containers and moved profiles are), or from the drive root
   for a virtual machine file outside the profile, or when the file is a link itself. A file or folder stored online only (a cloud file that is not downloaded) is
   never opened or listed, so the tool never makes OneDrive or another sync app download
   it. A cloud file that is already downloaded is read as usual.
4. The existing limits stay: listings are capped, each file is read only up to a size
   limit (MCP configs 16 MB), at most 64 virtual machine files named in one inventory are
   read (`maxVmFilesPerInventory` in `config/virtualisation.json`), and a virtual machine
   file that is not on a local fixed drive is never opened, in any session.
5. In the user's own non-elevated session, links are followed as usual: the tool has no
   more rights than the user there.
6. **Nothing skipped is dropped silently.** Each location that is not read is recorded
   with where it is (relative to the profile, as `%USERPROFILE%\...`, and a browser
   profile by its label, never a name the person chose; a virtual machine file outside
   the profile is shown as the inventory names it), what was not read, why, and how to
   read it. Only what Windows says is not there counts as missing: a folder or file the
   tool may not look at (for example because of its permissions) is recorded too. The checks that depend on it (SC-09, SC-12, SC-13, SC-14, FW-07 and
   UA-07) are then Manual, never Pass or Not applicable, and the records appear in the
   report, the GUI and the `ai.notRead` block of `user-status.json` (with
   `ai.scanComplete`, which is `false` only when a location not read could hide an AI
   tool). Machine-scope checks name a full audit without elevation, signed
   in as that user; User-scope checks name the per-user probe. A reason is a fixed
   string: it never contains file contents or error text.

These checks are made by path, so a user who can create symbolic links (for example with
Developer Mode on) could swap a folder, or a folder on the way to a junction's target,
for a link between the check and the read; a SYSTEM audit could then connect to a network
share. Blocking local-to-remote symbolic link evaluation by policy prevents this.

### Credentials

When it finds a credential in an MCP client config it records **only a classification**:
the provider, the credential type, and whether the value is held in plaintext or
referenced from an environment variable or credential manager. It never records:

- the credential value, or any hash, fingerprint or other value derived from it, in
  `status.json`, `user-status.json`, the report, the transcript, or any verbose stream;
- another user's secrets from a SYSTEM / machine audit - that context records only that
  a config file is present, its path and its permissions, and never opens it. Parsing
  and credential classification happen only in the user's own session.

When a config can't be parsed, only that is recorded ("it could not be parsed by the
audit"), never the parser's message, which can quote the text it stopped at. Its
permissions are recorded by the config's path relative to the profile.

No credential is validated or sent anywhere; there are no network calls in this path.
