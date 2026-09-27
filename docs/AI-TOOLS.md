# Finding AI tools

Baseline finds the AI tools installed on a device: assistants, coding agents, local model runners and their extensions, AI browsers and AI browser extensions. The list, and how each is found on each operating system, is in `config/ai-tools.json`.

The tools found appear in the report's AI section, the app's AI tab and the `ai` block of `user-status.json`. UA-07 asks for MFA on the account each one uses, SC-09 warns about every agent that can run commands or change files on the device, and UA-10 flags an agent running with administrator rights.

## What could not be looked at

When the audit runs as SYSTEM or elevated it doesn't follow a symbolic link in the user's profile, or open a file stored online only (see [SECURITY.md](../SECURITY.md)). Each place it skips is listed in `ai.notRead` (where, what, why and how to read it), and `ai.scanComplete` is `false` when one of them could hide an AI tool, a virtual machine or an MCP config. The report then says the list of AI tools may be incomplete, and SC-09 and UA-07 add a Manual result for what was not read. `agentsFound` and `contained` describe only what was seen, so rely on them when `scanComplete` is `true`.

## AI browser extensions and AI browsers

Baseline recognises AI browser extensions, such as Claude in Chrome, the ChatGPT extension, Sider and Monica, and AI browsers, such as Comet, Opera Neon and Genspark. They're in `config/ai-tools.json` like any other tool (for example `claude-in-chrome` or `perplexity-comet`), and UA-07 asks for MFA on the account they use.

It looks in the profiles of Chrome, Edge, Brave, Vivaldi, Opera, Arc, Comet, Genspark and Firefox, including their Beta, Dev and Canary builds and Firefox Developer Edition and Nightly; `config/browser-profiles.json` says where each keeps them. It reads only the names of folders and files there, and never opens a file, so it never reads browsing history, cookies, browser settings or anything an extension has stored.

Some limits:

- **Installed is not the same as turned on.** An extension that has been turned off still counts, and so does one removed since the browser was last started.
- **Leftover profiles.** When a browser has been uninstalled but its profile folder is still there, extensions in it are labelled a leftover: the report and the app say the tool is only in the profile folder of a browser that is no longer installed, and UA-07 doesn't count it as a service in use. To remove the tool, delete that folder. A browser counts as installed when one of the files in its `installed` list in `config/browser-profiles.json` exists, so if you add a browser that installs somewhere else, list that place too, or leave `installed` out. A browser installed to a folder the person chose (Firefox and Vivaldi let you choose) is labelled a leftover in the same way; if your organisation does that, put your copy of the file in `%ProgramData%\EngramicBaseline\config` with `installed` left out for that browser.
- **What isn't seen:** extensions loaded in developer mode, portable browsers, browsers started with their own user data folder, Opera side profiles, Opera Beta and Opera Developer (Opera Neon Developer is covered), Firefox forks, and Firefox profiles kept outside the usual `Profiles` folder.
- **Whose profile.** An audit run as SYSTEM looks only at the profile of the user signed in at the console, and at none when it finds no one there; the report then says the list of AI tools may be incomplete. Someone signed in only over Remote Desktop (for example on Azure Virtual Desktop, a Windows 365 Cloud PC or a server) isn't found this way. Each user's own probe covers their profile.
- **What an extension can do** (its permissions, or whether it can act on web pages by itself) isn't judged. Every recognised extension is listed as not able to act on the device.

### After upgrading

New catalog entries can add services to UA-07, which then needs an MFA attestation in `cloud-services.json`. A copy of `ai-tools.json` in `%ProgramData%` replaces the shipped one, so merge new entries into it.

## What Baseline can't see

Baseline finds recognised AI apps and browser extensions installed on a device. It can't see AI websites used in a browser tab, such as a chatbot's website, or AI built into the browser itself, such as Copilot in Edge, Gemini in Chrome or Brave Leo. For those, use browser policy (Edge or Chrome URL allow and block lists, and the browser's own settings for its built-in AI), DNS filtering, or Microsoft Defender for Cloud Apps.
