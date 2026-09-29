# The .NET solution

Engramic Baseline is being ported from PowerShell to C# on .NET 10. The .NET code sits beside the
PowerShell module (`src/CEAudit`), which stays the reference until both tools give the same results.
This note covers the layout, the rules the build enforces, and how to build and test.

## Layout

| Path | What it holds |
|---|---|
| `Baseline.slnx` | The solution. `Baseline.Portable.slnf` lists the projects that build and test on Linux. |
| `global.json` | The .NET SDK (10.0.401, which CI installs exactly and the lock files follow) and the test runner. |
| `Directory.Build.props` | Settings for every project, including the one version of the product. |
| `Directory.Packages.props` | The version of every package, set once. |
| `src/Engramic.Baseline.Model` | Contracts: the status files, findings, changesets and config, and how they are written. |
| `src/Engramic.Baseline.Platform` | The interfaces and records of the primitives (registry, files, processes, tokens and so on), and the trust rules of the data folder. |
| `src/Engramic.Baseline.Engine` | The check and fix contracts, the runner, the framework rollups, changesets and undo. |
| `src/Engramic.Baseline.Controls` | The checks, the fixes, the readers that interpret what the primitives return, and the shipped config. |
| `src/Engramic.Baseline.Windows` | The Windows primitives, calling Win32 through code that CsWin32 generates from `NativeMethods.txt`, including SecureStore and the audit mutex. |
| `src/Engramic.Baseline.Cli` | `baseline.exe`, the command line. |
| `tests/Engramic.Baseline.*.Tests` | xUnit v3 tests: one project for each library, and one for the command line. |
| `tests/Engramic.Baseline.Invariants.Tests` | Tests of the repository's own rules, described below. |
| `tests/Engramic.Baseline.Testing` | Fakes and recorded responses that the tests share. |
| `tests/Engramic.Baseline.Testing.Windows` | Windows fixtures: folders under the temp folder with the security descriptors a test gives, junctions, hard links and other reparse points, and mutexes of the tests' own. |
| `tests/AotCanary` | Compiles the AOT-clean libraries with Native AOT and calls into each one. |
| `tools/parity` | Compares the ported checks with the PowerShell module on a device (below). |

Model, Platform, Engine and Controls target `net10.0` and must not depend on Windows, so their tests
run on Linux too. Windows, the CLI and their tests target `net10.0-windows`. All build output goes
under `artifacts/`, never beside the sources.

## Rules the build enforces

**One version.** `VersionPrefix` and `VersionSuffix` in `Directory.Build.props` are the only place the
version is written. Every assembly and `baseline.exe --version` take it from there.

**Warnings are errors**, and so are these analysers:

- Product code (`src/`) uses the **Recommended** analysers plus **every security rule**. A public member
  needs an XML comment, and the public API of each project is tracked in `PublicAPI.Shipped.txt` and
  `PublicAPI.Unshipped.txt`: a new public member goes into the Unshipped file, so every change to what
  other code can call shows in the diff. "All" would add rules that are off even in the Recommended
  set, such as CA1303 (localisable literals), CA2007 (`ConfigureAwait` on every await) and CA1062
  (argument checks that the nullable annotations already give). A rule from it can still be switched
  on in `.editorconfig` when it earns its place.
- Tests use the **Default** analysers, since their names read as sentences and they may use the APIs
  product code must not.
- `.editorconfig` holds the few rule settings and the code style enforced in the build: file-scoped
  namespaces, braces on every block, explicit accessibility, the naming rules and no unused usings.

**Windows versions.** CA1416 is an error: `net10.0` projects cannot call Windows-only APIs, and Windows
projects cannot call an API newer than build 14393 (Windows 10 1607, Server 2016) without a version
check. The minimum is written as the `SupportedOSPlatform` attribute by `Directory.Build.targets`,
because `net10.0-windows` has a target platform version of 7.0 and the SDK refuses a higher
`SupportedOSPlatformVersion`.

**AOT.** Model, Platform, Engine and Windows are AOT-clean (`IsAotCompatible`), and the AOT canary
compiles them with Native AOT, each rooted whole, with every warning an error. Controls runs the same
trim and AOT analysers. JSON is source-generated.

**Banned APIs.** Product code must not call the APIs in `src/BannedSymbols.txt`; the build fails with
RS0030 and says what to use instead.

| Banned | Why | Use instead |
|---|---|---|
| `File`, `Directory`, `FileInfo`, `DirectoryInfo`, opening a stream by path | Path-based access follows junctions and symbolic links, and creating a folder by path accepts one someone else made first | SecureStore or ProfileReader, which work by handle |
| `Path.GetTempPath`, `Path.GetTempFileName` | The temp folder of SYSTEM is shared with other accounts | A SecureStore scratch folder |
| `SetAccessControl`, `SetOwner`, `FileSystemAclExtensions` | Access control is set only when an object is created, and nothing takes ownership | SecureStore; `MutexAcl.Create` and the like |
| `Registry`, `RegistryKey` | Every read and write names its registry view | The registry primitive |
| `System.Management` | Not AOT-ready | The CIM layer, in its own project |
| `Process.Start`, `ProcessStartInfo` | Tools must be resolved from System32 and signature-checked, never found through PATH | The trusted process runner |
| Reading environment variables | Whoever starts the process sets them | A known folder or config |
| `DateTime.Now`, `UtcNow`, `Today`, `DateTimeOffset.Now`, `UtcNow` | Tests must be able to set the time | `TimeProvider` |
| Loading an assembly from a path | Nothing runs that did not ship with the product | - |
| `NativeLibrary`, `Marshal.GetDelegateForFunctionPointer` | Native code is reached only through CsWin32 (below) | A function in `NativeMethods.txt` |
| Reflection-based `JsonSerializer` overloads | Not AOT-safe | A `JsonTypeInfo` from a source-generated `JsonSerializerContext` |

**Exemptions.** A few audited classes, added as the port goes on, do these things safely: SecureStore,
ProfileReader, the registry primitive and the trusted process runner. Only the files they live in may use
a banned API, and only like this:

1. The file is listed in `src/BannedApiExemptions.txt`, with the reason.
2. Each use sits between `#pragma warning disable RS0030 // <reason>` and `#pragma warning restore RS0030`,
   around as few lines as possible.

Adding a file to the list, or a use to a listed file, needs the maintainer's review. Nothing else may turn
the rule down:

- `Directory.Build.targets` fails the build of a product project that does not reference the analyser,
  skips the analysers (`RunAnalyzers` or `RunAnalyzersDuringBuild` set to false, or
  `OptimizeImplicitlyTriggeredBuild`), reads a banned-API list other than `src/BannedSymbols.txt` or
  names RS0030 in `NoWarn` or `WarningsNotAsErrors`.
- `Engramic.Baseline.Invariants.Tests` fails on an unlisted suppression, a pragma without a reason or
  restore, a bare `#pragma warning disable`, a `SuppressMessage`, a build setting that names RS0030, and
  what the build cannot see in itself: a product project that stops importing the shared build files,
  switches the analysers off, removes an analyser or additional file, or brings its own
  `Directory.Build.*` or other build settings under `src/`. The same tests check that every line of `BannedSymbols.txt` names
an API that exists and that every overload of what it bans is listed, so an overload .NET adds later
fails them.

**Native code.** A Win32 call can do what a banned API does, so native code follows the same rules,
checked by `Engramic.Baseline.Invariants.Tests`:

- Win32 is reached only through the functions CsWin32 generates in `Engramic.Baseline.Windows`, which
  stay internal (`"public": false` in `NativeMethods.json`). Hand-written code declares no `DllImport`,
  `LibraryImport`, `extern` method, COM import or unmanaged function pointer, and loads no library.
- `NativeMethods.txt` lists plain names, one per line: no wildcards, modules or namespaces, so every
  function is reviewed by name.
- A function that opens, creates, copies, moves or deletes a file or folder by path, renames or deletes
  an open file (`SetFileInformationByHandle`, which reads a relative new name against the current
  directory), uses the temp folder, touches the registry, starts a process, sets a security descriptor,
  reads or sets the environment or answers from it (the known-folder API builds ProgramData from
  `%SystemDrive%`), loads a library or creates a COM object is sensitive (the list is in
  `NativeCodeTests`). It may be named only in a file on `src/BannedApiExemptions.txt`, only between the same
  `#pragma warning disable RS0030 // <reason>` and restore as a banned API, and it comes off
  `NativeMethods.txt` when no exempt file uses it.

The analyser cannot ban these functions itself, because CsWin32's generated overloads call one another
and RS0030 would fail the generated code, so this rule is checked on the source text instead.

**Packages.** Add or change a version in `Directory.Packages.props`, run `dotnet restore Baseline.slnx`,
and commit the `packages.lock.json` files it changes; CI restores in locked mode and fails if a lock
file is out of date. Some implicit packages (the trimming and AOT tools) follow the SDK version, so
`global.json` and the lock files move together: to take a new patch SDK, install it, change the version
in `global.json`, run `dotnet restore Baseline.slnx --force-evaluate` and commit all of it in one change.
CI installs exactly the SDK that `global.json` names, never the newest patch of its feature band, so it
keeps passing when a new patch ships and moves only when `global.json` does. If a restore changes lock
files you did not mean to change, check that `dotnet --version` matches `global.json`.
CsWin32 is still 0.x and pinned to an exact version.

**Config.** The shipped `config/*.json` files are built into `Engramic.Baseline.Controls` (`ShippedConfig`)
from the repository's config folder, which the PowerShell module also reads. Nothing reads them from
disk, so they cannot be changed beside the executable, and no file API is needed for them. A check that
reads another file adds it there as an `EmbeddedResource`. Administrators' overrides, which replace a
shipped file whole, will come through SecureStore and its trust checks, in front of the shipped copy.

**Text.** Sources are ASCII only (write other characters as escapes, such as `"\u00e9"` in C#),
user-facing text is British English, and quotes are straight. The Hygiene check below enforces the first.

## Build and test

From the repository root, with the SDK in `global.json`:

```
dotnet restore Baseline.slnx --locked-mode
dotnet build Baseline.slnx -c Release --no-restore -warnaserror
dotnet test --solution Baseline.slnx -c Release --no-build
```

On Linux, use `Baseline.Portable.slnf` in place of `Baseline.slnx`.

Publish after a restore of the whole solution, with `--no-restore`: a restore for a single runtime would
apply that runtime to the referenced libraries too, which their lock files do not list.

```
dotnet publish src/Engramic.Baseline.Cli -c Release -r win-x64 --no-restore
dotnet publish tests/AotCanary -c Release -r win-x64 --no-restore
```

`baseline.exe` is published self-contained with ReadyToRun, and neither trimmed nor single-file.
Native AOT links with the C++ build tools of Visual Studio. Without them, adding
`-p:IlcUseEnvironmentalTools=true` still runs the AOT compiler over all four libraries, and only the
final link fails.

Some tests need an elevated administrator, as CI's Windows runner is: those that make folders owned by
Administrators, as the installer does, or a symbolic link, or that open the audit mutex as an
administrator. Run without elevation, they skip and say why. No test touches the real data folder, its
registry key, a scheduled task or the product's mutex: folders are made under the temp folder with unique
names and deleted by that exact path, the seal is read from a registry in memory, and mutexes have names
of the tests' own.

The hygiene check needs a clone that git can read:

```
pwsh -NoProfile -File tools/hygiene/Test-Hygiene.ps1
```

## The audit command

`baseline.exe audit` runs the ported checks on this device, read-only, and prints the findings. With
`--json findings` or `--json status` it writes findings.json or status.json to standard output instead,
byte for byte as the file is written (UTF-8 with a byte order mark), to redirect into a file from cmd or
PowerShell 7.4 and later. It writes no file itself: files go only into the machine data folder, through
SecureStore, which the scheduled audit writes. It has no option to name an output folder: SecureStore
accepts only the sealed data folder, and a folder named on the command line may be one a standard user
controls, or once did, which nothing in its state now can rule out.

```
baseline.exe audit --id SU-01
baseline.exe audit --id SU-01 --json status > status.json
```

## The data folder: SecureStore

`SecureStore`, in `Engramic.Baseline.Windows`, is the machine data folder, `%ProgramData%\EngramicBaseline`,
checked through handles and held open while in use. It is the one file on `src/BannedApiExemptions.txt`
that opens, creates, renames or deletes files, and product code writes files only through it
(`ISecureStore`; the tests share a fake). This first version checks a data folder that exists and writes
files in it: it creates nothing, repairs nothing and moves nothing aside.

**Opening** it:

1. ProgramData comes from the known-folder API, which builds it as `%SystemDrive%\ProgramData` from the
   process environment: a process started with `SystemDrive` changed is told another folder. So the
   answer must be `ProgramData` on the drive Windows is installed on (`GetSystemWindowsDirectoryW`,
   which comes from the kernel), or SecureStore refuses. A ProgramData folder moved elsewhere is not
   supported.
2. ProgramData is opened by path with `FILE_FLAG_OPEN_REPARSE_POINT`, so a link is opened as itself and
   seen, and `GetFinalPathNameByHandleW` must give back the path that was opened, so no folder on the
   way is a link. It must be a folder, not a reparse point, owned by SYSTEM, Administrators or
   TrustedInstaller. Its access list is not judged: standard users may create folders in it, by design.
3. The data folder is opened in it the same way, must pass the trust rules below, and must carry the
   install's seal: the text value `DataRootSealed` under `HKLM\SOFTWARE\EngramicBaseline.DataRoot`
   (64-bit view), which the installer writes when it makes the folder locked. A folder that looks locked
   but was never sealed is refused: a handle a user opened while they owned a folder, or could change its
   permissions, keeps that access after any later lock, and nothing in the folder's state shows that
   never happened.
4. Both handles are held until the store is disposed, without `FILE_SHARE_DELETE` and with the right to
   list, which the sharing check counts (it ignores a handle that may only read attributes or
   permissions), so neither folder can be renamed, replaced or deleted while held, and their paths keep
   naming the folders that were checked.

Whether to open each folder relative to its parent's handle (`NtCreateFile` with `RootDirectory`)
instead is left to a later spike. This way never follows a link either: every open names the item
itself with `FILE_FLAG_OPEN_REPARSE_POINT`, inside folders already held, and each is confirmed by its
final path.

**Trust rules** (`DataFolderTrust` in Platform, as the module's `Get-CEDataPathProblem` and the Intune
scripts judge): an item is trusted when it is not a reparse point and not stored online only; is owned by
SYSTEM, Administrators or TrustedInstaller; has an access list; gives no other account `FILE_WRITE_DATA`,
`FILE_APPEND_DATA`, `FILE_WRITE_EA`, `FILE_DELETE_CHILD`, `FILE_WRITE_ATTRIBUTES`, `DELETE`, `WRITE_DAC`,
`WRITE_OWNER`, `GENERIC_WRITE` or `GENERIC_ALL` in any entry, inherited and inherit-only ones included;
and denies a trusted account nothing. Rights to read are fine for anyone, and so is CREATOR OWNER. Unlike
the module, whose `Get-Acl` drops entries it does not recognise, an entry of an unknown kind fails.

**Writing** a file replaces it atomically, so a reader sees the old file or the new one:

1. Whatever is at the target's name is opened as itself: it must be nothing, or an ordinary file with one
   name that is not read-only. A link, a folder or a file with other names (hard links) is refused and
   left as it is.
2. A new file, `<name>.<32 random hex digits>.tmp` as the module names its own, is created with
   `CREATE_NEW`, no sharing and `FILE_FLAG_OPEN_REPARSE_POINT` (a link already at that name is a
   collision, never followed), owned by Administrators, which SYSTEM and an elevated administrator may
   name, and taking the folder's access list. Its final path, its facts and its security are checked
   through its handle.
3. It is written, flushed and renamed over the target through its handle (`FILE_RENAME_INFO` with
   replace). The rename replaces the target's name and never writes into or through it: a hard link or
   symbolic link swapped in after step 1 is replaced as a name, and a junction or folder makes the
   rename fail. The rename reads a relative name against the current directory and refuses
   `RootDirectory`, so it is given the target's full path, which the held folders keep inside the data
   folder, and the file's final path is checked afterwards.
4. While another process, such as a reader or an antivirus scan, has the target open, the rename fails;
   it is tried six times over about three seconds, by the store's clock. A write that fails deletes its
   new file through its handle.

Tests give the ProgramData path, the seal's location and the clock (`SecureStoreOptions`). Still to come:
creating the data folder and its subfolders locked, moving an untrusted one aside, scratch and undo
folders, reading administrators' config overrides, and the attack suite run as SYSTEM.

## The scheduled audit

`baseline.exe scheduled-audit` is the unattended audit for the scheduled task, as
`app/Invoke-CEScheduledAudit.ps1` runs it, with what has been ported so far. The scheduled task that the
installer registers still runs the module's script.

1. It runs only as SYSTEM, and refuses anyone else with a message.
2. It takes the audit mutex, `Global\EngramicBaselineAudit`, which the module's scheduled audit and
   installer take too, waiting up to 30 minutes. It is created with `MutexAcl` and an access list
   granting SYSTEM and Administrators alone. One that exists already and does not let this account in,
   as a standard user could make it first to stop audits, fails as access denied, and the run counts as
   failed.
3. It opens the data folder through SecureStore. A refusal is reported with SecureStore's reason, and
   nothing is written.
4. It runs the machine checks (SU-01 so far) and writes status.json, UTF-8 with a byte order mark, with
   SecureStore's atomic write. A failed run leaves the old status.json, whose age then keeps growing, as
   in the module.

| Exit code | Meaning |
|---|---|
| 0 | The audit ran and status.json was written. |
| 1 | It failed, or refused to run: not SYSTEM, the mutex could not be taken, or the data folder was refused. |
| 2 | Another audit, or an install, held the mutex for 30 minutes. |

Not ported yet: counting failed runs in last-error.json (only into a data folder that was opened and
checked, as the module does), the report folder and its retention, the log, events 1000 to 1003, and
`excludeCheckIds` from an administrator's config.

## Comparing with the PowerShell module

`tools/parity/Compare-Parity.ps1` runs the same checks in the untouched module, out of process in Windows
PowerShell 5.1, and in `baseline.exe` on this device, then compares every field of every finding, every
value of status.json and what the Intune discovery script reports for each. It ignores what differs by
design (the tool version, times and paths), lists each difference it expects with the reason, and exits
1 on any other difference. Run it as the account whose audit you want to compare: a standard user, an
elevated administrator or SYSTEM.

```
dotnet build Baseline.slnx -c Release
powershell -NoProfile -ExecutionPolicy Bypass -File tools/parity/Compare-Parity.ps1 -Id SU-01
```

## CI

`.github/workflows/dotnet.yml` runs on every pull request and on pushes to `main` and `feat/dotnet-port`:

| Job | What it does |
|---|---|
| Build and test (.NET) | On Windows: the locked restore, the build with warnings as errors, the tests, `baseline.exe` published and run with `--version`, and the AOT canary published and run. |
| Unit tests (Linux) | Builds and tests the portable projects in `Baseline.Portable.slnf`. |
| Hygiene | Every tracked text file is ASCII, and every URL host in `src/`, `tests/`, `tools/` and `docs/`, every `engramic-ai/` repository and every `engramic.ai` name anywhere is on `tools/hygiene/public-allowlist.txt`. |

The PowerShell module's jobs stay in `ci.yml`.
