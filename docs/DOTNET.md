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
| `src/Engramic.Baseline.Platform` | The interfaces and records of the primitives (registry, files, the event log, processes, tokens, HTTP and so on), the layout and trust rules of the data folder, and the rules that choose a service request's proxy. |
| `src/Engramic.Baseline.Engine` | The check and fix contracts, the runner, the framework rollups, changesets and undo. |
| `src/Engramic.Baseline.Controls` | The checks, the fixes, the readers that interpret what the primitives return, and the shipped config. |
| `src/Engramic.Baseline.Windows` | The Windows primitives, calling Win32 through code that CsWin32 generates from `NativeMethods.txt`, including SecureStore, the audit mutex, the service client, the process list and file signatures. |
| `src/Engramic.Baseline.Cli` | `baseline.exe`, the command line. |
| `tests/Engramic.Baseline.*.Tests` | xUnit v3 tests: one project for each library, and one for the command line. |
| `tests/Engramic.Baseline.Contracts.Tests` | The status.json contract: golden files of its bytes, and the Intune scripts run on it (below). |
| `tests/Engramic.Baseline.Invariants.Tests` | Tests of the repository's own rules, described below. |
| `tests/Engramic.Baseline.Testing` | Fakes and recorded responses that the tests share. |
| `tests/Engramic.Baseline.Testing.Windows` | Windows fixtures: folders under the temp folder with the security descriptors a test gives, junctions, hard links and other reparse points, mutexes of the tests' own, and the standard user who plays the attacker in the attack suite. |
| `tests/AotCanary` | Compiles the AOT-clean libraries with Native AOT, calls into each one, runs detection and times itself against the JIT build (spike 7, below). |
| `tools/parity` | Compares the ported checks with the PowerShell module on a device (below). |
| `tests/parity/divergences.json` | The ledger of accepted differences between the module and `baseline.exe`, with the reason and scope of each. |
| `tools/contracts` | Runs the unchanged Intune scripts on a status.json, and proves the contract end to end as SYSTEM in CI (below). |
| `tools/ci` | Helpers for CI runners only: running a program, or the SYSTEM tests of a test assembly, as SYSTEM through a temporary scheduled task, and running the attack suite with a throwaway standard user as the attacker. |
| `tools/Release.psm1` | What the release scripts beside it share: which PE files of a published folder this repository built, and what their signatures say (below). |

Model, Platform, Engine and Controls target `net10.0` and must not depend on Windows, so their tests
run on Linux too. Windows, the CLI and their tests target `net10.0-windows`. All build output goes
under `artifacts/`, never beside the sources.

## Rules the build enforces

**One version.** `VersionPrefix` and `VersionSuffix` in `Directory.Build.props` are the only place the
version is written. Every assembly and `baseline.exe --version` take it from there. They are plain text under
no condition, and no other build file sets a version (`VersionTests`), because a release tag is held to them
exactly (below).

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
compiles them with Native AOT, each rooted whole, with every warning an error, and runs detection with them.
Controls runs the same trim and AOT analysers. JSON is source-generated. Windows turns off runtime
marshalling (`DisableRuntimeMarshalling`): CsWin32 generates every call with blittable values only, so each
compiles to a direct call, and a signature that would need marshalling, such as a string parameter, fails the
build with CA1420.

**Banned APIs.** Product code must not call the APIs in `src/BannedSymbols.txt`; the build fails with
RS0030 and says what to use instead.

| Banned | Why | Use instead |
|---|---|---|
| `File`, `Directory`, `FileInfo`, `DirectoryInfo`, opening a stream by path | Path-based access follows junctions and symbolic links, and creating a folder by path accepts one someone else made first | SecureStore or ProfileReader, which work by handle |
| `Path.GetTempPath`, `Path.GetTempFileName` | The temp folder of SYSTEM is shared with other accounts | A SecureStore scratch folder |
| `SetAccessControl`, `SetOwner`, `FileSystemAclExtensions` | Access control is set only when an object is created, and nothing takes ownership | SecureStore; `MutexAcl.Create` and the like |
| `Registry`, `RegistryKey` | Every read and write names its registry view | The registry primitive |
| `System.Management` | Not AOT-ready | The CIM layer, in its own project |
| `HttpClient`, `HttpClientHandler`, `SocketsHttpHandler` | A client made anywhere else would use .NET's default proxy, which follows environment variables and, as SYSTEM, SYSTEM's own Internet settings | The service client (`IServiceClient`) |
| `Process.Start`, `ProcessStartInfo` | Tools must be resolved from System32 and signature-checked, never found through PATH | The trusted process runner |
| Reading environment variables | Whoever starts the process sets them | A known folder or config |
| `DateTime.Now`, `UtcNow`, `Today`, `DateTimeOffset.Now`, `UtcNow` | Tests must be able to set the time | `TimeProvider` |
| Loading an assembly from a path | Nothing runs that did not ship with the product | - |
| `NativeLibrary`, `Marshal.GetDelegateForFunctionPointer` | Native code is reached only through CsWin32 (below) | A function in `NativeMethods.txt` |
| Reflection-based `JsonSerializer` overloads | Not AOT-safe | A `JsonTypeInfo` from a source-generated `JsonSerializerContext` |

**Exemptions.** A few audited classes, added as the port goes on, do these things safely: SecureStore,
ProfileReader, the registry primitive, the trusted process runner, the service client and the signature check.
Only the files they live in may use a banned API, and only like this:

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
  directory, and `NtSetInformationFile`), uses the temp folder, touches the registry, starts a process, sets a security descriptor,
  reads or sets the environment or answers from it (the known-folder API builds ProgramData from
  `%SystemDrive%`), loads a library or creates a COM object is sensitive (the list is in
  `NativeCodeTests`). So is `WinVerifyTrust`, which opens the file by its path when it is given no handle, and
  a catalog always by its path. It may be named only in a file on `src/BannedApiExemptions.txt`, only between the same
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
reads another file adds it there as an `EmbeddedResource`, and its schema to `ConfigFile` in the same change.
Code reads the files through `IConfigFiles`. Administrators' overrides, which replace a shipped file whole,
come through SecureStore and the config trust gate, in front of the shipped copy (below).

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

A hung test fails the run instead of holding it until CI gives up: once no test has finished for 30 seconds,
the hang dump extension (`tests/Directory.Build.props`) dumps and stops the test process, and `TestResults/`
gets the dump and a `_hang.log` that names the tests still running. A project whose tests are slow by nature
sets a longer `BaselineHangDumpTimeout` in its project file: the Contracts tests wait 10 minutes, since each of
their Intune-reader runs starts Windows PowerShell five times and may take up to 210 seconds on a busy runner
before it gives up (`IntuneReaders.cs` gives the measurements). Tests that wait on work on other threads,
as the runner's tests do, give up on each wait after 10 seconds and say what they were waiting for, and they
move a fake clock only once the code under test has started its timer on it.

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
registry key, a scheduled task, the product's mutex or its event source: folders are made under the temp
folder with unique names and deleted by that exact path, the seal is read from a registry in memory, notices go
to an event log in memory, and mutexes and the one elevated test that writes a real event have names of the
tests' own.

**The attack suite** is the tests with the trait `Suite=Security`: what someone can do to the data folder
before and while SecureStore runs, at every place it keeps: pre-created folders, junctions, symbolic links, hard
links and other reparse points, deny entries, rename races (staged between two of the store's steps by
`SecureStoreHooks`), cloud-style placeholders and files stored online only, oversized files and deep trees, in the
data folder, its kept folders, the scratch and undo folders, and administrators' config overrides. Most run anywhere, with the account running the
tests standing in for the trusted accounts. Those with the product's rules, folders owned by Administrators,
need elevation. `SecureStoreAttackerTests` need a real standard user as the attacker, whom a test impersonates:
the Security job makes one for each run (`tools/ci/Invoke-SecurityTests.ps1`: a local account with a random name
and password, deleted afterwards) and runs the suite as the elevated administrator and, through a scheduled task,
as SYSTEM. Anywhere else those tests skip and say why.

```
dotnet test --project tests/Engramic.Baseline.Windows.Tests -c Release -- --filter-trait Suite=Security
```

A few tests hold only as SYSTEM and change the machine, putting each change back: the service client's tests
set the machine's WinHTTP proxy with netsh and add names to the hosts file. They are explicit, so a test run
leaves them out unless it asks for them (`-explicit only`), and they skip unless they run as SYSTEM. The Tests as
SYSTEM job runs them through `tools/ci/Test-AsSystem.ps1`, which counts a skip as a failure. Never run them as
SYSTEM on a machine that is not there to be changed.

The hygiene check needs a clone that git can read:

```
pwsh -NoProfile -File tools/hygiene/Test-Hygiene.ps1
```

### Before pushing: the pre-flight

One command runs what CI runs on the working tree, every step even after one fails, and ends with a table of
the steps and one verdict:

```
powershell -ExecutionPolicy Bypass -File tools\Invoke-PreFlight.ps1 -ModulePath C:\modules -PesterVersion 6.2.0
```

| Job | Steps |
|---|---|
| .NET | `dotnet --version` is the SDK in `global.json`, then the locked restore, the build with warnings as errors and the tests, with the commands of the "Build and test (.NET)" job. A step is not run once one before it failed. |
| Hygiene | `tools/hygiene/Test-Hygiene.ps1`, as the Hygiene job runs it. |
| Workflows | `actionlint` on `.github/workflows`. No CI job runs it, so this is where a workflow change is linted. |
| Tests (powershell), Tests (pwsh) | PSScriptAnalyzer, the Pester unit tests and the desktop app layout, the "Tests" jobs of `ci.yml`, in Windows PowerShell 5.1 and in pwsh 7 when it is installed. The unit tests are judged by Pester's result and failed containers, since a discovery error is a failed container with no failed test. |

The verdict is FAILED, and the exit code 1, when any step failed. A step that cannot run on this machine, such
as actionlint when it is not on `PATH` (pass `-ActionlintPath`), shows as skipped with the reason, and the
verdict names it. `-SkipDotNet` leaves out the .NET steps on a machine without the SDK, and `-SkipLint` leaves
out PSScriptAnalyzer. `-ModulePath` names a folder holding Pester and PSScriptAnalyzer, and `-PesterVersion`
picks the Pester that CI resolves (6.x).

It runs as the current user and changes nothing on the device. What needs a disposable machine is left to CI
and the sandbox: the contract and parity runs as SYSTEM, and the Intune rehearsal
(`tools\sandbox\New-SandboxRun.ps1 -Environment ci`). `tools\New-SignedRelease.ps1` runs the pre-flight before
it builds anything.

## The audit command

`baseline.exe audit` runs the ported checks on this device, read-only, and prints the findings. With
`--json findings` or `--json status` it writes findings.json or status.json to standard output instead,
byte for byte as the file is written (UTF-8 with a byte order mark), to redirect into a file from cmd or
PowerShell 7.4 and later. It writes no file itself: files go only into the machine data folder, through
SecureStore, which the scheduled audit writes. It has no option to name an output folder: SecureStore
accepts only the sealed data folder, and a folder named on the command line may be one a standard user
controls, or once did, which nothing in its state now can rule out.

**Config.** Elevated (an elevated administrator or SYSTEM, the test the config trust gate makes), it reads
administrators' config overrides from the data folder's `config` folder through the config trust gate, as the
scheduled audit does, so that an administrator sees the result Intune will report. It opens the data folder with
`SecureStore.OpenReadOnly` (below), which judges by the same rules but changes nothing: an untrusted data folder or
`config` folder is refused and left in place, never moved aside, and a missing one is never made. It prints
`Config override used: <path>` for each override in use, on standard output beside the summary and on standard
error with `--json`, so that standard output stays the file alone; and `Warning: ...` on standard error for each
override refused or unreadable, worded as the scheduled audit words it, and once for a data folder or `config`
folder refused (`Warning: Ignoring the config overrides in the data folder and using the shipped config: <reason>`,
or `in the config folder`). A refused `config` folder names no override, since nothing in it was opened and it may
hold none; the scheduled audit would instead move it aside, with the one notice of event 1003. A refusal
uses the shipped file; an override that cannot be read, such as one a standard user has locked or holds an oplock
on, makes the checks that need it report Error, as in the scheduled audit. Nothing is written to the event log.
A data folder or `config` folder that does not exist means no overrides, and no warning.

Not elevated, it reads only the config that ships with the tool, since the data folder is for SYSTEM and
administrators. `--shipped-config` does the same when elevated: the parity harness passes it, and gives the
module an empty data folder, so that both read the shipped config whatever the runner's data folder holds.

```
baseline.exe audit --id SU-01
baseline.exe audit --id SU-01 --json status > status.json
baseline.exe audit --id SU-01 --shipped-config
```

## The data folder: SecureStore

`SecureStore`, in `Engramic.Baseline.Windows`, is the machine data folder, `%ProgramData%\EngramicBaseline`,
and the folders kept in it, checked through handles and held open while in use. It is the one file on
`src/BannedApiExemptions.txt` that opens, creates, renames or deletes files and folders, and product code
reaches files only through it (`ISecureStore`, or `IDataFolderReader` for code that only reads; the tests share a
fake).

| Folder | What it holds | Standard users |
|---|---|---|
| The data folder | `status.json` and `last-error.json` | - |
| `logs` | The scheduled audit's and the install's logs | - |
| `reports` | A folder for each audit's report | - |
| `config` | Administrators' config overrides | May read |
| `cache` | Answers kept between runs, such as the firmware catalog's | - |
| `undo` | The undo journals of fixes applied elevated or as SYSTEM | - |
| `scratch` | A folder for each run of a Windows tool that needs files | - |

Each is born locked, as the installer's `New-CEDataDirectorySecurity` makes them: owned by Administrators, with
a protected access list granting SYSTEM and Administrators full control, `O:BAD:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)`,
and Users read and execute on `config`. The PowerShell tool's `packs` folder is not made, since code packs are
not part of this tool; one an older install left is left alone.

**Three ways in.**

- `SecureStore.Open` is for everything that uses the data folder, such as the scheduled audit: the data folder
  must exist, carry the install's seal and be trusted, or it is refused; it is never created or moved. A folder
  kept in it is checked the first time it is used, and made then if it is missing.
- `SecureStore.OpenReadOnly` is for a run that promises to change nothing, such as an elevated `baseline.exe audit`
  reading administrators' config overrides. It checks the data folder exactly as `Open` does, through its handle,
  and gives a `ReadOnlySecureStore`, or nothing when there is no data folder. That store can only read (`RootPath`
  and `ReadFile`): it is not an `ISecureStore`, so no cast reaches a writer, and the SecureStore it reads through is
  out of reach. A folder kept in the data folder is opened as itself and judged by the same rules the first time a
  file in it is read, then held; one that fails, or that this account may not open to judge, is refused with a
  `SecureStoreException` that says why (`IsFolderRefused`, since nothing in it was opened) and left as it is, never
  moved aside or deleted, and a missing one reads as nothing and is not made. So it creates, moves, deletes and
  writes nothing, and never writes event 1003. A separate type, rather than a flag on SecureStore that every writer
  would have to check, makes the read-only promise something the compiler keeps for the store's own callers. The one
  place the product chooses which store an audit opens, `AuditSettings.ForThisDevice`, opens it through a function
  declared to give a `ReadOnlySecureStore`, so `SecureStore.Open` cannot take its place without that type changing,
  and `AuditCommandTests` check the type.
- `SecureStore.Initialize` is for the install and SYSTEM, with the audit mutex held as the installer holds it: it
  makes the data folder and every folder kept in it. An existing data folder is kept only when the seal exists
  and it passes the trust rules through its handle; anything else there is moved aside (below) and a fresh one
  made. A folder it makes is not sealed: the install records the seal afterwards, as the installer does.

The seal is the text value `DataRootSealed` under `HKLM\SOFTWARE\EngramicBaseline.DataRoot` (64-bit view), which
the installer writes when it makes the folder locked. A folder that looks locked but was never sealed is not
trusted: a handle a user opened while they owned a folder, or could change its permissions, keeps that access
after any later lock, and nothing in the folder's state shows that never happened.

**ProgramData** comes from the known-folder API, which builds it as `%SystemDrive%\ProgramData` from the process
environment: a process started with `SystemDrive` changed is told another folder. So the answer must be
`ProgramData` on the drive Windows is installed on (`GetSystemWindowsDirectoryW`, which comes from the kernel), or
SecureStore refuses. A ProgramData folder moved elsewhere is not supported. It is the one folder opened by its
path: with `FILE_FLAG_OPEN_REPARSE_POINT`, so a link at its name is opened as itself and seen, and
`GetFinalPathNameByHandleW` must give back the path that was opened, so no folder on the way is a link. It must be
a folder, not a reparse point, owned by SYSTEM, Administrators or TrustedInstaller. Its access list is not judged:
standard users may create folders in it, by design.

It is held with `FILE_READ_ATTRIBUTES`, `READ_CONTROL` and `SYNCHRONIZE` alone: enough to read its attributes, owner
and final path, and all that opening or creating the data folder relative to it, or renaming an item into it, needs
of its handle. Standard users may write to ProgramData, so Windows honours their refusal to share it: one who opens
it to list it, sharing nothing, stops every later open that would read, write or delete it until they let go. A
handle with none of those rights is left out of sharing checks, so they cannot stop the store opening it. Such a
handle does not stop ProgramData being renamed; the data folder held in it does, since Windows refuses to rename a
folder while anything in it is open, and each held folder's final path is checked. Renaming ProgramData needs an
administrator in any case.

**Everything below it by handle.** Every other item is opened with `NtCreateFile`, by one plain name, relative to
the handle of the folder it is in (`RootDirectory`), and with `FILE_OPEN_REPARSE_POINT`: no path is parsed, so no
link on the way can redirect it, a link at the name is opened as the link, and the file system itself refuses
`..`. Folders are held without `FILE_SHARE_DELETE` and with the right to list, which the sharing check counts (it
ignores a handle that may only read attributes or permissions), so none can be renamed, replaced or deleted while
held, and the paths the store gives, such as a scratch folder's for a tool's command line, keep naming the folders
that were checked. Each held folder's final path is checked too. Spike 1, below, records why.

Standard users may read `config`, and so may hold it open to list it without sharing. Windows ignores a refusal to
share reading from someone who may not write to what they hold, so that does not stop the store opening `config`.
That was seen on build 26200; the Security suite checks it on each build it runs on.

**Born locked.** A folder is made by `NtCreateFile` with `FILE_CREATE` and its security descriptor in the same
call, relative to its parent's handle, and the handle that call returns is the one held: there is no moment when
it exists unlocked or unheld. Anything already at the name, a junction or a file included, makes the create fail;
it is someone else's, to be judged, never adopted.

**Moving aside.** An item where the store keeps a folder that fails the trust rules is renamed through its own
handle, out of the data folder (`NtSetInformationFile`, `FileRenameInformation` with `RootDirectory` the held
ProgramData), to `EngramicBaseline.untrusted-<id>` for the data folder itself and
`EngramicBaseline.untrusted-<id>-<name>` for a folder in it, where `<id>` is 32 random hexadecimal digits: the names
the module's `Get-CEDataAsidePath` and the installer's `Get-CEAsidePath` give. A name already taken is never
replaced. A link is deleted as a link instead. Each is a notice (`Notices`) and Application event 1003 under the
`EngramicBaseline` source, worded as the module words it and naming where the item went. The module always says it
"made a fresh, locked one in its place"; the store says so only once it has, and otherwise that nothing was made in
its place, as when a read moves aside the folder it was to read from. Nothing untrusted is listed, re-owned or
repaired: a handle its maker kept still works, which is why a fresh folder is made instead.

- An item whose access list denies SYSTEM and Administrators everything is still moved: `DELETE` comes from the
  parent's `FILE_DELETE_CHILD`, and `FILE_READ_ATTRIBUTES` from its `FILE_LIST_DIRECTORY`, whatever the item's own
  list says, so it is opened with those two alone, and judged as unreadable.
- Windows refuses to rename a folder while any file in it is open, so whoever made an untrusted folder can stop it
  being moved by holding a file in it open. The store tries six times over about three seconds, by its clock, then
  fails with a message and makes nothing in its place. That stops the set-up, and nothing untrusted is used.
- A rename opens the folder it renames into, to add the name, so a standard user who holds ProgramData open without
  sharing it stops a move aside the same way, and the message names ProgramData. That too stops the set-up, and
  nothing untrusted is used.

**Trust rules** (`DataFolderTrust` in Platform, as the module's `Get-CEDataPathProblem` and the Intune
scripts judge): an item is trusted when it is not a reparse point and not stored online only; is owned by
SYSTEM, Administrators or TrustedInstaller; has an access list; gives no other account `FILE_WRITE_DATA`,
`FILE_APPEND_DATA`, `FILE_WRITE_EA`, `FILE_DELETE_CHILD`, `FILE_WRITE_ATTRIBUTES`, `DELETE`, `WRITE_DAC`,
`WRITE_OWNER`, `GENERIC_WRITE` or `GENERIC_ALL` in any entry, inherited and inherit-only ones included;
and denies a trusted account nothing. Rights to read are fine for anyone, and so is CREATOR OWNER. Unlike
the module, whose `Get-Acl` drops entries it does not recognise, an entry of an unknown kind fails. The data
folder also needs the seal; a folder kept in it does not. A file the store reads must also be an ordinary file
with one name, no longer than its caller allows.

**Writing** a file replaces it atomically, so a reader sees the old file or the new one:

1. Whatever is at the target's name is opened as itself: it must be nothing, or an ordinary file with one
   name that is not read-only. A link, a folder or a file with other names (hard links) is refused and
   left as it is.
2. A new file, `<name>.<32 random hex digits>.tmp` as the module names its own, is created with `FILE_CREATE`,
   no sharing and `FILE_OPEN_REPARSE_POINT` (a link already at that name is a collision, never followed), owned
   by Administrators, which SYSTEM and an elevated administrator may name, and taking the folder's access list.
   Its final path, its facts and its security are checked through its handle.
3. It is written, flushed and renamed over the target through its handle, relative to the folder's handle
   (`FileRenameInformation` with replace). The rename replaces the target's name and never writes into or
   through it: a hard link or symbolic link swapped in after step 1 is replaced as a name, and a junction or
   folder makes the rename fail. The file's final path is checked afterwards.
4. While another process, such as a reader or an antivirus scan, has the target open, the rename fails;
   it is tried six times over about three seconds, by the store's clock. A write that fails deletes its
   new file through its handle.

**Reading** a file (`ReadFile`), such as an administrator's config override or a cached answer: it is opened
relative to its folder's handle, as itself, and shared with readers alone, so it cannot change while it is read.
It is read only when the trust rules pass for it and it is no longer than the length the caller gives, at most
64 MiB; a longer file is refused, never cut short. A missing file, or a missing folder, reads as nothing, and so
does an untrusted folder, once it has been moved aside. Through `ReadOnlySecureStore`, an untrusted folder is
refused instead (`SecureStoreException.IsFolderRefused`), and stays where it is.

A file that breaks a rule, or whose access list keeps this account out, is refused. One that cannot be opened or
read at the time is not judged at all, and the `SecureStoreException` says so (`IsUnavailable`): the file or its
folder held open by another process without sharing, part of the file locked, or a device error. Anyone who may
read the file can lock part of it, and standard users may read the `config` folder. Holding the file or its folder
open without sharing stops the read only when the holder may write to what they hold: Windows ignores a refusal to
share reading from a holder who may only read it. Nor does the store wait on an oplock another process holds on the
file or a folder it judges: those opens use `FILE_COMPLETE_IF_OPLOCKED`, so an open that would wait for the holder
to acknowledge the break comes back at once and is tried again, like one refused for sharing, six times over about
three seconds. A holder who never acknowledges would otherwise hold the read, and the lock the config trust gate
holds while it reads, for as long as they liked.

**Scratch folders** (`CreateScratchFolder`) hold the files a Windows tool reads and writes, such as `secedit`'s
INF and database: each is born locked under a random name in `scratch`, where the module's `New-CEScratchFolder`
makes its own, held while in use, and deleted with everything in it when disposed. Nothing elevated writes to or
reads back from the temp folder, which for SYSTEM is shared with other accounts.

**Deleting a tree** (`DeleteTree`, and a scratch folder's disposal): each item is opened relative to its folder's
handle and as itself, and a link is deleted as a link. Each folder is checked through its handle just before it is
listed, and listed through that handle (`GetFileInformationByHandleEx`), so what is listed is what was checked; a
folder that fails, one this account cannot read, a quarantine (`*.untrusted-*`) and anything more than 64 folders
deep are left in place, unlisted, and named in what the delete returns. Paths are never built, so a tree deeper
than Windows allows a path is deleted all the same. Where Windows can (version 1709 and later), each item goes at
once, with POSIX semantics, and a read-only file goes without its attribute being changed (1809 and later), since
its other names share the attribute; otherwise a read-only file with one name has the attribute cleared first, and
one with other names is left in place.

**Undo journals** of fixes applied elevated or as SYSTEM go in `undo` (`WriteFile(DataFolder.Undo, ...)`), locked
like the rest, so that an elevated restore reads a journal no standard user could have changed.

Tests give the ProgramData path, the seal's location, the event log and the clock (`SecureStoreOptions`), and
the trust rules and the owner of what the store makes, so that they run without elevation in folders of their
own. The config trust gate (below) reads administrators' overrides through `ReadFile`, of SecureStore in the
scheduled audit and of `ReadOnlySecureStore` in an elevated `baseline.exe audit`. Still to come:
`baseline.exe setup`, which will call `Initialize` and write the seal.

### Spike 1: walking paths

The question was how SecureStore should reach items below ProgramData without ever following a link: open each
relative to its parent's handle (`NtCreateFile` with `RootDirectory`, and `OBJ_DONT_REPARSE` if build 14393 has it),
or open each by its path without `FILE_SHARE_DELETE`, hold the handles, and confirm each path with
`GetFinalPathNameByHandleW`.

**Decision: both, each where it is strong.** ProgramData, the anchor, is opened by its path and confirmed by its
final path, as before, and held with `FILE_READ_ATTRIBUTES`, `READ_CONTROL` and `SYNCHRONIZE` alone, which sharing
checks ignore, so that a standard user who may write to it cannot keep the store out by holding it open without
sharing. The relative opens and renames need no access on its handle, and the data folder held in it keeps it from
being renamed. Everything below it is opened by relative `NtCreateFile`, one plain name at a time, with
`FILE_OPEN_REPARSE_POINT`, and renamed by `NtSetInformationFile` relative to a held folder; folders stay held
without `FILE_SHARE_DELETE`, so that the paths given to tools keep naming them, and are confirmed by their final
paths. `OBJ_DONT_REPARSE` is not used: with one name at a time there is no folder on the way for it to guard, and a
link at the name must be opened as itself to be deleted or moved aside. Nothing in the design is newer than build
14393, apart from the faster deletion, which falls back to the older one. The invariant tests hold SecureStore to
it (`SecureStoreDesignTests`).

**Why.** A relative open parses no path, so there is nothing for a link on the way to redirect. It creates a folder
and returns its handle in one call, where a path-based create must open the folder again afterwards. It needs no
long paths for deep trees. And a rename can name its target folder by handle, which the Win32 call refuses.
The fallback, had the relative opens failed on a build, was the first version's way: path-based opens with
`FILE_FLAG_OPEN_REPARSE_POINT` inside held folders, each confirmed by its final path.

**Evidence, on build 26200** (Windows 11 25H2, an enablement update of 24H2's build 26100), from a throwaway
program and from `PathWalkingTests`, which run wherever the tests run:

| What | Result |
|---|---|
| One name, relative, with `FILE_OPEN_REPARSE_POINT`, where it is a junction | The junction itself |
| The same without `FILE_OPEN_REPARSE_POINT` | Where the junction leads |
| Two names, relative, the first a junction (`junction\file`) | Followed, even with `FILE_OPEN_REPARSE_POINT`, which covers the last name alone: so names are opened one at a time |
| The same with `OBJ_DONT_REPARSE` | `STATUS_REPARSE_POINT_ENCOUNTERED` (0xC000050B) |
| `OBJ_DONT_REPARSE` and `FILE_OPEN_REPARSE_POINT`, one name, a junction | The junction itself |
| `OBJ_DONT_REPARSE` on an absolute `\??\C:\...` path | Opened: the drive letter is an object manager link, not a reparse point |
| `..\sibling`, relative | `STATUS_OBJECT_NAME_INVALID` (0xC0000033) |
| `FILE_CREATE` over a junction or a folder | `STATUS_OBJECT_NAME_COLLISION` (0xC0000035) |
| `FILE_CREATE` with a security descriptor | Born with exactly that owner and protected access list |
| `FILE_CREATE` naming Administrators as the owner, not elevated | `STATUS_INVALID_OWNER` (0xC000005A) |
| `FILE_OPEN_NO_RECALL` beside `FILE_DIRECTORY_FILE` | `STATUS_INVALID_PARAMETER`, so it is given for files only |
| `NtSetInformationFile` rename with a folder's handle as `RootDirectory` | Renamed into that folder |
| `SetFileInformationByHandle` rename with a `RootDirectory` | `ERROR_INVALID_PARAMETER` (87) |
| Relative open, `FILE_CREATE` and rename, through a folder's handle that has only `FILE_READ_ATTRIBUTES`, `READ_CONTROL` and `SYNCHRONIZE` | Done: the folder's handle needs no access |
| A folder held open to list it with no sharing, by an account that may write to it | A later open to list it: `ERROR_SHARING_VIOLATION` (32); one with only `FILE_READ_ATTRIBUTES`, `READ_CONTROL` and `SYNCHRONIZE`: opened; a rename into it: `STATUS_SHARING_VIOLATION` (0xC0000043) |
| The same, by an account that may only read it | Its refusal to share reading is ignored: a later open to list it succeeds |
| Renaming a folder held without `FILE_SHARE_DELETE` | `ERROR_SHARING_VIOLATION` (32) |
| Renaming a folder held only with `FILE_READ_ATTRIBUTES`, `READ_CONTROL` and `SYNCHRONIZE` | Renamed: such a handle is left out of sharing checks |
| Renaming a folder with a file open in it, shared for deletion or not | `ERROR_ACCESS_DENIED` (5) |
| A child that denies this account everything, opened for `DELETE` and `FILE_READ_ATTRIBUTES` without `SYNCHRONIZE` | Opened, through its parent's rights; renamed and deleted through that handle |
| The same child opened with `READ_CONTROL` or `SYNCHRONIZE` | `STATUS_ACCESS_DENIED` |
| A chain of 300 folders made and deleted by relative opens | Done, though its path was over 5,000 characters |
| A folder listed through its handle (`FileFullDirectoryInfo`) | Its names, a junction as a reparse point, not entered |

**Still to run on builds 14393, 17763 and 19045**, by running `PathWalkingTests` and the Security suite on lab
machines of those builds: that relative `NtCreateFile` with `FILE_OPEN_REPARSE_POINT`, and `FILE_CREATE` with a
security descriptor, behave as above; that `NtSetInformationFile` renames relative to a folder's handle; that a
hostile child opens through its parent's rights; that a holder who may only read a folder cannot refuse to share
reading it (`PathWalkingTests`, and the attacker holding `config` in the Security suite), since on a build where
it does not hold a standard user can stop the store opening `config`; and which of `FileDispositionInformationEx`'s POSIX semantics
(1709) and read-only override (1809) each build takes, since the store falls back to the older deletion where they
are missing (`ClassicDelete` in `SecureStoreHooks` tests that way on any build). `OBJ_DONT_REPARSE` is reported,
not relied on: `PathWalkingTests` accepts `STATUS_REPARSE_POINT_ENCOUNTERED` or `STATUS_INVALID_PARAMETER` for it,
and writes which to the test output. The GitHub runners cover Windows Server 2025 (build 26100) in the meantime.

## Detection

What the AI tool checks will read about the device, from primitives in the Windows library that compile with
Native AOT. None of them uses WMI or WinRT, and none opens a file by a path it is given: the signature check has
Windows read the file through a handle, and Windows opens a catalog itself, by the path its catalog database
holds.

- **Processes** (`WindowsProcessList`, behind `IProcessList`): the process table from a Toolhelp snapshot, then
  for each process its image path (`QueryFullProcessImageName`), its command line (`NtQueryInformationProcess`
  with `ProcessCommandLineInformation`, Windows 8.1 and later), its session, and from its access token its owner
  (`TokenUser`) and elevation (`TokenElevation`). Each process is opened with
  `PROCESS_QUERY_LIMITED_INFORMATION` and its token with `TOKEN_QUERY`, the least either can be opened with, so
  the reader can neither read another process's memory nor change anything. The image path, session, owner and
  elevation are Windows' own records of the process. The command line is not: Windows copies it from the
  process's own memory, where the process may have rewritten it since it started, and `Win32_Process.CommandLine`
  reads the same copy. It is the process's own claim, so a check should not rely on it alone. Parity is
  unaffected: the module tells the AI tools that run in `node.exe` apart by command line alone
  (`config/ai-tools.json`), so a tool that rewrites its own escapes that match in both. What this account may not
  open stays null: not elevated, the tokens of other accounts' processes; elevated, a few of Windows' own (the
  runner read the owners of 150 of 151); either way, a process that ended between the snapshot and the open. A
  process identifier can be reused, so an entry describes the process that had it when it was opened.
- **Installed programs**: the registry primitive lists a key's subkeys (`IRegistry.GetSubKeyNames`) and reads
  `HKEY_USERS`, so a reader can do what the module's `Get-CEInstalledSoftware` does: walk
  `SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall` in both views of HKLM and in one user's hive. That
  hive is HKCU, or as SYSTEM the hive of the person signed in at the console, under `HKEY_USERS` (none when no
  one is). The module reads no other hive. A reader that walked every loaded hive would also count the programs
  of a second person signed in, or of a service account whose profile is loaded: a difference from the module
  that `tests/parity/divergences.json` would have to record. Neither reads `HKEY_USERS\S-1-5-18`, SYSTEM's own
  hive, where a per-user installer run as SYSTEM (by Intune, for example) registers, nor the hive of anyone not
  signed in. Another person's hive throws `UnauthorizedAccessException` unless the reader is elevated or SYSTEM.
- **Signatures** (`FileSignatures.Verify`): Authenticode, read through a handle the caller opened, as
  `Get-AuthenticodeSignature` checks it: a signature embedded in the file, or else a catalog of Windows that holds
  the file's hash (SHA-256, then SHA-1), which is how most files of Windows are signed. It gives the state, the
  signer's common name, whether the signature came from a catalog, and WinVerifyTrust's result. It checks no
  revocation and fetches nothing from the network, so it never waits on one. A catalog signs a hash, not a
  place: a copy of `cmd.exe` in a temp folder is valid, so the trusted process runner must also check where a tool
  is. `WinVerifyTrust` is sensitive (above), so `FileSignatures.cs` is on `src/BannedApiExemptions.txt` and
  names it only in pragma regions. Every call passes the caller's handle; for a catalog signature Windows opens
  the catalog by the path its catalog database gives, in `System32\CatRoot`, which only Windows and
  administrators may change.
- **File versions**: no primitive. `FileVersionInfo.GetVersionInfo` reads by path, which product code may not, and
  the module reads no file versions. A check that needs one would read the version resource through a handle.
  Windows also gives a process whose manifest does not declare Windows 10, as `baseline.exe`'s does not, the
  fixed version of its own files as 6.2 (`cmd.exe` 10.0.26100 reads as 6.2.26100), so such a check reads the
  text version or the exe gets a manifest.

### Spike 7: detection under Native AOT

The question was whether Model, Platform, Engine and Windows can run detection compiled with Native AOT, so that
an app built on them could be published Native AOT while `baseline.exe` stays JIT with ReadyToRun; and what
Native AOT costs and buys.

**Proposed decision: keep the four libraries AOT-clean with detection in them, held there by the canary on every
change, and keep `baseline.exe` and the desktop app JIT with ReadyToRun.** Detection runs under Native AOT with no
warning and no change to how the libraries are written. An app built on them that wants a small, quick-starting
exe may publish Native AOT: on the runner the canary started in about half the time, ran in about 40 percent of
it, peaked at 68 percent of the memory and shipped one 9 MB file instead of a 78 MB folder. The cost is a C++
linker wherever it is published, and a rebuild for each .NET patch, as for `baseline.exe` today.

**Fallback.** Such an app publishes self-contained JIT with ReadyToRun, as `baseline.exe` does; the libraries need
no change, and the canary's JIT run shows they work that way. A primitive that cannot be AOT-clean
(System.Management, WinRT, COM through the runtime's marshalling) goes in a project the four libraries never
reference, and an app published Native AOT goes without it.

**What the canary proved before this spike**, compiled with Native AOT on the runner: the status files and config
read and written with source-generated JSON; SIDs and registry values; the check runner, the framework rollups
and the config trust gate; the console session, a registry read in the 64-bit view and the account from
`WindowsIdentity`; the data folder's trust rules; SecureStore refusing a missing ProgramData folder (the
known-folder API and `CreateFile` through CsWin32); the audit mutex with its access list; the proxy rules, the
machine's WinHTTP proxy, and the service client's `HttpClient` sending to a loopback site.

**Added by this spike**, each printing a fact and failing the canary on error:

| Step | Through | On the runner (Server 2025, build 26100) |
|---|---|---|
| Processes, with owner and elevation from tokens | `WindowsProcessList` | 151 processes; 150 owners, 134 elevated, 148 paths and 147 command lines read; this canary found as itself; 10 ms |
| Installed programs | `WindowsRegistry.GetSubKeyNames` and `GetValue` | 40 in the 64-bit view and 19 in the 32-bit view of HKLM; 1 loaded user hive, with none; 24 ms |
| Authenticode | `FileSignatures.Verify` | `cmd.exe` valid in a catalog, signed by Microsoft Windows; `vcruntime140.dll` valid, embedded; the canary itself not signed; 133 to 246 ms, most of it the first catalog lookup |
| File version | `FileVersionInfo`, in the canary | `cmd.exe` read; product code has no version reader (above) |

**CsWin32 and `LibraryImport`.** CsWin32 0.3.335 with `"allowMarshaling": false` generates `DllImport`s that pass
blittable values only (`BOOL`, `HANDLE`, `PCWSTR`, pointers), loads from System32, and saves the last error
itself (`Marshal.SetLastSystemError` and `SetLastPInvokeError`) rather than through `SetLastError = true`. It
generates `LibraryImport` only in its build-task mode with marshalling allowed. Native AOT compiles a blittable
`DllImport` to a direct call, so `LibraryImport` would add nothing here. Turning runtime marshalling off in
Windows makes that a rule (above): the Windows tests pass unchanged, and a string parameter fails the build with
CA1420. One thing to know: with marshalling off, a `bool` passes as one byte, not a Win32 `BOOL`; CsWin32 uses
`BOOL`, and hand-written native calls are not allowed.

**Measurements.** The canary prints the time from its process's creation to `Main` (the runtime's start-up), from
`Main` to its end (all its steps), its peak working set and the size of the files it ships. Compiled with Native
AOT on the runner, it runs itself and the JIT build that the build step left in `artifacts/bin` five times each,
one after another, and prints the medians. That JIT build is framework-dependent and carries the feature
switches `PublishAot` sets in its `runtimeconfig.json`. Both use invariant globalization, as `AotCanary.csproj`
sets, so neither loads ICU, which `baseline.exe` does: they compare like for like, but their run times and
working sets leave out what ICU costs (the laptop's figures below show it). On the runner (`windows-latest`,
Windows Server 2025, build 26100), from the "Run the AOT canary" step of two runs:

| Build | Files | Size | Start-up | Run | Wall | Peak working set |
|---|---|---|---|---|---|---|
| Native AOT | 1 | 8.99 MB | 21 to 24 ms | 149 to 166 ms | 183 to 201 ms | 31.9 MB |
| JIT, framework-dependent | 6, and the shared runtime | 0.81 MB | 42 to 44 ms | 377 to 398 ms | 453 to 476 ms | 46.6 MB |

On the maintainer's laptop (build 26200), JIT builds only, since it has no C++ linker. Each figure is the median
of 7 runs, each build run in turn with the others after one warm-up run of each, in two passes; a range spans the
two passes. The self-contained builds were published from a copy of the worktree, since their restore differs
from the locked one. The ReadyToRun build with ICU is published as `baseline.exe` is, with:

```
dotnet publish tests/AotCanary/AotCanary.csproj -c Release -r win-x64 --self-contained -p:PublishAot=false
  -p:PublishReadyToRun=true -p:InvariantGlobalization=false -p:StartupHookSupport=false
  -p:JsonSerializerIsReflectionEnabledByDefault=false -o <folder>
```

Its `runtimeconfig.json` holds the switches of `baseline.exe`'s, as `tools/New-SignedRelease.ps1 -DotNet`
publishes it, and none of `PublishAot`'s. The self-contained JIT build sets `-p:PublishReadyToRun=false` instead,
and the invariant ReadyToRun build leaves out the last three properties, keeping the canary's invariant
globalization.

| Build | Files | Size | Start-up | Run | Wall | Peak working set |
|---|---|---|---|---|---|---|
| JIT, framework-dependent, invariant (the build the runner times) | 6, and the shared runtime | 0.81 MB | 39 ms | 213 to 214 ms | 276 to 283 ms | 45.0 MB |
| JIT, self-contained, with ICU | 193 | 77.4 MB | 57 to 58 ms | 217 to 220 ms | 308 to 311 ms | 49.1 to 49.2 MB |
| ReadyToRun, self-contained, invariant | 193 | 78.1 MB | 53 ms | 164 to 165 ms | 248 ms | 45.6 to 45.7 MB |
| ReadyToRun, self-contained, with ICU, as `baseline.exe` is published | 193 | 78.1 MB | 54 to 57 ms | 174 to 177 ms | 265 to 268 ms | 47.8 to 47.9 MB |

ICU added 10 to 12 ms to the run, 17 to 20 ms to the wall time and about 2.2 MB to the peak working set, and
nothing to start-up, since .NET loads it at the first use of a culture, after `Main`. The runtime uses the ICU that
Windows 10 1903 and later carry (NLS before that), so the folder is no bigger. ReadyToRun took about 43 ms off
the run of the self-contained build with ICU.

Publishing the canary with Native AOT took 36 seconds on the runner, about 20 of them in the AOT compiler.

**What Native AOT costs an app built on these libraries:**
- A C++ linker (the Visual Studio build tools) wherever it is published. CI has one; the machine that signs
  releases, which publishes `baseline.exe` today, does not, so such an app is published by CI or on a machine with
  the build tools.
- One exe holding the runtime as well as the app, so every .NET security fix means a rebuild and a new signature,
  as for self-contained `baseline.exe`; and nothing in the exe keeps Microsoft's own signature.
- What the runtime does not do without a JIT: no `Reflection.Emit`, no reflection-based JSON, no loading
  assemblies, no built-in COM, and no EventSource tracing unless switched back on. The rules above already keep
  all of these out of the four libraries.

**What stays out of the AOT-clean libraries:** System.Management (CIM and WMI); WinRT, including
`PackageManager`; COM that relies on the runtime's marshalling, such as WUA, the Task Scheduler and WinGet's COM
API, which under Native AOT would need source-generated COM; reading a file by path, `FileVersionInfo` included;
and the desktop app's WPF. These belong in a separate Windows project for CIM, WinRT and COM, which the four
libraries never reference.

**Still to run:** the canary and the new tests on builds 14393, 17763 and 19045, for `ProcessCommandLineInformation`
(8.1 and later), `CryptCATAdminAcquireContext2` and `CryptCATAdminCalcHashFromFileHandle2` (8 and later) and the
SHA-1 catalog fallback, which no file on the runner needs; detection as SYSTEM with a person signed in, since the
runner's canary runs as its elevated administrator, whose hive holds no programs; Native AOT for Arm64; and a
signed Native AOT exe under Smart App Control and App Control. The ReadyToRun figures come from the laptop only,
since the runner publishes no ReadyToRun build of the canary. `ProcessCommandLineInformation` is not among the
classes `NtQueryInformationProcess`'s documentation lists, though Windows has had it since 8.1. Matching the AI
tool catalog, Store packages, the profile reads, and the console user's SID that a reader running as SYSTEM
needs to find that person's hive, are not in this spike.

## Config: the config trust gate

The checks read config through `IConfigFiles`. The shipped files are built into Controls (`ShippedConfig`, above),
and the config trust gate, `ConfigTrustGate` in Engine, puts in front of each one an administrator's override
that passes every rule, as the module's `Get-CEConfig` does with `Get-CEDataPathProblem`. An override is a whole
file of the same name in the data folder's `config` folder, and it replaces the shipped file whole: nothing is
merged. Two runs read overrides: the scheduled audit, as SYSTEM, through the SecureStore it holds; and
`baseline.exe audit` when it is elevated and not given `--shipped-config`, through `SecureStore.OpenReadOnly`,
since it promises to change nothing (above). The gate is the same for both; only what happens to an untrusted
`config` folder differs. An override is used only when all of these hold:

| Rule | Held by |
|---|---|
| The run is elevated or SYSTEM. A run that is not reads no override from the machine: the data folder is for SYSTEM and administrators. | `ConfigTrustGate` |
| The file ships and has a schema (`ConfigFile.Names`): only a file the tool reads can be overridden. | `ConfigTrustGate` |
| SecureStore reads it, relative to the handle of the `config` folder it holds (which it checks first, and, when untrusted, moves aside with event 1003 in the scheduled audit, or refuses and leaves in place in `baseline.exe audit`), and as itself: not a junction, symbolic link or other reparse point, not stored online only, an ordinary file with one name, owned by SYSTEM, Administrators or TrustedInstaller, giving no one else a right to change it, denying them nothing, and no longer than 1 MiB (`ConfigTrustGate.MaxOverrideLength`, many times the largest file in the config folder). | `SecureStore.ReadFile`, `DataFolderTrust.FindReadProblem` |
| It meets its file's schema: UTF-8, with or without a byte order mark; one JSON object and nothing after it; no comments or trailing commas; no member named twice in one object, whatever the case of its letters, since the reader matches names without regard to case; no more than 64 objects and arrays deep; and accepted by the file's source-generated reader, the one the checks use, with its required members and their types. Members the model does not have are allowed and not read, as the shipped files carry notes. | `ConfigFile.FindProblem` |

Otherwise the shipped file is used, and the refusal is one of the gate's notices, naming the override and why, for
the run to log. Nothing is changed to get round a refusal. Each file is decided the first time the run reads it,
and later reads give the same bytes. A `config` folder refused as a whole, as `ReadOnlySecureStore` refuses an
untrusted one (`SecureStoreException.IsFolderRefused`), is one notice that names the folder and no file, since
nothing in it was opened and it may hold no override; every file is then the shipped copy for the rest of the run.
The gate may be read from several threads, and reads the data folder one file at a time, as SecureStore needs.

**An override that cannot be read is not refused.** When SecureStore could not open or read it at all
(`SecureStoreException.IsUnavailable`, above), nothing about it was judged and what it holds is not known. A
standard user can bring that about for as long as they like, by locking part of the override or holding an oplock
on it, so falling back to the shipped copy would let them undo an administrator's override without a trace.
Holding the override or the `config` folder open without sharing does the same for a process that may write to
them; from a standard user, who may only read them, Windows ignores that refusal. Instead every read of that file
in the run throws, each check that needs it reports an Error finding, and the gate's notice says why. Any other
failure to read it counts the same way: only a refusal, by SecureStore's rules or the file's schema, uses the
shipped copy.

**A file joins with its schema.** A config file that joins the shipped config joins `ConfigFile`'s schemas in the
same change: `ShippedConfigTests` fails while a shipped file has no schema, and the gate refuses every override of
such a file. `network.json`, the service client's proxy settings (below), has its reader as its schema,
`ConfigFile.ReadNetwork`. Every member of it is optional and a value of another type takes its default, as the
service client reads it, so what refuses an override of it is almost always a rule every file meets, such as a
member named twice or text that is not UTF-8. The checks read the settings through `AuditConfig.Network`, from the
run's config, so an override reaches the first check that sends a request through the gate.

**Differences from the module**, each deliberate:

- A run that is not elevated reads no override, so a standard user's `baseline.exe audit` uses only the shipped
  config. The module's audit reads any override it can list when it is not elevated, and the trusted ones when it
  is. An elevated `baseline.exe audit` reads them as the scheduled audit does, so an administrator's result matches
  what Intune reports; what is left of the difference is that a run that is not elevated reads none.
- The data folder must carry the install's seal (SecureStore) before any override in it is read. The module reads
  overrides wherever the permissions pass.
- An override that is not valid is refused and the shipped file used. In the module, one that `ConvertFrom-Json`
  cannot read stops the config load, and with it the audit.
- An override must be UTF-8, with or without a byte order mark: one strict format for a file that SYSTEM trusts.
  The module read overrides with `Get-Content -Raw`, which follows a UTF-16 byte order mark (what Windows
  PowerShell 5.1's `>` and `Out-File` write) and in 5.1 reads a file without one as ANSI (what its `Set-Content`
  writes), so an override saved either way loaded there. Here it is refused and the shipped file used, and the
  notice and event 1003 say what was found and what to do: that the file is saved as UTF-16, or is not UTF-8 at a
  given line and may be ANSI, and to save it as UTF-8, for example with `Set-Content -Encoding utf8`. ANSI text
  with no character outside ASCII is already UTF-8, and loads.
- The scheduled audit moves an untrusted `config` folder aside, with event 1003, rather than only ignoring it. An
  elevated `baseline.exe audit`, which changes nothing, refuses it, warns once of the folder, and uses the shipped
  files.
- In the scheduled audit each refused or unreadable override is also event 1003, not only a warning in its output;
  `baseline.exe audit` warns on standard error alone. An override that cannot be read fails the checks that need
  it, where in the module it stops the config load and with it the audit.

**Tests.** `ConfigSchemaTests` (Model) hold each rule of the schema, and `network.json`'s: a copy like the shipped
one passes, as does a value of another type, and a malformed one is refused. `ConfigTrustGateTests` (Engine) hold the gate's
rules with a data folder in memory, including each of SecureStore's refusals as `DataFolderTrust` words it, and
each kind of read failure, which is not a refusal. In the attack suite, `ConfigTrustGateTests` (Windows) plant an
override that breaks each rule in a data folder of the tests' own and read it through the real SecureStore, without
elevation, and hold it up in each way a reader can (`Holders`: the override held open without sharing, locked in
part, or under a batch oplock never acknowledged, and the `config` folder held open without sharing), which must
fail the checks within the store's retries and never give the shipped copy; `ConfigTrustGateElevatedTests` use the
product's rules in a data folder made as the installer makes it: an override that a standard user owns (the
attacker plants it), that standard users can change, or that is a symbolic link, a junction or a hard link is
refused and the shipped file used, one owned by Administrators loads, the attacker locking an administrator's
override or holding an oplock on it does not get the shipped copy used in its place, and the attacker holding the
override or the `config` folder open without sharing does not stop it loading. The Security job runs them as the
elevated administrator and as SYSTEM; they also read through `SecureStore.OpenReadOnly`, where an untrusted `config`
folder, made standard-user-changeable or by the attacker, is refused, left in place and named in one notice of the
folder. `SecureStoreReadOnlyTests` (Windows, without elevation) refuse a missing ProgramData folder and an
unsealed, untrusted or linked data folder or `config` folder through the read-only store, the `config` folder as a
folder (`IsFolderRefused`), give nothing for a missing data folder, read a trusted override, and
show after each that the tree is unchanged name for name and byte for byte (`TreeSnapshot`), that no step that would
change something was reached, and that no event was written; they also hold that `ReadOnlySecureStore` has no
writer. `ScheduledAuditTests` (Cli) hold the scheduled audit's use of the gate, and, elevated, read an override
through the real SecureStore. `AuditCommandTests` (Cli) hold that `baseline.exe audit` reads overrides only when
elevated and not given `--shipped-config`, what it prints for each override used and refused, that a refusal of the
data folder or an unreadable override is reported as the scheduled audit reports it, that a refused `config` folder
is one warning of the folder, that its settings for this device open the data folder only through the read-only way
in, and, elevated, that through the real read-only store it reads an override, and leaves an untrusted `config`
folder and an unsealed data folder as they were, with no event.

## The service client

The tool's own requests, such as those to the firmware catalog, go through one service client, as the module's go
through `14-ServiceClient.ps1`. Its contract is portable: `IServiceClient`, its request and response, and
`ProxyChooser`, in Platform. On Windows, `ServiceClient` sends the requests and `WinHttpProxy` says what Windows says
about proxies. `ServiceClient.cs` is the one file on `src/BannedApiExemptions.txt` that makes an `HttpClient` or a
handler.

**A request** is one GET:

- to an https address, or plain http to this device (`localhost`, `127.0.0.1` or `::1`) for a development server.
  Anything else is refused before a route is chosen, wherever the address came from. `ServiceUri.TryResolve` joins a
  configured base address and a path, and says what is wrong in the module's words;
- with `User-Agent: EngramicBaseline/<version>`, and `If-None-Match` when the caller holds a copy;
- held to 1 to 600 seconds (20 by default) and 1 KB to 16 MB of body (64 KB by default), as in the module: a slower
  or larger response fails it;
- through a handler made for it alone, which sends the site nothing but the request: no Windows sign-in, no cookies,
  no redirect followed (a 3xx comes back as it is) and nothing decompressed. The site's certificate is checked
  against the operating system's trusted roots, with no pinning.

A failure comes back as a response with status 0 and an error, never as an exception: the innermost message, then the
module's hint, "If this device uses a proxy, set proxyUrl in network.json."

**The route.** Each request's handler names its proxy, or has none. .NET's default proxy is never used: it follows
environment variables (`HTTPS_PROXY` and the like) that whoever starts the process sets, and as SYSTEM it reads
SYSTEM's own Internet settings. `ProxyChooser` takes the first of these that applies, and notes on the route what it
passed over and why:

1. An address on this device, or a name without a dot, goes direct.
2. `proxyUrl` in `network.json`, when it is an http:// address. An https:// one is passed over with the module's
   warning, since the file is shared with the module and Windows PowerShell cannot use one.
3. The machine's WinHTTP proxy (`netsh winhttp set proxy`), from `WinHttpGetDefaultProxyConfiguration`, unless the
   process runs as SYSTEM and `useWinHttpProxyWhenSystem` is false: direct when its bypass list names the host (with
   `*` and `?`, and `<local>` for names without a dot); otherwise its http proxy for the scheme, or direct when it
   names none for the scheme, as WinHTTP itself would.
4. A PAC file: the one at `proxyAutoConfigUrl` when that is set, otherwise, when `proxyAutoDetect` is true, the one
   WPAD finds through DHCP and DNS. `WinHttpGetProxyForUrl` asks it out of process only: the WinHTTP Web Proxy
   Auto-Discovery service downloads and runs the script, never this process, and its server is never sent the
   sign-in. The script is asked about the scheme, host and port alone, never the path or query, and the first http
   proxy it names is used, or none when it says `DIRECT`. A lookup that finds nothing, fails, or gives no answer
   within 10 seconds (or the request's own time, if that is shorter) goes direct with a note. A configured PAC file
   that fails does not fall back to WPAD.
5. Otherwise the request goes direct.

**The Windows sign-in** (NTLM or Kerberos; as SYSTEM, the computer account's) goes to a proxy only when
`proxyUseDefaultCredentials` is true, and never to one that WPAD found, since whoever answers WPAD on the local network
could collect it. Such a proxy can be named in `proxyUrl`, or its PAC file in `proxyAutoConfigUrl`.

**Settings.** `NetworkSettings`, in Engine, reads `network.json` through `IConfigFiles`, and a check reads it through
`AuditConfig.Network`, from the run's config: the config trust gate (above) in the scheduled audit and an elevated
`baseline.exe audit`, so an administrator's override that passes every rule, `network.json`'s schema included,
replaces the shipped copy whole; and the shipped copy alone in an audit that is not elevated or is given
`--shipped-config`. Nothing in the product makes a `ServiceClient` yet: SU-08, the first check that will, takes its
settings from there. What each case gives:

- No override: the shipped copy.
- An override the gate refuses, by SecureStore's rules or the schema: the shipped copy, and the gate's warning, which
  the scheduled audit also writes as event 1003. The routes carry no note of it, since the override never reached
  the settings.
- An override that could not be read, as a standard user can bring about by locking it: `AuditConfig.Network`
  throws, so the check that needs it reports an Error, as for any config file. The defaults are not used in its
  place, or whoever held the override up could turn WPAD back on, or a named proxy off, unseen.
- A `network.json` that is missing or not valid, which through the gate can only be a broken shipped copy, and the
  tests keep that from shipping: the defaults, with the problem noted on every route.

**Tests.** `ProxyChooser` is covered branch by branch with a fake of what Windows says, in the Platform tests, which
run on Linux too. The Windows tests send real requests to servers on the loopback address: a site; a proxy that
answers `CONNECT` and asks for NTLM, to see the sign-in sent only when it is allowed; and the host of PAC files, which
the real WinHTTP service fetches. They only read the machine's own settings. Five explicit tests run as SYSTEM in the
Tests as SYSTEM job: `network.json`'s proxy; the WinHTTP proxy set with netsh, and its bypass list; a named PAC file;
a PAC file that WPAD finds through names added to the hosts file, served on port 80 through http.sys for those
names only, since CI's runner refuses a socket of our own on port 80; and plain http refused. The settings are
read through the gate in `NetworkSettingsTests` (Engine: an override that passes, one the schema refuses, and one
that could not be read) and `ShippedConfigTests` (Controls: an override in place of the real shipped copy), and
`ScheduledAuditTests` and `AuditCommandTests` (Cli) hold that a check is given an override only where the run reads
overrides; `ScheduledAuditTests` also that the check reports an Error when the override could not be read.

**Differences from the module.** These are deliberate. Once SU-08, the check that asks the firmware catalog, is
ported, any difference they make to its findings goes in the parity ledger.

| The module | baseline.exe | Why |
|---|---|---|
| With no `proxyUrl`, as SYSTEM, uses the WinHTTP proxy if one is set; otherwise .NET's default proxy, from the account's own Internet settings | Uses the WinHTTP proxy for every account (as SYSTEM, unless `useWinHttpProxyWhenSystem` is false), then a PAC file, then goes direct, and never an account's own Internet settings | The default proxy follows environment variables, and as SYSTEM, SYSTEM's own settings. An account whose proxy is set only in its own Internet settings needs `proxyUrl`, `proxyAutoConfigUrl` or the WinHTTP proxy |
| Has no PAC file or WPAD of its own | Reads `proxyAutoConfigUrl` and `proxyAutoDetect`, and asks the PAC file out of process, about the host alone, for up to 10 seconds | For networks that publish their proxy only in a PAC file. A script from the network never runs in the tool |
| Sends the sign-in to the WinHTTP proxy always, and to `proxyUrl` with `proxyUseDefaultCredentials` | Sends it only with `proxyUseDefaultCredentials`, and never to a proxy that WPAD found | One setting decides whether the computer account's sign-in leaves the device |
| Follows redirects | Returns the 3xx | Each request's proxy is chosen for its host, and plain http is refused |
| Sends plain http to whatever address it is given; only a base address is checked when it is resolved | Refuses plain http, except to this device, in the client itself | The rule holds whatever a caller passes |
| Splits a WinHTTP proxy list on semicolons alone | Splits it on white space too, as WinHTTP allows | It read `a:80 b:80` as one address, and used no proxy |
| Reads `[` and `]` in a bypass entry as a set of characters (`-like`) | Takes them as written | WinHTTP's bypass list has no sets |
| Treats names in the computer's own DNS domain, and its own addresses, as local (.NET's `BypassProxyOnLocal`) | Treats only this device's names, loopback addresses and names without a dot as local | Put the domain on the WinHTTP bypass list, or in a PAC file |
| Reads `network.json` as PowerShell converts values: `1` and `"true"` are true, and `0` and `""` false | Reads a switch only from JSON `true` or `false`, and an address only from a string; any other value takes the default | A value of the wrong type costs only itself, and nothing reads as true that was not written so |
| Uses the defaults silently when `network.json` cannot be read | Uses the shipped copy, with the gate's warning, for an override the gate refuses; reports an Error for the check that needs an override it could not read; and uses the defaults, with the problem noted on every route, only for a shipped copy that is missing or not valid | Says why no proxy was used, and an override held up by a standard user is never swapped for the defaults unseen |
| Words a timeout as .NET words the cancellation | Says the request timed out, and after how long | .NET's words for it name no timeout |
| Returns the body as text | Returns it as bytes | Its callers parse JSON from UTF-8 |

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
4. It runs the machine checks (SU-01 so far), which read config through the config trust gate from the
   data folder it holds (above): it prints `Config override used: <path>` for each administrator's override
   in use, and writes `Warning: Ignoring the config override <name> and using the shipped copy: <reason>` to
   standard error for each one refused, and carries on, as the module warns. For an override it could not
   read it writes `Warning: Could not read the config override <name>, ...`, and the checks that need it are
   Error findings in status.json. Each of those warnings is also Application event 1003 under the
   `EngramicBaseline` source, worded as SecureStore's notices are, so an administrator sees it without the
   task's output.
5. It writes status.json, UTF-8 with a byte order mark, with SecureStore's atomic write. A failed run
   leaves the old status.json, whose age then keeps growing, as in the module.

| Exit code | Meaning |
|---|---|
| 0 | The audit ran and status.json was written. |
| 1 | It failed, or refused to run: not SYSTEM, the mutex could not be taken, or the data folder was refused. |
| 2 | Another audit, or an install, held the mutex for 30 minutes. |

Not ported yet: counting failed runs in last-error.json (only into a data folder that was opened and
checked, as the module does), the report folder and its retention, the log, events 1000 to 1002, and
`excludeCheckIds` from an administrator's config.

The Contracts job runs it as SYSTEM on its runner, in the data folder the installer makes (below).

## The status.json contract

The Intune discovery and detection scripts already deployed in tenants read status.json, schema 1, so its
bytes are a contract. Three kinds of test hold it.

**Golden files.** `tests/Engramic.Baseline.Contracts.Tests/Golden` holds the exact bytes `baseline.exe` writes
for three documents: the scheduled audit as SYSTEM with SU-01 passing, the same with SU-01 failing, and a
reader probe that uses every status, all three frameworks, the hardware block, a report folder and text
beyond ASCII. The tests check that the product writes each one byte for byte and reads it back.
`StatusContract` compares a file with its golden file and says where they differ: the byte order mark, UTF-8,
every key by its exact name, casing and order, the kind and value of every value, the line ends, and then the
bytes, so escaping and indentation cannot drift either. A golden file changes only with the contract, never
to make a test pass. The golden files start with a byte order mark, so the hygiene allowlist names them.

**The Intune scripts.** `tools/contracts/Invoke-IntuneReaders.ps1` runs `intune/Discover-CECompliance.ps1` and
`Detect-CECompliance.ps1` from their files, unchanged, in 64-bit and 32-bit Windows PowerShell 5.1 (System32's
and SysWOW64's), hidden, and returns what each reported as data: the exit code, the output, the discovery JSON
or the detection line split into its parts, and the bitness, version and account each host said it ran as.
Given a file, it copies it into a data folder of its own and points the hosts at it through `ProgramData`,
where both scripts look; elevated, that folder is born locked as the installer makes the data folder, so the
scripts' own trust check passes. With `-MachineDataFolder` they read the device's data folder, as under
Intune. The discovery script starts the scheduled audit when status.json is old or unreadable, so each host
first replaces `Get-ScheduledTask` and `Start-ScheduledTask` with stand-ins that record the attempt and fail,
as they do where the task is missing: a test file never starts a real audit on the machine running it.

The Intune-reader tests run both scripts on the golden documents as Baseline writes them at the time of the
test, since the scripts measure the audit's age from the clock: both hosts must report the same, every value
of the probe must come through, and `CEOSSupported` must follow SU-01. They skip where there is no Windows
PowerShell, such as on Linux.

**Deliberate changes.** The tests change a copy of the probe, never the product: a key renamed, a nested key
renamed, a framework's key renamed, a check identifier's casing changed, a fixed key's casing changed, and the
byte order mark removed. The golden comparison must name each change. The Intune scripts must report
something else, in each host, for every change they can see:

| Change | Why the Intune scripts see it |
|---|---|
| A key renamed (`autoFailCount`, a check's `status`, `ce-v3.3`) | They read those values, and the probe gives each a value they can tell from the one they fall back to. |
| A check identifier's casing changed (`SU-03` to `su-03`) | The discovery script lists the failing checks by their keys, as written. |

PowerShell finds a property whatever its case (the discovery script itself asks for `SchemaVersion` and
`AuditTime`), so a change to the casing of a fixed key such as `autoFailCount` cannot change what the scripts
print. The tests say so, and the golden tests are what guard it, for every other reader of the file. The
same goes for the byte order mark: the scripts read status.json with `-Encoding UTF8`, so removing the mark
doesn't change their output either. The golden tests still guard the mark, which copies of the scripts from
before that change, already in tenants, need.

**End to end, as SYSTEM.** `tools/contracts/Test-StatusContract.ps1`, which the Contracts job runs on its
runner, installs with `intune/Install-CEChecker.ps1` and shows, step by step, that:

1. `scheduled-audit` as SYSTEM refuses a data folder that does not exist, and creates none;
2. the install's data folder is born locked (owned by Administrators, a protected access list of SYSTEM and
   Administrators) and sealed;
3. without the seal, `scheduled-audit` refuses the folder and writes nothing;
4. it writes status.json with a byte order mark, in strict UTF-8, with every key as the golden file spells and
   orders it, owned by Administrators, trusted by the discovery script's own check, and no temporary file left;
5. three more runs replace it atomically: the file ID changes each time, and a reader polling throughout sees
   only the old file or the new one, whole, and never no file;
6. to 8. the Intune scripts, in both hosts, as SYSTEM and as the elevated administrator, report the same for it
   as for the status.json that the installed module then writes for SU-01 in the same folder as SYSTEM
   (`tools/contracts/Write-ModuleStatus.ps1`), apart from the tool version, which the ledger (below) ignores
   (`tools/contracts/Compare-IntuneReaders.ps1`);
9. with Users given write access to the data folder, `scheduled-audit` refuses it and leaves status.json alone;
10. with a junction in the data folder's place, leading to an empty folder only SYSTEM and Administrators can
    change, `scheduled-audit` opens the junction as itself, refuses it and writes nothing where it leads.

Each step that takes something away puts it back, and the data folder is left as the install made it.

It changes the machine, so it refuses to run unless elevated, and where the tool is installed or its data
folder exists unless given `-Force`. Runs as SYSTEM go through `tools/ci/Invoke-AsSystem.ps1`: a temporary
scheduled task, as the deployment rehearsal uses, with its wrapper and output in a folder only SYSTEM and
Administrators can change.

Without elevation, the golden and Intune-reader tests run as they are, and the reader comparison runs on
files you make (the redirect from cmd):

```
dotnet test --project tests/Engramic.Baseline.Contracts.Tests -c Release
artifacts\bin\Engramic.Baseline.Cli\release\baseline.exe audit --id SU-01 --json status --shipped-config > baseline.json
powershell -ExecutionPolicy Bypass -File tools\contracts\Write-ModuleStatus.ps1 -Id SU-01 -Path module.json -DataRoot module-data
powershell -ExecutionPolicy Bypass -File tools\contracts\Invoke-IntuneReaders.ps1 -StatusPath baseline.json -ResultPath readers-baseline.json
powershell -ExecutionPolicy Bypass -File tools\contracts\Invoke-IntuneReaders.ps1 -StatusPath module.json -ResultPath readers-module.json
powershell -ExecutionPolicy Bypass -File tools\contracts\Compare-IntuneReaders.ps1 -ModuleResultPath readers-module.json -BaselineResultPath readers-baseline.json
```

## Comparing with the PowerShell module

`tools/parity/Compare-Parity.ps1` runs the same checks in the untouched module, out of process in Windows
PowerShell 5.1, and in `baseline.exe` on this device, as the account that runs it, then compares: first the
device context each tool saw (computer, account, elevation, Windows), since one difference there explains many
after it; then every field of every finding and their order, every value of status.json and its byte order
mark, and every value the Intune discovery and detection scripts report for each file in both hosts
(`tools/contracts/Invoke-IntuneReaders.ps1`). Both tools read only the shipped config: the module is given an empty
data folder, and `baseline.exe audit` is given `--shipped-config`, so that an elevated run does not read the
overrides in the runner's data folder.

Every accepted difference is in the ledger, `tests/parity/divergences.json`. An entry names the path it covers
(and everything under it, with `*` for one part of a name, such as the host in `discovery[*]`); its kind,
`ignored` for a value that differs by design and is not compared, such as the tool version and the audit time,
or `explained` for a difference accepted until more is ported, such as the hardware block `baseline.exe` does
not write yet; the reason; and the scope, the contexts (`standard user`, `elevated administrator`, `SYSTEM`)
and checks (identifiers, or `*`) it applies to. The ledger is checked when it is read, and one that cannot be
read stops the run. Anything else that differs is unexplained, and the gate is zero unexplained differences:
the script exits 1 on any. An explained entry that explained nothing in a run is listed, to take off once no
context or check needs it. `-ResultPath` writes every value compared, with its result and ledger entry, and
the verdict, as JSON.

Run it as the account whose audit you want to compare: a standard user, an elevated administrator or SYSTEM.
The Parity job runs it for SU-01 as the elevated administrator and, through a temporary scheduled task, as
SYSTEM.

```
dotnet build Baseline.slnx -c Release
powershell -NoProfile -ExecutionPolicy Bypass -File tools/parity/Compare-Parity.ps1 -Id SU-01
```

## Signing baseline.exe

A release of `baseline.exe` is the published folder, self-contained: the launcher and the assemblies this
repository builds, and beside them the .NET runtime and the package assemblies. Every PE file in it must carry a
valid, timestamped Authenticode signature, in the file itself: ours on what this repository built, Microsoft's
on everything else, exactly as Microsoft signed it. Nothing of Microsoft's is signed again.

**What is ours.** The `.deps.json` that `dotnet publish` writes lists every library with its kind. Ours are the
assets of the libraries of kind `project`, and the launcher, `baseline.exe` beside `baseline.deps.json`
(`Get-ReleaseOwnFile` in `tools/Release.psm1`). The runtime pack's files and the package assemblies are someone
else's. A folder without a `.deps.json`, or one that names a file which is not there or lies outside the folder,
is refused, so nothing is signed or judged on a guess.

**Package assemblies stay as their publisher signed them.** ReadyToRun compiles an assembly into a new file, which
drops its signature, so each package assembly is left out of it with `PublishReadyToRunExclude` in the command
line's project (`System.CommandLine.dll` so far). A package assembly that loses its signature some other way fails
the check below, which says why.

**Signing.** `tools\Sign-Release.ps1 -IncludeExtensions .exe, .dll` signs only our files: with signtool and the
Artifact Signing dlib (`-AzureMetadata`), or with `Set-AuthenticodeSignature` and a certificate (`-Thumbprint`,
`-PfxPath`) for testing. Every signature is SHA256 and timestamped, and a PE signature without a timestamp fails.
A PE file chosen for signing that already carries any signature is refused, not signed over, whatever the
manifest says.

**The check.** `tools\Test-ReleaseSignatures.ps1` looks at every PE file under a folder, `.exe` and `.dll` and any
other file with a PE header, and fails, listing each problem file by file, unless:

- each of ours is signed by our publisher (`-Publisher`, the organisation in the certificate, since Artifact
  Signing issues a new certificate every few days) or certificate (`-Thumbprint`), verifies as Valid and is
  timestamped. `-AllowUntrustedChain` also accepts, on ours alone, a chain that ends in a root the machine does not
  trust, as a test certificate or a test profile gives;
- every other PE file is signed by a certificate issued to Microsoft Corporation by a Microsoft authority, verifies
  as Valid and is timestamped, whatever the switches say.

With `-Unsigned` it checks a folder before signing: none of ours may be signed yet, and every other PE file must
already carry Microsoft's signature. The "Build and test (.NET)" job runs that on what it publishes, so a package
assembly that lost its signature fails the pull request, not the release.

**A release.** `tools\New-SignedRelease.ps1 -DotNet -AzureMetadata <metadata>` first checks the signing login:
unless the metadata carries an `AccessToken` or excludes `AzureCliCredential`, that is the Azure CLI's, so `az`
must be on the window's PATH and signed in (`az login`), or it stops in seconds instead of after the build. It then
runs the pre-flight, publishes
`baseline.exe` from the committed tree with the SDK in `global.json`, runs the check with `-Unsigned`, signs ours,
runs the check again with the publisher (`-Publisher`, Engramic Ltd by default), runs the signed
`baseline.exe --version`, and writes the zip, its checksum, release notes and `release.json` to
`build\release-dotnet`. It publishes nothing, and marks a build on an untrusted chain DO NOT PUBLISH. Without
`-DotNet` it cuts the PowerShell release as before. Later, CI is to publish and attest the unsigned folder, and this
script to verify that attestation before it signs anything; until then the folder is published on the machine that
signs it.

**The tag.** A `v*` tag must be `v` and the version of what it releases, exactly: the module's `ModuleVersion`, or
`VersionPrefix` and `VersionSuffix` together (`v1.0.0-alpha.0`). The Release workflow checks it with
`tools/Test-ReleaseTag.ps1`. A tag for the module is judged as before, whatever `Directory.Build.props` holds, and
where there is none, only the module's version counts.

**The sign-test sandbox.** `tools\sandbox\New-SandboxRun.ps1 -Environment sign-test` proves all of this on a clean
Windows with a throwaway self-signed certificate made inside the sandbox: it installs the SDK in `global.json`,
publishes `baseline.exe`, checks the unsigned folder, signs ours and shows that no runtime or package file changed
and that a file carrying Microsoft's signature is refused, runs the check, catches a byte changed in a signed file,
and runs `baseline.exe --version` and `baseline.exe audit --id SU-01` from the signed build. When
`build\release-dotnet` holds a build signed by `New-SignedRelease.ps1 -DotNet`, it runs the same check and the
same slice on that build too, as it was signed.

## CI

`.github/workflows/dotnet.yml` runs on every pull request and on pushes to `main` and `feat/dotnet-port`:

| Job | What it does |
|---|---|
| Build and test (.NET) | On Windows: the locked restore, the build with warnings as errors, the tests, `baseline.exe` published and run with `--version`, the signatures of the published files checked before signing (`Test-ReleaseSignatures.ps1 -Unsigned`), and the AOT canary published and run, which runs detection and then times itself against the JIT build of it that the build step left in `artifacts/bin`. |
| Unit tests (Linux) | Builds and tests the portable projects in `Baseline.Portable.slnf`. |
| Contracts | On Windows: the contract tests (the golden files, and the Intune scripts in both hosts with the deliberate changes), then `baseline.exe` published self-contained under Program Files and `tools/contracts/Test-StatusContract.ps1`: the install, `scheduled-audit` as SYSTEM, and the Intune scripts on its status.json and the module's, as SYSTEM and as administrator. It uploads what its steps wrote only when it fails. |
| Parity | On Windows: `baseline.exe` published the same way, and `Compare-Parity.ps1` for SU-01 as the elevated administrator and as SYSTEM, which fails on any difference the ledger does not explain. It uploads both comparisons only when it fails. |
| Security | On Windows: the attack suite (`Suite=Security`) with a throwaway standard user as the attacker (`tools/ci/Invoke-SecurityTests.ps1`), as the elevated administrator and, through `tools/ci/Invoke-AsSystem.ps1`, as SYSTEM. It runs the built test assembly directly, since `dotnet test` run as SYSTEM took the project for a VSTest one, so there is no hang dump; the SYSTEM run's task has a time limit, and a run in which no test ran fails. It uploads the results only when it fails. |
| Tests as SYSTEM | On Windows: the Windows tests built, and the explicit ones with the trait `Context=System` run as SYSTEM through `tools/ci/Test-AsSystem.ps1`, which counts a skip as a failure and fails unless at least five ran and every one passed: the service client's proxies from `network.json`, the WinHTTP proxy netsh sets, a named PAC file and WPAD, the sign-in sent only where it is allowed, and plain http refused. It keeps the results when it fails. |
| Hygiene | Every tracked text file is ASCII, and every URL host in `src/`, `tests/`, `tools/` and `docs/`, every `engramic-ai/` repository and every `engramic.ai` name anywhere is on `tools/hygiene/public-allowlist.txt`. |

The PowerShell module's jobs stay in `ci.yml`.
