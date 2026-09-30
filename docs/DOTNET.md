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
| `src/Engramic.Baseline.Platform` | The interfaces and records of the primitives (registry, files, processes, tokens, HTTP and so on), the trust rules of the data folder, and the rules that choose a service request's proxy. |
| `src/Engramic.Baseline.Engine` | The check and fix contracts, the runner, the framework rollups, changesets and undo. |
| `src/Engramic.Baseline.Controls` | The checks, the fixes, the readers that interpret what the primitives return, and the shipped config. |
| `src/Engramic.Baseline.Windows` | The Windows primitives, calling Win32 through code that CsWin32 generates from `NativeMethods.txt`, including SecureStore, the audit mutex and the service client. |
| `src/Engramic.Baseline.Cli` | `baseline.exe`, the command line. |
| `tests/Engramic.Baseline.*.Tests` | xUnit v3 tests: one project for each library, and one for the command line. |
| `tests/Engramic.Baseline.Contracts.Tests` | The status.json contract: golden files of its bytes, and the Intune scripts run on it (below). |
| `tests/Engramic.Baseline.Invariants.Tests` | Tests of the repository's own rules, described below. |
| `tests/Engramic.Baseline.Testing` | Fakes and recorded responses that the tests share. |
| `tests/Engramic.Baseline.Testing.Windows` | Windows fixtures: folders under the temp folder with the security descriptors a test gives, junctions, hard links and other reparse points, and mutexes of the tests' own. |
| `tests/AotCanary` | Compiles the AOT-clean libraries with Native AOT and calls into each one. |
| `tools/parity` | Compares the ported checks with the PowerShell module on a device (below). |
| `tests/parity/divergences.json` | The ledger of accepted differences between the module and `baseline.exe`, with the reason and scope of each. |
| `tools/contracts` | Runs the unchanged Intune scripts on a status.json, and proves the contract end to end as SYSTEM in CI (below). |
| `tools/ci` | Helpers for CI runners only, such as running a program, or the SYSTEM tests of a test assembly, as SYSTEM through a temporary scheduled task. |
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
| `HttpClient`, `HttpClientHandler`, `SocketsHttpHandler` | A client made anywhere else would use .NET's default proxy, which follows environment variables and, as SYSTEM, SYSTEM's own Internet settings | The service client (`IServiceClient`) |
| `Process.Start`, `ProcessStartInfo` | Tools must be resolved from System32 and signature-checked, never found through PATH | The trusted process runner |
| Reading environment variables | Whoever starts the process sets them | A known folder or config |
| `DateTime.Now`, `UtcNow`, `Today`, `DateTimeOffset.Now`, `UtcNow` | Tests must be able to set the time | `TimeProvider` |
| Loading an assembly from a path | Nothing runs that did not ship with the product | - |
| `NativeLibrary`, `Marshal.GetDelegateForFunctionPointer` | Native code is reached only through CsWin32 (below) | A function in `NativeMethods.txt` |
| Reflection-based `JsonSerializer` overloads | Not AOT-safe | A `JsonTypeInfo` from a source-generated `JsonSerializerContext` |

**Exemptions.** A few audited classes, added as the port goes on, do these things safely: SecureStore,
ProfileReader, the registry primitive, the trusted process runner and the service client. Only the files they
live in may use a banned API, and only like this:

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
reads another file adds it there as an `EmbeddedResource`. Code reads the files through `IConfigFiles`, the seam
where administrators' overrides, which replace a shipped file whole, will come in through SecureStore and its trust
checks, in front of the shipped copy.

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
registry key, a scheduled task or the product's mutex: folders are made under the temp folder with unique
names and deleted by that exact path, the seal is read from a registry in memory, and mutexes have names
of the tests' own.

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

**Settings.** `NetworkSettings`, in Engine, reads `network.json` through `IConfigFiles`: the shipped copy today, and an
administrator's override once the config trust gate lands. A file that is missing or not valid gives the defaults,
with the problem noted on every route.

**Tests.** `ProxyChooser` is covered branch by branch with a fake of what Windows says, in the Platform tests, which
run on Linux too. The Windows tests send real requests to servers on the loopback address: a site; a proxy that
answers `CONNECT` and asks for NTLM, to see the sign-in sent only when it is allowed; and the host of PAC files, which
the real WinHTTP service fetches. They only read the machine's own settings. Five explicit tests run as SYSTEM in the
Tests as SYSTEM job: `network.json`'s proxy; the WinHTTP proxy set with netsh, and its bypass list; a named PAC file;
a PAC file that WPAD finds through names added to the hosts file and a server on port 80; and plain http refused.

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
| Uses the defaults silently when `network.json` cannot be read | Uses the defaults, with the problem noted on every route | Says why no proxy was used |
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
| The byte order mark removed | They read status.json without naming an encoding, so Windows PowerShell 5.1 reads a file without the mark in the ANSI code page, and the probe's `toolVersion`, which is not ASCII, arrives garbled. |

PowerShell finds a property whatever its case (the discovery script itself asks for `SchemaVersion` and
`AuditTime`), so a change to the casing of a fixed key such as `autoFailCount` cannot change what the scripts
print. The tests say so, and the golden tests are what guard it, for every other reader of the file. If the
scripts ever name UTF-8 when they read status.json, removing the mark stops changing their output and the
tests say that too; the golden tests still guard the mark, which the scripts already in tenants need.

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
artifacts\bin\Engramic.Baseline.Cli\release\baseline.exe audit --id SU-01 --json status > baseline.json
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
(`tools/contracts/Invoke-IntuneReaders.ps1`).

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

**A release.** `tools\New-SignedRelease.ps1 -DotNet -AzureMetadata <metadata>` runs the pre-flight, publishes
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
| Build and test (.NET) | On Windows: the locked restore, the build with warnings as errors, the tests, `baseline.exe` published and run with `--version`, the signatures of the published files checked before signing (`Test-ReleaseSignatures.ps1 -Unsigned`), and the AOT canary published and run. |
| Unit tests (Linux) | Builds and tests the portable projects in `Baseline.Portable.slnf`. |
| Contracts | On Windows: the contract tests (the golden files, and the Intune scripts in both hosts with the deliberate changes), then `baseline.exe` published self-contained under Program Files and `tools/contracts/Test-StatusContract.ps1`: the install, `scheduled-audit` as SYSTEM, and the Intune scripts on its status.json and the module's, as SYSTEM and as administrator. It uploads what its steps wrote only when it fails. |
| Parity | On Windows: `baseline.exe` published the same way, and `Compare-Parity.ps1` for SU-01 as the elevated administrator and as SYSTEM, which fails on any difference the ledger does not explain. It uploads both comparisons only when it fails. |
| Tests as SYSTEM | On Windows: the Windows tests built, and the explicit ones with the trait `Context=System` run as SYSTEM through `tools/ci/Test-AsSystem.ps1`, which counts a skip as a failure and fails unless at least five ran and every one passed: the service client's proxies from `network.json`, the WinHTTP proxy netsh sets, a named PAC file and WPAD, the sign-in sent only where it is allowed, and plain http refused. It keeps the results when it fails. |
| Hygiene | Every tracked text file is ASCII, and every URL host in `src/`, `tests/`, `tools/` and `docs/`, every `engramic-ai/` repository and every `engramic.ai` name anywhere is on `tools/hygiene/public-allowlist.txt`. |

The PowerShell module's jobs stay in `ci.yml`.
