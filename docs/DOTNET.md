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
| `src/Engramic.Baseline.Platform` | The interfaces and records of the primitives: registry, files, processes, tokens and so on. |
| `src/Engramic.Baseline.Engine` | The check and fix contracts, the runner, the framework rollups, changesets and undo. |
| `src/Engramic.Baseline.Controls` | The checks, the fixes, and the readers that interpret what the primitives return. |
| `src/Engramic.Baseline.Windows` | The Windows primitives, calling Win32 through code that CsWin32 generates from `NativeMethods.txt`. |
| `src/Engramic.Baseline.Cli` | `baseline.exe`, the command line. |
| `tests/Engramic.Baseline.*.Tests` | xUnit v3 tests: one project for each library. |
| `tests/Engramic.Baseline.Invariants.Tests` | Tests of the repository's own rules, described below. |
| `tests/Engramic.Baseline.Testing` | Fakes and recorded responses that the tests share. |
| `tests/AotCanary` | Compiles the AOT-clean libraries with Native AOT and calls into each one. |

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

**Packages.** Add or change a version in `Directory.Packages.props`, run `dotnet restore Baseline.slnx`,
and commit the `packages.lock.json` files it changes; CI restores in locked mode and fails if a lock
file is out of date. Some implicit packages (the trimming and AOT tools) follow the SDK version, so
`global.json` and the lock files move together: to take a new patch SDK, install it, change the version
in `global.json`, run `dotnet restore Baseline.slnx --force-evaluate` and commit all of it in one change.
CI installs exactly the SDK that `global.json` names, never the newest patch of its feature band, so it
keeps passing when a new patch ships and moves only when `global.json` does. If a restore changes lock
files you did not mean to change, check that `dotnet --version` matches `global.json`.
CsWin32 is still 0.x and pinned to an exact version.

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

The hygiene check needs a clone that git can read:

```
pwsh -NoProfile -File tools/hygiene/Test-Hygiene.ps1
```

## CI

`.github/workflows/dotnet.yml` runs on every pull request and on pushes to `main` and `feat/dotnet-port`:

| Job | What it does |
|---|---|
| Build and test (.NET) | On Windows: the locked restore, the build with warnings as errors, the tests, `baseline.exe` published and run with `--version`, and the AOT canary published and run. |
| Unit tests (Linux) | Builds and tests the portable projects in `Baseline.Portable.slnf`. |
| Hygiene | Every tracked text file is ASCII, and every URL host in `src/`, `tests/`, `tools/` and `docs/`, every `engramic-ai/` repository and every `engramic.ai` name anywhere is on `tools/hygiene/public-allowlist.txt`. |

The PowerShell module's jobs stay in `ci.yml`.
