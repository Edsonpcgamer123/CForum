# Static analysis of the CForum Windows download

Analysis date: 2026-09-14 UTC

## Verdict

**Do not execute this download.** The archive is not the Windows installer described
by CForum's README. It is a batch-file launcher, a LuaJIT interpreter, and a heavily
obfuscated Lua program. During safe, instrumented evaluation, the Lua program decoded
Windows FFI declarations for process-memory allocation, direct inspection of loaded
modules and PE export tables, screen capture, elevation detection, temporary-file
access, console hiding, and message boxes. Those capabilities are unrelated to running
a Cloudflare forum locally and are strongly consistent with a concealed loader or
information-stealing program.

This assessment did **not** execute the supplied Windows binary or allow the Lua
payload access to the filesystem, processes, or network. Because the payload is
deliberately obfuscated and its later native calls were blocked, this report does not
claim to identify its final second-stage payload or network infrastructure.

## Sample identification

Downloaded from:

`https://github.com/Edsonpcgamer123/CForum/raw/refs/heads/main/functions/Forum_C_v3.7-beta.3.zip`

| File | Size (bytes) | SHA-256 |
| --- | ---: | --- |
| `Forum_C_v3.7-beta.3.zip` | 584,667 | `0d36790958ed56584b28f664306d4536341d9f47fc2aea109e11aaae8e497ae7` |
| `Application.bat` | 23 | `a91b3308a7e9aa9fa660c72d27f226d8f50bfac2629f79a828fbecff323c0fe0` |
| `buff.log` | 308,924 | `3989cdf958d258244f3a72bac594214112ffe1008d4d81233a5911482dd302ca` |
| `load.exe` | 872,448 | `167b166e26dd44f580a00f2c879089c5362eff5120ac88e0701b11b1eb320ca9` |

The ZIP entries all carry the same DOS timestamp, `2026-03-14 05:24:28`.

## What is actually in the archive

`Application.bat` contains only the following command (with no trailing newline):

```bat
start load.exe buff.log
```

In other words, this is not an installer. The batch file launches `load.exe` and gives
the misleadingly named `buff.log` to it as a program.

`load.exe` is an unsigned 64-bit Windows GUI PE. Its own strings identify it as
LuaJIT 2.1.0-beta3, and its PE export name is `luajit.exe`. Its imports are almost
entirely ordinary runtime functions from `KERNEL32.dll`; this does not make the bundle
safe, because the suspicious behavior resides in the Lua input and uses LuaJIT FFI to
resolve and invoke native APIs dynamically.

`buff.log` is plain-text Lua rather than a log. It is compressed into a single line,
uses meaningless identifiers, opaque arithmetic, encrypted byte strings, and a large
flattened state machine. This level of obfuscation prevents a reader from auditing the
program that the README asks them to run.

## Behavior exposed by instrumented decoding

The Lua was evaluated with process creation, file access, module loading, and network
access replaced by logging stubs. Before reaching the blocked native-library access,
it decoded and submitted an FFI declaration block containing:

* `VirtualAlloc` and `VirtualFree`, commonly used by in-memory loaders;
* definitions for the PEB, loader entries, DOS/NT PE headers, data directories, and
  export directories, sufficient to walk loaded modules and resolve API addresses
  without normal imports;
* `GetSystemMetrics`, `GetDC`, `CreateCompatibleDC`, `CreateDIBSection`, `BitBlt`, and
  related GDI functions, which together implement desktop screenshot capture;
* `GetComputerNameW`, `GetTempPathW`, `IsWow64Process`, and Windows version checks,
  which collect host/environment information;
* `GetCurrentProcess` and a `TOKEN_ELEVATION` structure, indicating privilege/elevation
  inspection;
* `GetConsoleWindow` and `ShowWindow` with `SW_HIDE`, allowing its console to be hidden;
* `Sleep`, wide/multibyte conversion, handle management, and `MessageBoxW`.

It also requested the LuaJIT `ffi` and `bit` modules and attempted to load
`lua51.dll`. Direct PE-export parsing combined with an intentionally tiny static import
table is a notable evasion technique: additional APIs and network behavior can be
resolved at runtime without appearing in `load.exe`'s import table.

## Repository-level warning signs

At the time of analysis, GitHub's API described the repository as a TypeScript
Cloudflare Workers/Pages forum. The README instead directed Windows users to this ZIP,
called it an installer named like `CForum-Setup-[version].exe`, and instructed users to
approve a Windows permission prompt. The archive contains neither that filename nor an
installer UI. The README also claimed the local app would open a browser, while the
decoded program contains screenshot and low-level process-memory functionality with no
credible need in a forum application.

The repository was created on 2026-03-11 according to GitHub's API. Commit
`0033a0c9cd41c0cb7be5265ad079983931f79be3`, dated 2026-03-14, added the ZIP under
`functions/`; the immediately preceding commit removed a GitHub Actions deployment
workflow and rewrote the README. Issues were disabled when checked. These facts do not
prove malware alone, but they reinforce the technical findings.

## Recommended response

1. Do not run `Application.bat`, `load.exe`, or `buff.log`, including in Windows
   Sandbox on a machine containing real credentials.
2. Report the repository and downloadable file to GitHub as suspected malware, quoting
   the hashes above and the mismatch between the README and archive contents.
3. Submit the hashes or sample to the security product used by your organization. A
   public multi-engine sandbox may help identify the final family, but uploading a
   private sample would disclose it to third parties; this sample is already public.
4. If it has already been run, disconnect the host from the network, preserve volatile
   evidence if incident-response support is available, rotate credentials from a
   separate known-clean device, revoke browser sessions/tokens, and rebuild the host
   from trusted media rather than assuming deletion of the three files is sufficient.
