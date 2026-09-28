Read `.claude/CLAUDE.local.md` first if it exists (machine-specific paths, never committed).

# Quokka

- Binary exporter: IDA Pro / Ghidra / Binary Ninja -> protobuf `.quokka` file -> Python analysis without the disassembler
- **Version** 1.0.0 (unreleased; last tag v0.6.2). Bump together: `CMakeLists.txt` (`project(... VERSION)`), `bindings/python/quokka/version.py`, `ghidra_extension/build.gradle` (`quokkaVersion`), `binaryninja_extension/bn_quokka/version.py` + `plugin.json`, `ida-plugin.json`
- **PyPI** `quokka-project`, imported as `quokka`
- **Roadmap / todos**: `docs/roadmap.md` (single source; add new todos there, with an id)

# Components

| Path | What | Agent notes |
|---|---|---|
| `proto/quokka.proto` | Wire format, stable contract | `proto/CLAUDE.md` |
| `src/`, `include/quokka/` | IDA plugin (C++20) | `src/CLAUDE.md` |
| `ghidra_extension/` | Ghidra extension (Java) | `ghidra_extension/CLAUDE.md`, `README.md` |
| `binaryninja_extension/` | Binary Ninja plugin + headless script (Python) | `binaryninja_extension/README.md` |
| `bindings/python/` | Python library + `quokka-cli` / `quokka-apply` | `bindings/python/CLAUDE.md` |
| `tests/` | C++ + Python tests, dataset | `tests/CLAUDE.md`, `tests/README.md` |
| `docs/` | MkDocs user site (`pip install -e '.[doc]' && mkdocs serve`) | user-facing contract |
| `third_party/` | `ida-sdk` submodule (IDA >= 9.2), `ghidra` submodule (its tag = supported Ghidra version) | |
| `scripts/fetch_ghidra.sh` | Download the Ghidra release matching the submodule tag | |
| `cmake/`, `ci/`, `.github/workflows/` | Build modules, Dockerfiles, CI | |

# Conventions

- ASCII only in source files (any language)
- Protobuf changes follow `proto/CLAUDE.md`; a new exported artifact goes proto -> every exporter (IDA, Ghidra, Binary Ninja) -> Python bindings
- Python work: `source .venv/bin/activate`
- Every fix/feature ships with tests; run exporter integration tests when the export pipeline or schema changes
- Document every change: the relevant CLAUDE.md (agent facts) and `docs/` (user-facing API/contract)

# Commits

- Imperative subject, < 50 chars, no trailing period; body only when the why is not obvious (wrap 72)
- Prefix with 1-2 component tags, back to back: `[ida]` `[ghidra]` `[python]` `[proto]` `[tests]` `[docs]` `[cmake]` (e.g. `[ida][tests] ...`); omit tags when > 2 components
- State the intent, never restate the diff; prefer a single line
- Example: `[ghidra] Fix null pointer in function export`

# Debugging exporter bugs

- Debug build with symbols (`-DCMAKE_BUILD_TYPE=Debug`)
- Fresh empty folder: no leftover database/project or old `.quokka` (stale artifacts mask root causes)
- Still failing -> attach `gdb` / `lldb`

# Writing CLAUDE.md files

- This root file stays high-level (what every prompt needs, no component internals); add a fact only if it saves real re-derivation time
- One component per file; cross-link, never duplicate. How-to for humans lives in READMEs/`docs/`; CLAUDE.md holds rules, invariants, gotchas, pointers
- Bullets and tables, no prose; stable facts only (no test counts, no line numbers, no status)
- Verify claims against the code before writing them
