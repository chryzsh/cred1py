# AGENTS.md

## Repository Purpose
- `cred1py` is an SCCM CRED-1 tooling repo.
- Main entrypoint is `main.py`.

## Operating Rules For Agents
- Make focused, minimal changes tied to the requested task.
- Do not commit generated loot or secrets (`loot/`, extracted credentials, PFX files, raw policy blobs).
- Treat all credential-like output as sensitive.
- Prefer extending existing flows over adding one-off scripts unless explicitly requested.

## Required Workflow
1. Inspect current status with `git status --short`.
2. Implement the requested change.
3. Run lightweight verification relevant to changed files (at minimum `python3 -m py_compile` for touched Python files).
4. Review diff for unintended edits.
5. **Commit each change you make** with a clear commit message before moving to the next change.
6. Push commits to the active branch unless the user says not to.

## CLI Structure Notes
- `attack`: PXE/SOCKS attack path.
- `decrypt`: local `.boot.var` decryption.
- `loot`: extract media variables/PFX from decrypted XML.
- `policies`: remote policy retrieval from MP, supports `--fallback-local`.
- `policies-local`: local `.raw` policy processing and credential extraction.

## Documentation Notes
- Keep README usage examples in sync with CLI behavior.
- Prefer `variables.xml` as policy mode input when documenting commands.
