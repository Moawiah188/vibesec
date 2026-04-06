# Install Semgrep

VibeSec runs Semgrep locally on your machine — no cloud, no account required.

## Install

**macOS / Linux / Windows:**
```bash
pip install semgrep
```

**macOS (Homebrew):**
```bash
brew install semgrep
```

## Verify

```bash
semgrep --version
```

You should see something like `1.x.x`. If the command isn't found, make sure Python's `Scripts` folder is on your `PATH`.

## Custom binary location?

If Semgrep is installed somewhere non-standard, set its path in VS Code settings:

**Settings → VibeSec → Semgrep Path**

or open `settings.json` and add:
```json
"vibesec.semgrepPath": "/path/to/semgrep"
```
