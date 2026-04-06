# Run Your First Scan

## How it works

1. Open any `.py`, `.js`, or `.ts` file
2. Run **VibeSec: Scan Current File** from the command palette (`Ctrl+Shift+P`)
3. Findings appear in two places:
   - **Inline squiggles** directly on the vulnerable lines
   - **VibeSec panel** (shield icon in the left sidebar) — grouped by file, sorted by severity

## Try the sample file

The repo includes an intentionally insecure Python file:

```
test-samples/insecure.py
```

Open it and run a scan. You should see findings for:
- Command injection (`subprocess`)
- Weak MD5 hashing
- Hardcoded API key
- SQL injection

## Reading the results

Each finding shows:
- **Severity icon** — red circle-X (error), yellow triangle (warning), blue circle-i (info)
- **Category** — e.g. `COMMAND-INJECTION`, `WEAK-HASH`
- **Line number**
- **Hover tooltip** — full rule ID, message, and code snippet

Click any finding to jump directly to that line in the editor.
