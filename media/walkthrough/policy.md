# Customize with a Policy File

Drop a `.vibesec.yaml` file in your project root to control how VibeSec scans.

Use **VibeSec: Open Policy File** to create one with a starter template, or create it manually:

```yaml
# Which rule packs to use
presets:
  - vibesec:default        # Bundled OWASP rules — works offline

# Minimum severity to report
severity:
  minSeverity: warning     # error | warning | info

# Exclude paths from scanning
files:
  exclude:
    - "**/node_modules/**"
    - "**/*.test.ts"

# Add your own inline rules
rules:
  - id: my-custom-rule
    message: "Don't use eval()"
    severity: ERROR
    languages: [javascript]
    pattern: eval(...)
```

## Key options

| Option | What it does |
|--------|-------------|
| `presets` | Rule packs to run. `vibesec:default` is the bundled OWASP set (offline). |
| `severity.minSeverity` | Filter out findings below this level. |
| `files.exclude` | Glob patterns to skip (node_modules, test files, etc.). |
| `rules` | Inline Semgrep rules for team-specific checks. |

After editing, run **VibeSec: Reload Policy** to pick up changes without restarting VS Code.
