import * as fs from "fs";
import * as path from "path";
import * as vscode from "vscode";
import { logBus, LogEvent } from "./logBus";

// LogStore — disk persistence for the log bus.
//
// Format: JSON Lines (one event per line) under
//   <globalStorageUri>/logs/vibesec.log
//
// Rotation: when the active file passes ROTATE_BYTES we rename it to
//   vibesec.log.1 (overwriting any previous .1) so disk usage stays bounded
//   at ~2× ROTATE_BYTES. We do NOT keep more than one rotated file in v1 —
//   the design's Logs page reads the in-memory ring buffer plus the most
//   recent on-disk tail, which is enough for the current use case.
//
// The store also tees every event to a vscode.OutputChannel so users can
// inspect raw logs from the standard Output panel (Help → Toggle Output → "VibeSec").
//
// On extension activation we tail-load the active file into the bus's ring
// buffer so the first time the user opens the Control Center after a reload
// they still see their last session's events.

const ROTATE_BYTES = 2 * 1024 * 1024; // 2 MB
const TAIL_REPLAY_LIMIT = 1000;       // events restored into ring buffer on activation

export class LogStore implements vscode.Disposable {
  private readonly logsDir: string;
  private readonly logFile: string;
  private readonly rotatedFile: string;
  private readonly outputChannel: vscode.OutputChannel;
  private readonly subs: vscode.Disposable[] = [];
  private unsubscribeBus: (() => void) | undefined;

  constructor(context: vscode.ExtensionContext) {
    this.logsDir     = path.join(context.globalStorageUri.fsPath, "logs");
    this.logFile     = path.join(this.logsDir, "vibesec.log");
    this.rotatedFile = path.join(this.logsDir, "vibesec.log.1");

    this.outputChannel = vscode.window.createOutputChannel("VibeSec");
    this.subs.push(this.outputChannel);

    this.ensureDir();
    this.tailLoadIntoRing();

    this.unsubscribeBus = logBus.subscribe((event) => {
      // Tee to OutputChannel — humans read this when they don't want the
      // structured Logs page.
      this.outputChannel.appendLine(formatForChannel(event));
      // Persist to disk. Failures are intentionally silent because the log
      // pipe must never break the scanner — but we surface a one-time warning
      // via the OutputChannel so power users notice.
      try {
        this.appendToDisk(event);
      } catch (err) {
        this.outputChannel.appendLine(
          `[VibeSec] log persistence failed: ${err instanceof Error ? err.message : String(err)}`,
        );
        // Stop trying after the first failure so we don't spam the channel
        // every single event.
        if (this.unsubscribeBus) { this.unsubscribeBus(); this.unsubscribeBus = undefined; }
      }
    });
  }

  /** Wipe the on-disk log + the ring buffer. Used by the "Clear logs" button. */
  async clear(): Promise<void> {
    logBus.clearRing();
    try { if (fs.existsSync(this.logFile))     { await fs.promises.unlink(this.logFile); } }
    catch { /* best-effort */ }
    try { if (fs.existsSync(this.rotatedFile)) { await fs.promises.unlink(this.rotatedFile); } }
    catch { /* best-effort */ }
  }

  dispose(): void {
    if (this.unsubscribeBus) { this.unsubscribeBus(); this.unsubscribeBus = undefined; }
    while (this.subs.length > 0) { this.subs.pop()?.dispose(); }
  }

  // ── Internals ─────────────────────────────────────────────────────────────

  private ensureDir(): void {
    try {
      fs.mkdirSync(this.logsDir, { recursive: true });
    } catch {
      // Caller will see write errors when appending. Nothing useful to do here.
    }
  }

  /**
   * Tail the most recent N lines of the active log file (fallback to
   * vibesec.log.1 if the active file doesn't exist yet) and seed the ring
   * buffer with them. Best-effort — bad lines are silently dropped, missing
   * files are no-ops.
   */
  private tailLoadIntoRing(): void {
    const sources = [this.rotatedFile, this.logFile].filter((p) => {
      try { return fs.existsSync(p); } catch { return false; }
    });
    if (sources.length === 0) { return; }

    const events: LogEvent[] = [];
    for (const src of sources) {
      let content: string;
      try { content = fs.readFileSync(src, "utf-8"); }
      catch { continue; }
      for (const line of content.split(/\r?\n/)) {
        if (line.trim() === "") { continue; }
        try {
          const parsed = JSON.parse(line) as LogEvent;
          if (isValidEvent(parsed)) { events.push(parsed); }
        } catch { /* skip malformed line */ }
      }
    }
    if (events.length === 0) { return; }
    // Keep only the freshest TAIL_REPLAY_LIMIT to bound replay cost.
    const trimmed = events.slice(-TAIL_REPLAY_LIMIT);
    logBus.replaceRing(trimmed);
  }

  private appendToDisk(event: LogEvent): void {
    // Rotate first if we're about to push over the cap. statSync throws when
    // the file doesn't exist yet — that's fine, we'll create it on append.
    let size = 0;
    try { size = fs.statSync(this.logFile).size; } catch { /* not yet created */ }
    if (size > ROTATE_BYTES) {
      try {
        // Drop any older rotated file before promoting the active one.
        if (fs.existsSync(this.rotatedFile)) { fs.unlinkSync(this.rotatedFile); }
        fs.renameSync(this.logFile, this.rotatedFile);
      } catch {
        // If rotation fails (e.g. another VS Code window holds the file)
        // we keep appending — the file will just exceed the cap until the
        // next attempt succeeds. Better than dropping events.
      }
    }
    fs.appendFileSync(this.logFile, JSON.stringify(event) + "\n", "utf-8");
  }
}

function isValidEvent(v: unknown): v is LogEvent {
  if (typeof v !== "object" || v === null) { return false; }
  const e = v as Partial<LogEvent>;
  return (
    typeof e.t === "string" &&
    typeof e.msg === "string" &&
    (e.level === "info" || e.level === "warn" || e.level === "error") &&
    (e.type === "scan" || e.type === "prompt" || e.type === "skip" ||
     e.type === "semgrep" || e.type === "policy" || e.type === "api" ||
     e.type === "other") &&
    (e.detail === undefined || typeof e.detail === "string")
  );
}

function formatForChannel(event: LogEvent): string {
  const time = event.t.slice(11, 19); // HH:MM:SS from ISO string
  const head = `${time}  [${event.level.toUpperCase().padEnd(5)}] ${event.type.padEnd(7)} ${event.msg}`;
  return event.detail ? `${head}\n  ${event.detail.split("\n").join("\n  ")}` : head;
}
