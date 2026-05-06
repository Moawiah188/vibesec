import * as vscode from "vscode";

// In-workspace history of scan completions, used by the Control Center
// Dashboard to render a real sparkline + 1d/7d/30d aggregates instead of
// fabricated numbers. Backed by `context.workspaceState` so each workspace
// keeps its own history; the cap keeps the persisted blob bounded.

export interface ScanHistoryEntry {
  /** Wall-clock ms since epoch when the scan finished. */
  ts:           number;
  filesScanned: number;
  filesSkipped: number;
  duration:     number; // milliseconds
  findings:     { error: number; warning: number; info: number };
  /** What kicked off the scan — used for the "trigger: manual|onSave" row on
   *  the Dashboard summary. */
  trigger:      "manual" | "onSave" | "selection";
}

const STATE_KEY = "vibesec.scanHistory";
const MAX_ENTRIES = 200;

export class ScanHistoryStore {
  private readonly emitter = new vscode.EventEmitter<ScanHistoryEntry[]>();
  /** Fires after every mutation with the new full array. */
  readonly onDidChange = this.emitter.event;

  constructor(private readonly context: vscode.ExtensionContext) {}

  /** Returns the full history sorted ascending by timestamp. */
  getAll(): ScanHistoryEntry[] {
    const raw = this.context.workspaceState.get<ScanHistoryEntry[]>(STATE_KEY, []);
    // Defensive: workspaceState is just JSON, anything could be in there if a
    // user hand-edited the workspace state file. Filter to the expected shape.
    return raw.filter(isValidEntry).sort((a, b) => a.ts - b.ts);
  }

  async record(entry: ScanHistoryEntry): Promise<void> {
    const next = [...this.getAll(), entry];
    // Drop oldest if we'd exceed the cap. A hard cap keeps workspaceState
    // small so VS Code's startup serialization stays fast.
    while (next.length > MAX_ENTRIES) { next.shift(); }
    await this.context.workspaceState.update(STATE_KEY, next);
    this.emitter.fire(next);
  }

  async clear(): Promise<void> {
    await this.context.workspaceState.update(STATE_KEY, []);
    this.emitter.fire([]);
  }

  dispose(): void {
    this.emitter.dispose();
  }
}

function isValidEntry(v: unknown): v is ScanHistoryEntry {
  if (typeof v !== "object" || v === null) { return false; }
  const e = v as Partial<ScanHistoryEntry>;
  return (
    typeof e.ts === "number" &&
    typeof e.filesScanned === "number" &&
    typeof e.filesSkipped === "number" &&
    typeof e.duration === "number" &&
    typeof e.findings === "object" && e.findings !== null &&
    typeof (e.findings as { error?: unknown }).error   === "number" &&
    typeof (e.findings as { warning?: unknown }).warning === "number" &&
    typeof (e.findings as { info?: unknown }).info     === "number" &&
    (e.trigger === "manual" || e.trigger === "onSave" || e.trigger === "selection")
  );
}
