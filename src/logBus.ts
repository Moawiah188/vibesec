// LogBus — process-wide singleton that captures structured log events from
// scanner / policy / llmClient / promptGenerator and fans them out to:
//   • an in-memory ring buffer (1000 events) for fast Control Center replay
//   • a vscode.OutputChannel ("VibeSec") for raw inspection
//   • disk persistence (wired in by logStore.ts at activation time)
//
// Designed to be safe to import from any source file *before* extension
// activation runs. Pre-activation events are captured into the ring buffer
// and replayed to subscribers as soon as they connect.

export type LogEventType = "scan" | "prompt" | "skip" | "semgrep" | "policy" | "api" | "other";
export type LogLevel = "info" | "warn" | "error";

export interface LogEvent {
  /** ISO 8601 timestamp. The webview formats this to HH:MM:SS for display. */
  t:       string;
  type:    LogEventType;
  level:   LogLevel;
  msg:     string;
  detail?: string;
}

export type LogListener = (event: LogEvent) => void;

const RING_CAPACITY = 1000;

class LogBus {
  private readonly ring: LogEvent[] = [];
  private readonly listeners: Set<LogListener> = new Set();

  emit(level: LogLevel, type: LogEventType, msg: string, detail?: string): void {
    const event: LogEvent = {
      t:     new Date().toISOString(),
      type,
      level,
      msg,
      detail,
    };
    this.ring.push(event);
    if (this.ring.length > RING_CAPACITY) {
      this.ring.shift();
    }
    // Iterate over a copy so listeners can unsubscribe inside their handler
    // without skipping later subscribers.
    for (const l of [...this.listeners]) {
      try { l(event); } catch { /* swallow — log infrastructure must never throw upward */ }
    }
  }

  info(type: LogEventType, msg: string, detail?: string):  void { this.emit("info",  type, msg, detail); }
  warn(type: LogEventType, msg: string, detail?: string):  void { this.emit("warn",  type, msg, detail); }
  error(type: LogEventType, msg: string, detail?: string): void { this.emit("error", type, msg, detail); }

  /** Snapshot of the ring buffer (oldest → newest). */
  getRing(): LogEvent[] {
    return this.ring.slice();
  }

  /** Replace the ring buffer wholesale. Used by logStore on startup so the
   *  webview's first replay includes events that survived a VS Code reload. */
  replaceRing(events: LogEvent[]): void {
    this.ring.length = 0;
    // Keep only the most recent RING_CAPACITY entries, preserving order.
    const start = Math.max(0, events.length - RING_CAPACITY);
    for (let i = start; i < events.length; i++) {
      this.ring.push(events[i]);
    }
  }

  /** Drop every buffered event. Called when the user clicks "Clear logs". */
  clearRing(): void {
    this.ring.length = 0;
  }

  subscribe(listener: LogListener): () => void {
    this.listeners.add(listener);
    return () => { this.listeners.delete(listener); };
  }
}

export const logBus = new LogBus();
